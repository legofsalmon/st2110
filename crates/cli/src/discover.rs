//! `st2110 discover`: find the streams on the network, from SAP announcements and from
//! the Senders of NMOS registries and Nodes found by DNS-SD.

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use serde::Serialize;
use st2110_discover::nmos::ApiKind;
use st2110_discover::{Discovery, Found, List, MDNS, Options, Origin};

use crate::{Format, Style, plural, seconds};

#[derive(Args)]
pub(crate) struct DiscoverArgs {
    /// Seconds to look for. Senders announce by SAP every 30 seconds or so, so a short
    /// look can miss some: give 35 to hear every one.
    #[arg(long, value_name = "SECONDS", default_value_t = 10.0)]
    duration: f64,
    /// Keep looking, and print each stream as it comes, changes and goes, until stopped.
    #[arg(long, conflicts_with_all = ["duration", "save"])]
    watch: bool,
    /// The address of a network interface to look on; every one that is up when
    /// omitted. Give it more than once for several.
    #[arg(long, value_name = "ADDRESS")]
    interface: Vec<Ipv4Addr>,
    /// Where to hear SAP announcements: a multicast group or a unicast address, and a
    /// port. 239.255.255.255:9875, where AES67 devices announce, and 224.2.127.254:9875
    /// when omitted. Give it more than once for several.
    #[arg(long, value_name = "ADDRESS:PORT")]
    sap: Vec<SocketAddrV4>,
    /// Do not listen for SAP announcements.
    #[arg(long, conflicts_with = "sap")]
    no_sap: bool,
    /// Read this registry's Query API, such as http://registry.example:8080, rather than
    /// finding registries and Nodes by DNS-SD.
    #[arg(long, value_name = "URL")]
    registry: Option<String>,
    /// Do not look for NMOS Senders.
    #[arg(long, conflicts_with = "registry")]
    no_nmos: bool,
    /// Where to ask by multicast DNS: its group, 224.0.0.251:5353, when omitted, or a
    /// responder's own address and port.
    #[arg(long, value_name = "ADDRESS:PORT")]
    mdns: Option<SocketAddrV4>,
    /// Do not ask DNS servers for registries by unicast DNS-SD.
    #[arg(long)]
    no_dns: bool,
    /// A DNS server to ask for registries, with its port when it is not 53; those the
    /// system uses when omitted. Give it more than once for several.
    #[arg(long, value_name = "ADDRESS", value_parser = dns_server)]
    dns_server: Vec<SocketAddr>,
    /// A domain to look for registries in, such as studio.example; the system's search
    /// domains when omitted. Give it more than once for several.
    #[arg(long, value_name = "DOMAIN")]
    domain: Vec<String>,
    /// Save each stream's SDP file into this directory, named after the stream, to
    /// receive, view or check.
    #[arg(long, value_name = "DIRECTORY")]
    save: Option<PathBuf>,
    /// Seconds to wait for each answer from a DNS server, a registry or a Node.
    #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
    timeout: f64,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

/// A DNS server's address, on port 53 unless it says otherwise.
fn dns_server(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .or_else(|_| text.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("{text} is not an IP address, or an address and port"))
}

fn options(args: &DiscoverArgs) -> Result<Options, String> {
    if args.no_sap && args.no_nmos {
        return Err("with --no-sap and --no-nmos there is nothing to look for".into());
    }
    let timeout = seconds("--timeout", args.timeout)?;
    if timeout.is_zero() {
        return Err(format!("--timeout {} is not a number of seconds above 0", args.timeout));
    }
    let defaults = Options::default();
    Ok(Options {
        interfaces: args.interface.clone(),
        sap: match (args.no_sap, args.sap.is_empty()) {
            (true, _) => Vec::new(),
            (false, true) => defaults.sap,
            (false, false) => args.sap.clone(),
        },
        nmos: !args.no_nmos,
        registry: args.registry.clone(),
        mdns: Some(args.mdns.unwrap_or(MDNS)),
        dns: !args.no_dns,
        dns_servers: args.dns_server.clone(),
        domains: (!args.domain.is_empty()).then(|| args.domain.clone()),
        timeout,
        ..defaults
    })
}

pub(crate) fn run(args: &DiscoverArgs) -> io::Result<ExitCode> {
    let looked = options(args).and_then(|options| Ok((options, seconds("--duration", args.duration)?)));
    let (options, duration) = match looked {
        Ok(looked) => looked,
        Err(e) => {
            eprintln!("st2110: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let timeout = options.timeout;
    let discovery = Discovery::start(options, || {});
    if args.watch {
        return watch(&discovery, args.format);
    }
    thread::sleep(duration);
    // A registry or the Nodes being read are waited for, a while.
    let deadline = Instant::now() + 2 * timeout;
    while discovery.list().busy && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let list = discovery.list();
    drop(discovery);
    let saved = match &args.save {
        Some(directory) => match save(directory, &list.streams) {
            Ok(saved) => saved,
            Err(e) => {
                eprintln!("st2110: {}: {e}", directory.display());
                return Ok(ExitCode::from(2));
            }
        },
        None => Vec::new(),
    };
    let mut out = io::stdout().lock();
    match args.format {
        Format::Text => write_text(&mut out, &list, args, duration, &saved, Style::detect())?,
        Format::Json => {
            let saved = saved.iter().map(|p| p.display().to_string()).collect();
            serde_json::to_writer_pretty(&mut out, &Discovered { list: &list, saved })?;
            writeln!(out)?;
        }
    }
    Ok(match (list.looking.is_empty(), list.streams.is_empty()) {
        // It could look nowhere; the notes say why.
        (true, _) => ExitCode::from(2),
        (false, true) => ExitCode::from(1),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// What `--format json` writes.
#[derive(Serialize)]
struct Discovered<'a> {
    #[serde(flatten)]
    list: &'a List,
    /// The SDP files saved.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    saved: Vec<String>,
}

/// A file name for a stream's SDP file: its name, with what file systems refuse left out.
fn file_name(name: &str) -> String {
    let cleaned: String =
        name.chars().map(|c| if c.is_alphanumeric() || " ._-()".contains(c) { c } else { '_' }).take(100).collect();
    let cleaned = cleaned.trim_matches([' ', '.']);
    if cleaned.is_empty() { "stream".into() } else { cleaned.into() }
}

/// Writes each stream's SDP file into `directory`, giving the files written.
fn save(directory: &Path, streams: &[Found]) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(directory)?;
    let mut saved: Vec<PathBuf> = Vec::new();
    for found in streams {
        let Some(sdp) = &found.sdp else { continue };
        let name = file_name(&found.name);
        let path = (1..)
            .map(|n| directory.join(if n == 1 { format!("{name}.sdp") } else { format!("{name} {n}.sdp") }))
            .find(|path| !saved.contains(path))
            .expect("a free name");
        fs::write(&path, sdp)?;
        saved.push(path);
    }
    Ok(saved)
}

/// What a stream carries and where it goes, on one line.
fn carries(found: &Found) -> String {
    let destinations = found.destinations();
    match (found.format(), destinations.is_empty()) {
        (format, true) => format,
        (format, false) if format.is_empty() => format!("to {}", destinations.join(" and ")),
        (format, false) => format!("{format}, to {}", destinations.join(" and ")),
    }
}

/// How a stream was found, on one line.
fn found_by(found: &Found) -> String {
    let by: Vec<String> = found
        .by
        .iter()
        .map(|origin| match origin {
            Origin::Sap { heard_s, .. } if found.stale => {
                format!("{}, not heard for {heard_s:.0} s", origin.describe())
            }
            Origin::Sap { interval_s: Some(every), .. } => format!("{}, every {every:.0} s", origin.describe()),
            Origin::Nmos { .. } if found.active == Some(false) => format!("{}, not sending", origin.describe()),
            _ => origin.describe(),
        })
        .collect();
    by.join("; ")
}

fn write_text(
    out: &mut impl Write,
    list: &List,
    args: &DiscoverArgs,
    duration: Duration,
    saved: &[PathBuf],
    style: Style,
) -> io::Result<()> {
    for found in &list.streams {
        writeln!(out, "{}", style.paint("1", &found.name))?;
        let carries = carries(found);
        if !carries.is_empty() {
            writeln!(out, "  {carries}")?;
        }
        writeln!(out, "  {}", found_by(found))?;
        if let Some(problem) = &found.problem {
            writeln!(out, "  no SDP file: {problem}")?;
        }
    }
    if !list.streams.is_empty() {
        writeln!(out)?;
    }
    writeln!(out, "{} found.", plural(list.streams.len(), "stream"))?;
    let nodes = list.apis.iter().filter(|a| a.kind == ApiKind::Node).count();
    match (&list.registry, list.peer_to_peer) {
        (Some(registry), _) => writeln!(out, "NMOS Senders read from the registry at {registry}.")?,
        (None, true) => writeln!(out, "NMOS Senders read from {} peer to peer.", plural(nodes, "Node"))?,
        (None, false) if !args.no_nmos && list.apis.is_empty() => writeln!(out, "No NMOS registry or Node found.")?,
        (None, false) => {}
    }
    if !list.looking.is_empty() {
        writeln!(out, "Looked for {} s for {}.", duration.as_secs_f64(), list.looking.join("; "))?;
    }
    for note in &list.notes {
        writeln!(out, "{}: {note}", style.paint("1;33", "note"))?;
    }
    if let Some(directory) = &args.save {
        writeln!(out, "Saved {} in {}.", plural(saved.len(), "SDP file"), directory.display())?;
    }
    Ok(())
}

/// Prints the streams as they come, change and go, and what goes wrong, until stopped.
fn watch(discovery: &Discovery, format: Format) -> io::Result<ExitCode> {
    let style = Style::detect();
    let mut out = io::stdout().lock();
    let mut generation = None;
    let mut shown: Vec<(String, String)> = Vec::new();
    let mut noted: Vec<String> = Vec::new();
    loop {
        let now = discovery.generation();
        if generation != Some(now) {
            generation = Some(now);
            let list = discovery.list();
            match format {
                Format::Json => {
                    serde_json::to_writer(&mut out, &list)?;
                    writeln!(out)?;
                }
                Format::Text => {
                    let lines: Vec<(String, String)> = list
                        .streams
                        .iter()
                        .map(|f| {
                            let key = format!("{} {}", f.name, f.destinations().join(" "));
                            (key, format!("{}: {} ({})", style.paint("1", &f.name), carries(f), found_by(f)))
                        })
                        .collect();
                    for (key, line) in &shown {
                        if !lines.iter().any(|(k, _)| k == key) {
                            writeln!(out, "- {line}")?;
                        }
                    }
                    for (key, line) in &lines {
                        match shown.iter().find(|(k, _)| k == key) {
                            None => writeln!(out, "+ {line}")?,
                            Some((_, before)) if before != line => writeln!(out, "~ {line}")?,
                            Some(_) => {}
                        }
                    }
                    for note in list.notes.iter().filter(|n| !noted.contains(n)) {
                        writeln!(out, "{}: {note}", style.paint("1;33", "note"))?;
                    }
                    (shown, noted) = (lines, list.notes);
                }
            }
            out.flush()?;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_files_after_streams() {
        assert_eq!(file_name("CAM 1 video"), "CAM 1 video");
        assert_eq!(file_name("../etc/passwd"), "_etc_passwd");
        assert_eq!(file_name("Prod: Cam/2 (ISO)"), "Prod_ Cam_2 (ISO)");
        assert_eq!(file_name(" .. "), "stream");
        assert_eq!(dns_server("192.168.10.1"), Ok("192.168.10.1:53".parse().unwrap()));
        assert_eq!(dns_server("127.0.0.1:5300"), Ok("127.0.0.1:5300".parse().unwrap()));
        assert!(dns_server("dns.example").is_err());
    }
}
