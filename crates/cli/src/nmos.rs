//! `st2110 nmos`: check a registry, live or from a saved snapshot.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use st2110_nmos::client::{NodeClient, Options, QueryClient};
use st2110_nmos::{Finding, MonitorView, Report, ResourceRef, Snapshot};
use st2110_sdp::Severity;

use crate::{Format, Style, describe, plural, read, seconds};

/// How to read a live registry.
pub(crate) struct Fetch {
    /// Where to save the snapshot.
    pub save: Option<PathBuf>,
    /// Seconds per request.
    pub timeout: f64,
    /// Whether to fetch the Senders' SDP files.
    pub sdp: bool,
    /// The IS-09 System API to read: its URL, or empty to find it by DNS-SD.
    pub system: Option<String>,
    /// Where an IS-10 token comes from.
    pub auth: crate::auth::Auth,
}

pub(crate) fn run(
    target: &str,
    fetch: &Fetch,
    format: Format,
    quiet: bool,
    deny_warnings: bool,
) -> io::Result<ExitCode> {
    let snapshot = match load(target, fetch).and_then(|snapshot| with_system(snapshot, fetch)) {
        Ok(snapshot) => snapshot,
        Err(message) => {
            eprintln!("st2110: {message}");
            return Ok(ExitCode::from(2));
        }
    };
    if let Some(path) = &fetch.save
        && let Err(e) = fs::write(path, snapshot.to_json() + "\n")
    {
        eprintln!("st2110: {}: {e}", path.display());
        return Ok(ExitCode::from(2));
    }
    let report = st2110_nmos::check(&snapshot);
    let mut out = io::stdout().lock();
    match format {
        Format::Text => write_text(&mut out, &snapshot, &report, quiet, Style::detect())?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
    }
    let failed = report.has_errors() || (deny_warnings && report.count(Severity::Warning) > 0);
    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// Adds what the IS-09 System API gives, when it was asked for. One that cannot be
/// read is a finding, not a failure.
fn with_system(mut snapshot: Snapshot, fetch: &Fetch) -> Result<Snapshot, String> {
    let Some(url) = &fetch.system else { return Ok(snapshot) };
    let timeout = seconds("--timeout", fetch.timeout)?;
    let url = if url.trim().is_empty() { crate::find::system(&fetch.auth.look, timeout)? } else { url.clone() };
    let token = fetch.auth.token(timeout, true)?;
    let options = Options { timeout, token, ..Options::default() };
    snapshot.system = Some(st2110_nmos::client::system(&url, &options));
    Ok(snapshot)
}

/// Reads a snapshot from a registry's or a Node's URL, or a saved file.
fn load(target: &str, fetch: &Fetch) -> Result<Snapshot, String> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let timeout = seconds("--timeout", fetch.timeout)?;
        if timeout.is_zero() {
            return Err(format!("--timeout {} is not a number of seconds above 0", fetch.timeout));
        }
        let token = fetch.auth.token(timeout, true)?;
        let options = Options {
            timeout,
            fetch_sdp: fetch.sdp,
            fetch_active: true,
            fetch_controls: true,
            token,
            versions: true,
            ..Options::default()
        };
        if lower.contains("/x-nmos/node") {
            let node = NodeClient::connect(target, &options).map_err(|e| e.to_string())?;
            return node.snapshot().map_err(|e| e.to_string());
        }
        return match QueryClient::connect(target, &options) {
            Ok(client) => client.snapshot().map_err(|e| e.to_string()),
            // No registry at a bare address: it may be a Node's.
            Err(e) if !lower.contains("/x-nmos/") && e.message.starts_with("HTTP 404") => {
                match NodeClient::connect(target, &options) {
                    Ok(node) => node.snapshot().map_err(|e| e.to_string()),
                    Err(_) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        };
    }
    let text = read(Path::new(target)).map_err(|e| format!("{target}: {e}"))?;
    Snapshot::from_json(&text).map_err(|e| format!("{target}: not a registry snapshot: {e}"))
}

/// A resource as the text output names it.
fn name(resource: Option<&ResourceRef>) -> String {
    resource.map_or_else(|| "registry".to_string(), ResourceRef::describe)
}

fn short(id: Option<&str>) -> String {
    id.map_or_else(|| "no id".to_string(), |id| id.chars().take(8).collect())
}

fn quoted(label: &str, id: Option<&str>) -> String {
    if label.is_empty() { short(id) } else { format!("\"{label}\" ({})", short(id)) }
}

/// A Sender's or Receiver's IS-12 status monitor, in one line: quiet when healthy,
/// amber when partly healthy, red when unhealthy, with any counter that is not 0.
fn monitor_line(monitor: &MonitorView, style: Style) -> String {
    let overall = monitor.overall.as_deref().unwrap_or("unread");
    let mut line = match overall {
        "PartiallyHealthy" => style.paint("33", "partially healthy"),
        "Unhealthy" => style.paint("31", "unhealthy"),
        other => other.to_ascii_lowercase(),
    };
    if let Some(message) = monitor.overall_message.as_deref().filter(|m| !m.is_empty()) {
        line.push_str(&format!(": {message}"));
    }
    let counted: Vec<String> =
        monitor.counters.iter().filter(|c| c.value > 0).map(|c| format!("{} {}", c.value, c.name)).collect();
    if !counted.is_empty() {
        line.push_str(&format!(" ({})", counted.join(", ")));
    }
    format!("monitor: {line}")
}

fn urn(value: Option<&str>) -> &str {
    value.map_or("", |v| v.rsplit(':').next().unwrap_or(v))
}

fn write_text(out: &mut impl Write, snapshot: &Snapshot, report: &Report, quiet: bool, style: Style) -> io::Result<()> {
    if !quiet {
        write_inventory(out, report, style)?;
    }
    let shown: Vec<&Finding> = report.findings.iter().filter(|f| !quiet || f.severity != Severity::Info).collect();
    for (i, finding) in shown.iter().enumerate() {
        let who = name(finding.resource.as_ref());
        let location = match finding.line {
            Some(line) => format!("{who}, SDP line {line}"),
            None => who,
        };
        writeln!(
            out,
            "{location}: {}[{}]: {} ({})",
            style.severity(finding.severity),
            finding.rule,
            finding.message,
            finding.reference
        )?;
        // Quote the SDP line once, after the last finding on it.
        let next = shown.get(i + 1);
        let last_on_line = next.is_none_or(|n| n.line != finding.line || n.resource != finding.resource);
        if let (true, Some(line), Some(text)) = (last_on_line, finding.line, sdp_line(snapshot, finding)) {
            writeln!(out, "  {} {}", style.paint("2", &format!("{line:>4} |")), text.trim_end())?;
        }
    }
    let (errors, warnings, notes) =
        (report.count(Severity::Error), report.count(Severity::Warning), report.count(Severity::Info));
    if errors + warnings + notes == 0 {
        if !quiet {
            writeln!(out, "registry: no problems found")?;
        }
    } else if !quiet || errors + warnings > 0 {
        writeln!(
            out,
            "registry: {}, {}, {}",
            plural(errors, "error"),
            plural(warnings, "warning"),
            plural(notes, "note")
        )?;
    }
    Ok(())
}

/// The line of a Sender's SDP file that a finding is about.
fn sdp_line<'s>(snapshot: &'s Snapshot, finding: &Finding) -> Option<&'s str> {
    let id = finding.resource.as_ref()?.id.as_deref()?;
    let text = snapshot.manifests.get(id)?.sdp.as_deref()?;
    text.lines().nth(finding.line?.checked_sub(1)?)
}

fn write_inventory(out: &mut impl Write, report: &Report, style: Style) -> io::Result<()> {
    let s = &report.summary;
    let mut heading = report.source.clone().unwrap_or_else(|| "registry".into());
    if let Some(version) = &report.api_version {
        heading.push_str(&format!(" (IS-04 {version})"));
    }
    writeln!(out, "{}", style.paint("1", &heading))?;
    writeln!(
        out,
        "  {}, {}, {}, {}, {} ({} active), {} ({} active)",
        plural(s.nodes, "node"),
        plural(s.devices, "device"),
        plural(s.sources, "source"),
        plural(s.flows, "flow"),
        plural(s.senders, "sender"),
        s.active_senders,
        plural(s.receivers, "receiver"),
        s.active_receivers
    )?;
    let mut ptp: Vec<String> =
        s.grandmasters.iter().map(|g| format!("{} locked to {}", plural(g.clocks, "clock"), g.id)).collect();
    if s.unlocked_clocks > 0 {
        ptp.push(format!("{} unlocked", plural(s.unlocked_clocks, "clock")));
    }
    if !ptp.is_empty() {
        writeln!(out, "  PTP: {}", ptp.join("; "))?;
    }
    if let Some(system) = &report.system {
        let mut given = Vec::new();
        if let Some(domain) = system.ptp_domain {
            given.push(format!("PTP domain {domain}"));
        }
        if let Some(timeout) = system.announce_receipt_timeout {
            given.push(format!("announce timeout {timeout}"));
        }
        if let Some(interval) = system.heartbeat_interval {
            given.push(format!("heartbeat every {interval} s"));
        }
        let given = if given.is_empty() { "nothing read".to_string() } else { given.join(", ") };
        writeln!(out, "  System API: {given} ({})", system.url)?;
    }
    let nodes: Vec<_> = report.nodes.iter().filter(|n| !n.interfaces.is_empty()).collect();
    if !nodes.is_empty() {
        writeln!(out, "nodes:")?;
    }
    for node in nodes {
        let interfaces: Vec<String> = node
            .interfaces
            .iter()
            .map(|i| {
                let mut text = i.name.clone();
                if let Some(port) = &i.port_id {
                    text.push_str(&format!(" {port}"));
                }
                match (&i.switch, &i.switch_port) {
                    (Some(switch), Some(port)) => text.push_str(&format!(" → switch {switch} port {port}")),
                    (Some(switch), None) => text.push_str(&format!(" → switch {switch}")),
                    _ => {}
                }
                text
            })
            .collect();
        writeln!(out, "  {}", quoted(&node.label, node.id.as_deref()))?;
        for interface in interfaces {
            writeln!(out, "    {interface}")?;
        }
    }
    if !report.senders.is_empty() {
        writeln!(out, "senders:")?;
    }
    for sender in &report.senders {
        let mut line = format!("  {}", quoted(&sender.label, sender.id.as_deref()));
        if let Some(node) = &sender.node {
            line.push_str(&format!(" on {node}"));
        }
        let state = match sender.active {
            Some(true) => "active",
            Some(false) => "inactive",
            None => "state unknown",
        };
        line.push_str(&format!(": {state}, {}", urn(sender.transport.as_deref())));
        if let Some(media_type) = &sender.media_type {
            line.push_str(&format!(", {media_type}"));
        }
        if !sender.receivers.is_empty() {
            line.push_str(&format!(", {}", plural(sender.receivers.len(), "receiver")));
        }
        if let Some(state) = &sender.compat {
            line.push_str(&format!(", IS-11 {}", state.replace('_', " ")));
            if let Some(sets) = sender.active_constraints.filter(|sets| *sets > 0) {
                line.push_str(&format!(" to {}", plural(sets, "constraint set")));
            }
        }
        writeln!(out, "{line}")?;
        if let Some(monitor) = &sender.monitor {
            writeln!(out, "    {}", monitor_line(monitor, style))?;
        }
        for stream in &sender.streams {
            writeln!(out, "    {}", describe(stream))?;
        }
    }
    if !report.receivers.is_empty() {
        writeln!(out, "receivers:")?;
    }
    for receiver in &report.receivers {
        let mut line = format!("  {}", quoted(&receiver.label, receiver.id.as_deref()));
        if let Some(node) = &receiver.node {
            line.push_str(&format!(" on {node}"));
        }
        let state = if receiver.active { "active" } else { "inactive" };
        line.push_str(&format!(
            ": {state}, {}, {}",
            urn(receiver.transport.as_deref()),
            urn(receiver.format.as_deref())
        ));
        match (&receiver.sender_label, &receiver.sender_id) {
            (Some(label), id) => line.push_str(&format!(", from {}", quoted(label, id.as_deref()))),
            (None, Some(id)) => line.push_str(&format!(", from unregistered sender {}", short(Some(id)))),
            (None, None) => {}
        }
        if let Some(state) = &receiver.compat {
            line.push_str(&format!(", IS-11 {}", state.replace('_', " ")));
        }
        writeln!(out, "{line}")?;
        if let Some(monitor) = &receiver.monitor {
            writeln!(out, "    {}", monitor_line(monitor, style))?;
        }
    }
    if !report.channel_maps.is_empty() {
        writeln!(out, "channel maps:")?;
    }
    for map in &report.channel_maps {
        writeln!(out, "  {}", quoted(&map.device, Some(&map.device_id)))?;
        for output in &map.outputs {
            let name = match output.name.as_deref().filter(|n| !n.is_empty() && *n != output.id) {
                Some(name) => format!("{name} ({})", output.id),
                None => output.id.clone(),
            };
            // Channels counted from 1, as `st2110 connect --map` takes them.
            let channels: Vec<String> = output
                .channels
                .iter()
                .enumerate()
                .map(|(i, route)| match (&route.input, route.channel_index) {
                    (Some(input), Some(channel)) => format!("{} ← {input}:{}", i + 1, channel + 1),
                    (Some(input), None) => format!("{} ← {input}", i + 1),
                    (None, _) => format!("{} silent", i + 1),
                })
                .collect();
            writeln!(out, "    {name}: {}", channels.join(", "))?;
        }
    }
    Ok(())
}
