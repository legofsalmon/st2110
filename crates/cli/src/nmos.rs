//! `st2110 nmos`: check a registry, live or from a saved snapshot.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use st2110_nmos::client::{Options, QueryClient};
use st2110_nmos::{Finding, Report, ResourceRef, Snapshot};
use st2110_sdp::Severity;

use crate::{Format, Style, describe, plural, read};

/// How to read a live registry.
pub(crate) struct Fetch {
    /// Where to save the snapshot.
    pub save: Option<PathBuf>,
    /// Seconds per request.
    pub timeout: f64,
    /// Whether to fetch the Senders' SDP files.
    pub sdp: bool,
}

pub(crate) fn run(
    target: &str,
    fetch: &Fetch,
    format: Format,
    quiet: bool,
    deny_warnings: bool,
) -> io::Result<ExitCode> {
    let snapshot = match load(target, fetch) {
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

/// Reads a snapshot from a registry URL or a saved file.
fn load(target: &str, fetch: &Fetch) -> Result<Snapshot, String> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let timeout = Duration::try_from_secs_f64(fetch.timeout)
            .ok()
            .filter(|t| !t.is_zero())
            .ok_or_else(|| format!("--timeout {} is not a number of seconds above 0", fetch.timeout))?;
        let options = Options { timeout, fetch_sdp: fetch.sdp, ..Options::default() };
        let client = QueryClient::connect(target, &options).map_err(|e| e.to_string())?;
        return client.snapshot().map_err(|e| e.to_string());
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
        writeln!(out, "{line}")?;
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
        writeln!(out, "{line}")?;
    }
    Ok(())
}
