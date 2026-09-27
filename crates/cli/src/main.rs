//! `st2110`: check SMPTE ST 2110 SDP files, NMOS registries and PTP messages from the
//! command line, and work out ST 2059-1 timing.

mod nmos;
mod ptp;
mod timing;

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use st2110_sdp::{Diagnostic, Report, Rule, Severity, Stream};

#[derive(Parser)]
#[command(
    name = "st2110",
    version,
    about = "Check SMPTE ST 2110 SDP files, NMOS registries and PTP messages against the standards"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check SDP files and describe the streams they declare.
    ///
    /// Exits with 0 when no file has an error, 1 when one does (or has a warning,
    /// with --deny-warnings), and 2 when a file cannot be read.
    Lint {
        /// SDP files to check; `-` reads standard input.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Print only warnings and errors, without stream summaries or notes (text output).
        #[arg(short, long)]
        quiet: bool,
        /// Exit with status 1 on warnings too.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Check an NMOS registry: its resources, PTP clocks, connections and every
    /// Sender's SDP file.
    ///
    /// TARGET is a registry's Query API URL, or a snapshot saved with --save (`-` reads
    /// standard input). Exits with 0 when nothing is an error, 1 when something is (or
    /// is a warning, with --deny-warnings), and 2 when the registry or file cannot be read.
    Nmos {
        /// Query API URL, such as http://registry.example:8080, or a saved snapshot.
        target: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Print only warnings and errors, without the lists of Senders and Receivers (text output).
        #[arg(short, long)]
        quiet: bool,
        /// Exit with status 1 on warnings too.
        #[arg(long)]
        deny_warnings: bool,
        /// Save what was read as a snapshot, to check again later without the registry.
        #[arg(long, value_name = "FILE")]
        save: Option<PathBuf>,
        /// Seconds to wait for each response from the registry or a Node.
        #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
        timeout: f64,
        /// Do not fetch the Senders' SDP files.
        #[arg(long)]
        no_sdp: bool,
    },
    /// Decode PTP messages and check them against the ST 2059-2 profile.
    ///
    /// Each FILE holds one message per line in hex, as `tshark -T fields -e udp.payload`
    /// writes them (`#` starts a comment), or a single message in binary. Exits with 0
    /// when no message has an error, 1 when one does or cannot be decoded (or has a
    /// warning, with --deny-warnings), and 2 when a file cannot be read.
    Ptp {
        /// Files of messages; `-` reads standard input.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Print only warnings, errors and messages that cannot be decoded (text output).
        #[arg(short, long)]
        quiet: bool,
        /// Exit with status 1 on warnings too.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Work out where a PTP time falls, by ST 2059-1: each video frame rate's frame,
    /// RTP timestamps and time code, and each audio rate's RTP timestamp and AES3 block.
    ///
    /// Without --video or --audio, shows 50 and 60000/1001 video and 48 kHz audio.
    Time {
        /// The time: PTP seconds, such as 1790510437.123456789 (or IS-04's
        /// 1790510437:123456789), or UTC, such as 2026-09-27T12:00:00Z. Now, by the
        /// system clock, when omitted.
        #[arg(long, value_name = "TIME")]
        at: Option<String>,
        /// A video frame rate, such as 50, 60000/1001 or 59.94; give it more than once
        /// for several.
        #[arg(long, value_name = "RATE")]
        video: Vec<String>,
        /// An audio sampling rate in Hz, such as 48000; give it more than once for several.
        #[arg(long, value_name = "HZ", value_parser = clap::value_parser!(u32).range(1..))]
        audio: Vec<u32>,
        /// Seconds from PTP time to Local Time: ST 2059-2's currentLocalOffset, such as
        /// 3563 for UTC+1. UTC (minus TAI − UTC) when omitted.
        #[arg(long, value_name = "SECONDS", allow_negative_numbers = true)]
        local_offset: Option<i32>,
        /// TAI − UTC in seconds.
        #[arg(long, value_name = "SECONDS", default_value_t = st2110_ptp::TAI_UTC_2017, allow_negative_numbers = true)]
        tai_utc: i32,
        /// The last daily jam, as PTP or UTC time, such as a grandmaster's
        /// timeOfPreviousJam. The last Local Time midnight when omitted.
        #[arg(long, value_name = "TIME")]
        jam: Option<String>,
        /// Count 30000/1001 time code without dropping frames.
        #[arg(long)]
        non_drop: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// List the rules, or show the ones named.
    Rules {
        /// Rule identifiers, such as mediaclk-offset; every rule when none is given.
        ids: Vec<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesFormat {
    Text,
    Markdown,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Lint { files, format, quiet, deny_warnings } => lint(&files, format, quiet, deny_warnings),
        Command::Nmos { target, format, quiet, deny_warnings, save, timeout, no_sdp } => {
            let fetch = nmos::Fetch { save, timeout, sdp: !no_sdp };
            nmos::run(&target, &fetch, format, quiet, deny_warnings)
        }
        Command::Ptp { files, format, quiet, deny_warnings } => ptp::run(&files, format, quiet, deny_warnings),
        Command::Time { at, video, audio, local_offset, tai_utc, jam, non_drop, format } => {
            let args = timing::Args { at, tai_utc, local_offset, video, audio, jam, non_drop };
            timing::run(&args, format)
        }
        Command::Rules { ids, format } => list_rules(&ids, format),
    };
    match result {
        Ok(code) => code,
        // Output closed early, as by `st2110 lint ... | head`.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("st2110: {e}");
            ExitCode::from(2)
        }
    }
}

/// One checked file.
#[derive(Serialize)]
struct Checked {
    file: String,
    #[serde(skip)]
    text: String,
    #[serde(flatten)]
    report: Report,
}

fn lint(files: &[PathBuf], format: Format, quiet: bool, deny_warnings: bool) -> io::Result<ExitCode> {
    let mut checked = Vec::new();
    let mut unreadable = false;
    for path in files {
        let file = path.display().to_string();
        match read(path) {
            Ok(text) => {
                let report = st2110_sdp::lint(&text);
                checked.push(Checked { file, text, report });
            }
            Err(e) => {
                eprintln!("st2110: {file}: {e}");
                unreadable = true;
            }
        }
    }
    let mut out = io::stdout().lock();
    match format {
        Format::Text => {
            let style = Style::detect();
            for c in &checked {
                write_text(&mut out, c, quiet, style)?;
            }
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &checked)?;
            writeln!(out)?;
        }
    }
    let failed =
        checked.iter().any(|c| c.report.has_errors() || (deny_warnings && c.report.count(Severity::Warning) > 0));
    Ok(match (unreadable, failed) {
        (true, _) => ExitCode::from(2),
        (false, true) => ExitCode::from(1),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// Reads a file, or standard input for `-`.
pub(crate) fn read_bytes(path: &Path) -> io::Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

/// Reads a text file, or standard input for `-`. Bytes that are not UTF-8, as in a
/// Latin-1 session name, become U+FFFD rather than stopping the check.
pub(crate) fn read(path: &Path) -> io::Result<String> {
    Ok(String::from_utf8_lossy(&read_bytes(path)?).into_owned())
}

/// ANSI colours, used only when writing to a terminal and `NO_COLOR` is unset.
#[derive(Clone, Copy)]
pub(crate) struct Style {
    color: bool,
}

impl Style {
    pub(crate) fn detect() -> Self {
        Self { color: io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }

    pub(crate) fn paint(self, code: &str, text: &str) -> String {
        if self.color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
    }

    pub(crate) fn severity(self, severity: Severity) -> String {
        let code = match severity {
            Severity::Error => "1;31",
            Severity::Warning => "1;33",
            Severity::Info => "1;36",
        };
        self.paint(code, severity.as_str())
    }
}

fn write_text(out: &mut impl Write, c: &Checked, quiet: bool, style: Style) -> io::Result<()> {
    let report = &c.report;
    if !quiet {
        let count = report.streams.len();
        writeln!(out, "{}: {count} stream{}", style.paint("1", &c.file), if count == 1 { "" } else { "s" })?;
        for stream in &report.streams {
            writeln!(out, "  {}", describe(stream))?;
        }
    }
    let lines: Vec<&str> = c.text.lines().collect();
    let shown: Vec<&Diagnostic> =
        report.diagnostics.iter().filter(|d| !quiet || d.severity != Severity::Info).collect();
    for (i, d) in shown.iter().enumerate() {
        write_diagnostic(out, &c.file, d, style)?;
        // Quote the source line once, after the last finding on it.
        let last_on_line = shown.get(i + 1).is_none_or(|next| next.line != d.line);
        if let Some(line) = d.line.filter(|_| last_on_line)
            && let Some(source) = lines.get(line - 1)
        {
            writeln!(out, "  {} {}", style.paint("2", &format!("{line:>4} |")), source.trim_end())?;
        }
    }
    let (errors, warnings, notes) =
        (report.count(Severity::Error), report.count(Severity::Warning), report.count(Severity::Info));
    if errors + warnings + notes == 0 {
        if !quiet {
            writeln!(out, "{}: no problems found", c.file)?;
        }
    } else if !quiet || errors + warnings > 0 {
        writeln!(
            out,
            "{}: {}, {}, {}",
            c.file,
            plural(errors, "error"),
            plural(warnings, "warning"),
            plural(notes, "note")
        )?;
    }
    if !quiet {
        writeln!(out)?;
    }
    Ok(())
}

pub(crate) fn describe(stream: &Stream) -> String {
    let mut label = format!("stream {} (line {}, {}", stream.index, stream.line, stream.essence.standard());
    if let Some(mid) = &stream.mid {
        label.push_str(&format!(", mid {mid}"));
    }
    label.push(')');
    if let (Some(destination), Some(port)) = (&stream.destination, stream.port) {
        label.push_str(&format!(" {destination}:{port}"));
    }
    format!("{label}: {}", stream.summary)
}

fn write_diagnostic(out: &mut impl Write, file: &str, d: &Diagnostic, style: Style) -> io::Result<()> {
    let location = match d.line {
        Some(line) => format!("{file}:{line}"),
        None => file.to_string(),
    };
    writeln!(out, "{location}: {}[{}]: {} ({})", style.severity(d.severity), d.rule, d.message, d.reference)
}

pub(crate) fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

/// Every rule: the SDP, NMOS and PTP catalogues in turn.
fn all_rules() -> impl Iterator<Item = &'static Rule> {
    st2110_sdp::rules::ALL.iter().chain(st2110_nmos::rules::ALL).chain(st2110_ptp::rules::ALL).copied()
}

/// Looks a rule up in any catalogue.
fn find_rule(id: &str) -> Option<&'static Rule> {
    all_rules().find(|rule| rule.id == id)
}

/// The catalogues as the Markdown page published in `docs/rules.md`.
fn rules_markdown() -> String {
    format!(
        "# Rules\n\n\
         Generated by `st2110 rules --format markdown`. Severity: **error** breaks a \"shall\" \
         (or an RFC \"MUST\"), **warning** breaks a \"should\" or is a known interoperability \
         hazard, **info** is a note that needs no action on its own.\n\n\
         ## SDP files\n\n\
         `st2110 lint` checks these in each SDP file, and `st2110 nmos` in each Sender's.\n\n{}\n\
         ## NMOS registries\n\n\
         `st2110 nmos` checks these across a registry's resources and against each Sender's SDP file.\n\n{}\n\
         ## PTP messages\n\n\
         `st2110 ptp` checks these in each message against the ST 2059-2 profile.\n\n{}",
        st2110_sdp::rules::markdown_table(st2110_sdp::rules::ALL),
        st2110_sdp::rules::markdown_table(st2110_nmos::rules::ALL),
        st2110_sdp::rules::markdown_table(st2110_ptp::rules::ALL)
    )
}

fn list_rules(ids: &[String], format: RulesFormat) -> io::Result<ExitCode> {
    let mut selected: Vec<&Rule> = Vec::new();
    for id in ids {
        match find_rule(id) {
            Some(rule) => selected.push(rule),
            None => {
                eprintln!("st2110: no rule is named {id}; `st2110 rules` lists them all");
                return Ok(ExitCode::from(2));
            }
        }
    }
    if ids.is_empty() {
        selected = all_rules().collect();
    }
    let mut out = io::stdout().lock();
    match format {
        RulesFormat::Markdown if ids.is_empty() => write!(out, "{}", rules_markdown())?,
        RulesFormat::Markdown => write!(out, "{}", st2110_sdp::rules::markdown_table(&selected))?,
        RulesFormat::Json => {
            serde_json::to_writer_pretty(&mut out, &selected)?;
            writeln!(out)?;
        }
        RulesFormat::Text => {
            let style = Style::detect();
            for rule in selected {
                writeln!(out, "{} {} ({})", style.paint("1", rule.id), style.severity(rule.severity), rule.reference)?;
                writeln!(out, "    {}", rule.summary)?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
