//! `st2110`: check SMPTE ST 2110 SDP files, NMOS registries, PTP messages and packet
//! captures from the command line, connect Receivers to Senders through IS-05, work out
//! ST 2059-1 timing, and send and receive streams.

mod connect;
mod nmos;
mod pcap;
mod ptp;
mod stream;
mod timing;
#[cfg(feature = "view")]
mod view;

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use st2110_sdp::{Diagnostic, Report, Rule, Severity, Stream};

#[derive(Parser)]
#[command(
    name = "st2110",
    version,
    about = "Check SMPTE ST 2110 SDP files, NMOS registries, PTP messages and packet captures against the standards, connect Receivers to Senders, and send and receive streams"
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
    /// Connect Receivers to Senders through IS-05, or list which Senders each Receiver
    /// can take.
    ///
    /// TARGET is a registry's Query API URL, or a snapshot saved with `st2110 nmos
    /// --save`. Name a Receiver with --receiver and what it is to take with --sender,
    /// --sdp or --disconnect, or give several connections to make together with --salvo.
    /// Without them, lists which Senders each Receiver can take (or the one --receiver
    /// names), by transport, format and capabilities. --cancel cancels an activation
    /// scheduled on a Receiver.
    ///
    /// Each connection is checked against the Receiver's constraints and capabilities
    /// before anything is sent, and on its /active endpoint and in the registry after.
    /// Several are made as a salvo that switches at one PTP time, --lead from now, and is
    /// rolled back when a Connection API rejects its part. Exits with 0 when every
    /// connection was made, scheduled or (with --dry-run) planned, 1 when one was
    /// refused, failed or differs, and 2 when the registry or a file cannot be read or a
    /// name finds no Sender or Receiver, or more than one.
    Connect {
        /// Query API URL, such as http://registry.example:8080, or a saved snapshot.
        target: String,
        /// The Receiver: its id, its label, or the start of its id.
        #[arg(long, value_name = "RECEIVER", conflicts_with = "salvo")]
        receiver: Option<String>,
        /// The Sender whose stream it is to take: its id, its label, or the start of its id.
        #[arg(long, value_name = "SENDER", group = "take", requires = "receiver")]
        sender: Option<String>,
        /// An SDP file of the stream it is to take, such as one from outside NMOS; `-`
        /// reads standard input.
        #[arg(long, value_name = "FILE", group = "take", requires = "receiver")]
        sdp: Option<PathBuf>,
        /// Disconnect it.
        #[arg(long, group = "take", requires = "receiver")]
        disconnect: bool,
        /// Cancel the activation scheduled on it.
        #[arg(long, group = "take", requires = "receiver", conflicts_with_all = ["at", "after", "dry_run"])]
        cancel: bool,
        /// A JSON file of connections to make together, such as
        /// [{"receiver": "MON 1", "sender": "CAM 2"}, {"receiver": "MON 2", "sdp":
        /// "feed.sdp"}, {"receiver": "MON 3", "disconnect": true}].
        #[arg(long, value_name = "FILE", conflicts_with = "take")]
        salvo: Option<PathBuf>,
        /// When they take effect: now, a PTP time such as 1790510437:0, or a UTC time such
        /// as 2026-09-27T12:00:00Z. Now for one connection when omitted, and --lead from
        /// now for several.
        #[arg(long, value_name = "TIME", conflicts_with = "after")]
        at: Option<String>,
        /// Seconds after each Connection API has the request that they take effect.
        #[arg(long = "in", value_name = "SECONDS")]
        after: Option<f64>,
        /// Seconds ahead to schedule several connections, for every Connection API to
        /// have its request in time.
        #[arg(long, value_name = "SECONDS", default_value_t = 2.0)]
        lead: f64,
        /// Plan and check the connections, and send nothing.
        #[arg(long)]
        dry_run: bool,
        /// Send connections the checks found problems with; the Receiver may refuse them.
        #[arg(long)]
        force: bool,
        /// Seconds to wait for each response.
        #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
        timeout: f64,
        /// Seconds to wait for a Receiver's /active endpoint, and then the registry, to
        /// show a connection; one scheduled further ahead is not waited for.
        #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
        wait: f64,
        /// TAI − UTC in seconds.
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = st2110_ptp::TAI_UTC_2017,
            allow_negative_numbers = true,
            value_parser = offset()
        )]
        tai_utc: i32,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
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
    /// Measure the ST 2110 streams and PTP messages in packet captures, as RP 2110-25
    /// describes, and check them against the standards.
    ///
    /// Reads pcap and pcapng files, as tcpdump, dumpcap and Wireshark write them. Give
    /// the streams' SDP files with --sdp to check each flow against its stream and run
    /// the ST 2110-21 models on its schedule; flows without one are recognised from their
    /// packets. Timing measurements need the capture's clock on PTP time, or on UTC to
    /// move onto it; --timescale auto works out which from PTP Sync messages, or else
    /// the RTP timestamps. Exits with 0 when nothing is an error, 1 when something is (or
    /// is a warning, with --deny-warnings), or a file ends partway through, and 2 when a
    /// file cannot be read or is not a capture.
    Pcap {
        /// Capture files; `-` reads standard input.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// An SDP file of streams in the captures; give it more than once for several.
        #[arg(long, value_name = "FILE")]
        sdp: Vec<PathBuf>,
        /// The clock that the capture's timestamps count.
        #[arg(long, value_enum, default_value_t = CaptureClock::Auto)]
        timescale: CaptureClock,
        /// TAI − UTC in seconds: how far a capture on UTC is behind PTP time.
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = st2110_ptp::TAI_UTC_2017,
            allow_negative_numbers = true,
            value_parser = offset()
        )]
        tai_utc: i32,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Print only warnings and errors, without the flows, PTP ports or notes (text output).
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
        #[arg(long, value_name = "SECONDS", allow_negative_numbers = true, value_parser = offset())]
        local_offset: Option<i32>,
        /// TAI − UTC in seconds.
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = st2110_ptp::TAI_UTC_2017,
            allow_negative_numbers = true,
            value_parser = offset()
        )]
        tai_utc: i32,
        /// The last daily jam, a whole second of PTP or UTC time, such as a grandmaster's
        /// timeOfPreviousJam. The last Local Time midnight when omitted.
        #[arg(long, value_name = "TIME")]
        jam: Option<String>,
        /// The local offset when the jam happened: ST 2059-2's previousJamLocalOffset.
        /// Time code keeps it until the next jam, so give it when the offset has changed
        /// since, as at a daylight saving change. --local-offset when omitted.
        #[arg(long, value_name = "SECONDS", allow_negative_numbers = true, value_parser = offset())]
        jam_local_offset: Option<i32>,
        /// Count 30000/1001 time code without dropping frames.
        #[arg(long)]
        non_drop: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Send colour bars or a tone as an ST 2110-20 video or ST 2110-30 audio stream.
    ///
    /// Sends from this machine on ordinary UDP sockets, each packet at its ST 2110-21
    /// time, paced by a spinning thread: a wide sender's timing at HD rates on a quiet
    /// machine. Frames and RTP timestamps line up with the SMPTE Epoch by the system
    /// clock, taken as UTC, with TAI --tai-utc ahead: PTP time when the clock follows
    /// PTP, as phc2sys keeps it. Writes the stream's SDP file to standard output, or to
    /// --sdp, before the first packet. Give --to twice for the two legs of an ST 2022-7
    /// pair. With --pcap, writes the packets into a capture file at their times instead,
    /// as fast as it can. Exits with 0 when the stream was sent, and 2 when it cannot be.
    Send {
        #[command(subcommand)]
        signal: stream::Signal,
    },
    /// Receive an ST 2110-20 video or ST 2110-30 audio stream and report what arrived.
    ///
    /// Reads the stream from its SDP file, joins each leg's multicast group (from the
    /// source the file names, for source-specific multicast) or listens on its unicast
    /// address, and merges the two legs of an ST 2022-7 pair. Reports each leg's packets
    /// and loss, the loss after merging, how far apart the legs arrive and the tightest
    /// ST 2022-7 class that allows it, incomplete and missing frames, gaps in the audio,
    /// and the latency from each RTP timestamp, which means something when both clocks
    /// follow PTP. With --pcap, reads the packets from a capture instead. Exits with 0
    /// when the stream arrived whole, 1 when packets were lost after merging, frames
    /// were incomplete or nothing arrived, and 2 when the stream cannot be received.
    Receive(stream::ReceiveArgs),
    /// Show an ST 2110-20 video stream in a window as it arrives.
    ///
    /// Receives the stream as `st2110 receive` does, from its SDP file, and shows each
    /// frame as it arrives, with the frames before it where its packets are missing,
    /// and the title counts those. With --pcap, plays a capture instead, at the pace it
    /// was captured. Escape or Q closes the window, and the report of what arrived
    /// follows. Exits as `st2110 receive` does.
    #[cfg(feature = "view")]
    View(view::ViewArgs),
    /// List the rules, or show the ones named.
    Rules {
        /// Rule identifiers, such as mediaclk-offset; every rule when none is given.
        ids: Vec<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,
    },
}

/// Reads an offset in seconds of at most a day either way, beyond any real one.
fn offset() -> clap::builder::RangedI64ValueParser<i32> {
    clap::value_parser!(i32).range(-86_400..=86_400)
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

/// The clock that a capture's timestamps count.
#[derive(Clone, Copy, ValueEnum)]
enum CaptureClock {
    /// Work it out from PTP Sync messages, or else the RTP timestamps.
    Auto,
    /// PTP time.
    Ptp,
    /// UTC, TAI − UTC behind PTP time.
    Utc,
}

impl From<CaptureClock> for st2110_pcap::Timescale {
    fn from(clock: CaptureClock) -> Self {
        match clock {
            CaptureClock::Auto => Self::Auto,
            CaptureClock::Ptp => Self::Ptp,
            CaptureClock::Utc => Self::Utc,
        }
    }
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
        Command::Connect {
            target,
            receiver,
            sender,
            sdp,
            disconnect,
            cancel,
            salvo,
            at,
            after,
            lead,
            dry_run,
            force,
            timeout,
            wait,
            tai_utc,
            format,
        } => {
            let args = connect::Args {
                target,
                receiver,
                sender,
                sdp,
                disconnect,
                cancel,
                salvo,
                at,
                after,
                lead,
                dry_run,
                force,
                timeout,
                wait,
                tai_utc,
            };
            connect::run(&args, format)
        }
        Command::Ptp { files, format, quiet, deny_warnings } => ptp::run(&files, format, quiet, deny_warnings),
        Command::Pcap { files, sdp, timescale, tai_utc, format, quiet, deny_warnings } => {
            let args = pcap::Args { files, sdp, timescale: timescale.into(), tai_utc };
            pcap::run(&args, format, quiet, deny_warnings)
        }
        Command::Time { at, video, audio, local_offset, tai_utc, jam, jam_local_offset, non_drop, format } => {
            let args = timing::Args { at, tai_utc, local_offset, video, audio, jam, jam_local_offset, non_drop };
            timing::run(&args, format)
        }
        Command::Send { signal } => stream::send(&signal),
        Command::Receive(args) => stream::receive(&args),
        #[cfg(feature = "view")]
        Command::View(args) => view::view(&args),
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

/// A number of seconds given for `option`: a timeout, a wait or a lead, up to a day.
pub(crate) fn seconds(option: &str, value: f64) -> Result<Duration, String> {
    Duration::try_from_secs_f64(value)
        .ok()
        .filter(|duration| duration.as_secs() < 86_400)
        .ok_or_else(|| format!("{option} {value} is not a number of seconds from 0 to a day"))
}

pub(crate) fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

/// Every rule: the SDP, NMOS, PTP message and capture catalogues in turn.
fn all_rules() -> impl Iterator<Item = &'static Rule> {
    st2110_sdp::rules::ALL
        .iter()
        .chain(st2110_nmos::rules::ALL)
        .chain(st2110_ptp::rules::ALL)
        .chain(st2110_pcap::rules::ALL)
        .copied()
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
         `st2110 ptp` checks these in each message against the ST 2059-2 profile, and \
         `st2110 pcap` in each port's messages in a capture.\n\n{}\n\
         ## Captures\n\n\
         `st2110 pcap` checks these across a capture's RTP flows and PTP messages, measuring \
         them as RP 2110-25 describes.\n\n{}",
        st2110_sdp::rules::markdown_table(st2110_sdp::rules::ALL),
        st2110_sdp::rules::markdown_table(st2110_nmos::rules::ALL),
        st2110_sdp::rules::markdown_table(st2110_ptp::rules::ALL),
        st2110_sdp::rules::markdown_table(st2110_pcap::rules::ALL)
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
