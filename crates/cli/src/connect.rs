//! `st2110 connect`: connect Receivers to Senders through IS-05, or list which Senders
//! each Receiver can take.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use st2110_connect::Activation;
use st2110_connect::client::{self, ConnectionClient};
use st2110_connect::controller::{self, Connection, Outcome, Route, Settings, State, Take};
use st2110_nmos::client::{Options, QueryClient};
use st2110_nmos::routing::{self, Matrix};
use st2110_nmos::{Kind, Snapshot};
use st2110_ptp::PtpTime;
use st2110_ptp::timing::read_time;

use crate::timing::now;
use crate::{Format, Style, plural, read, seconds};

/// The command's arguments, as given.
pub(crate) struct Args {
    pub target: String,
    pub receiver: Option<String>,
    pub sender: Option<String>,
    pub sdp: Option<PathBuf>,
    pub disconnect: bool,
    pub cancel: bool,
    pub salvo: Option<PathBuf>,
    pub at: Option<String>,
    pub after: Option<f64>,
    pub lead: f64,
    pub dry_run: bool,
    pub force: bool,
    pub timeout: f64,
    pub wait: f64,
    pub tai_utc: i32,
}

pub(crate) fn run(args: &Args, format: Format) -> io::Result<ExitCode> {
    let result = match (&args.salvo, &args.receiver, &args.sender, &args.sdp, args.disconnect) {
        (None, Some(receiver), ..) if args.cancel => cancel(args, receiver, format),
        (None, _, None, None, false) => {
            let making = [
                ("--dry-run", args.dry_run),
                ("--force", args.force),
                ("--at", args.at.is_some()),
                ("--in", args.after.is_some()),
            ];
            match making.iter().find(|(_, given)| *given) {
                Some((option, _)) => Err(Failure::Usage(format!(
                    "{option} is for making connections: give --receiver with --sender, --sdp or --disconnect, \
                     or --salvo"
                ))),
                None => list(args, format),
            }
        }
        _ => make(args, format),
    };
    match result {
        Ok(code) => Ok(code),
        Err(Failure::Io(e)) => Err(e),
        Err(Failure::Usage(message)) => {
            eprintln!("st2110: {message}");
            Ok(ExitCode::from(2))
        }
    }
}

/// Why the command stopped short.
enum Failure {
    /// Something that could not be read, or was not asked for properly.
    Usage(String),
    Io(io::Error),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Usage(message)
    }
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Failure {
    fn from(e: serde_json::Error) -> Self {
        Self::Io(e.into())
    }
}

/// Reads the registry, with each Sender's SDP file when `fetch_sdp` is set, or a
/// snapshot saved with `st2110 nmos --save`. A snapshot has no registry to check
/// connections in afterwards.
fn load(target: &str, timeout: Duration, fetch_sdp: bool) -> Result<(Snapshot, Option<QueryClient>), String> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let options = Options { timeout, fetch_sdp, ..Options::default() };
        let registry = QueryClient::connect(target, &options).map_err(|e| e.to_string())?;
        let snapshot = registry.snapshot().map_err(|e| e.to_string())?;
        return Ok((snapshot, Some(registry)));
    }
    let text = read(Path::new(target)).map_err(|e| format!("{target}: {e}"))?;
    let snapshot = Snapshot::from_json(&text).map_err(|e| format!("{target}: not a registry snapshot: {e}"))?;
    Ok((snapshot, None))
}

/// Lists which Senders each Receiver can take, or the one Receiver named. The SDP files
/// are read too, for the capabilities that are judged on them.
fn list(args: &Args, format: Format) -> Result<ExitCode, Failure> {
    let timeout = seconds("--timeout", args.timeout)?;
    let (snapshot, _) = load(&args.target, timeout, true)?;
    let mut matrix = routing::matrix(&snapshot);
    if let Some(name) = &args.receiver {
        let receiver = routing::find(&snapshot, Kind::Receiver, name)?;
        matrix.receivers.retain(|row| row.receiver.id.as_deref() == Some(receiver.id.as_str()));
    }
    let mut out = io::stdout().lock();
    match format {
        Format::Text => write_matrix(&mut out, &matrix, Style::detect())?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &matrix)?;
            writeln!(out)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn write_matrix(out: &mut impl Write, matrix: &Matrix, style: Style) -> io::Result<()> {
    if matrix.receivers.is_empty() {
        return writeln!(out, "no receivers are registered");
    }
    for row in &matrix.receivers {
        writeln!(out, "{}", style.paint("1", &row.receiver.describe()))?;
        if row.fits.is_empty() {
            writeln!(out, "  takes none of the {}", plural(matrix.senders.len(), "registered sender"))?;
        }
        for &i in &row.fits {
            let now = if row.current == Some(i) { ", taking it now" } else { "" };
            writeln!(out, "  {}{now}", matrix.senders[i].describe())?;
        }
    }
    Ok(())
}

/// Cancels the activation scheduled on a Receiver.
fn cancel(args: &Args, receiver: &str, format: Format) -> Result<ExitCode, Failure> {
    let timeout = seconds("--timeout", args.timeout)?;
    let (snapshot, _) = load(&args.target, timeout, false)?;
    let client = ConnectionClient::new(&client::Options { timeout, ..client::Options::default() });
    let cancelled = controller::cancel(&snapshot, receiver, &client)?;
    let mut out = io::stdout().lock();
    match format {
        Format::Text => {
            let name = Style::detect().paint("1", &cancelled.receiver.describe());
            let what = match (&cancelled.problem, cancelled.was_due.as_deref().and_then(PtpTime::parse)) {
                (Some(problem), _) => format!("not cancelled: {problem}"),
                (None, Some(due)) => format!("cancelled the activation due at {} UTC", due.utc(args.tai_utc)),
                (None, None) => "no activation was scheduled".into(),
            };
            writeln!(out, "{name}: {what}")?;
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &cancelled)?;
            writeln!(out)?;
        }
    }
    Ok(if cancelled.problem.is_some() { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// A connection in a salvo file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    receiver: String,
    sender: Option<String>,
    sdp: Option<PathBuf>,
    #[serde(default)]
    disconnect: bool,
}

/// What a Receiver is to take, from the options or a salvo entry. SDP files are read
/// from `base`.
fn take(sender: Option<&str>, sdp: Option<&Path>, disconnect: bool, base: &Path) -> Result<Take, String> {
    match (sender, sdp, disconnect) {
        (Some(sender), None, false) => Ok(Take::Sender(sender.to_string())),
        (None, Some(path), false) => {
            let path = if path.as_os_str() == "-" || path.is_absolute() { path.to_path_buf() } else { base.join(path) };
            let text = read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(Take::Sdp { name: path.display().to_string(), text })
        }
        (None, None, true) => Ok(Take::Nothing),
        _ => Err("give one of a sender, an SDP file or disconnect".into()),
    }
}

fn routes(args: &Args) -> Result<Vec<Route>, String> {
    let Some(path) = &args.salvo else {
        let receiver = args.receiver.clone().ok_or("--sender, --sdp and --disconnect need --receiver")?;
        let take = take(args.sender.as_deref(), args.sdp.as_deref(), args.disconnect, Path::new(""))?;
        return Ok(vec![Route { receiver, take }]);
    };
    let file = path.display();
    let text = read(path).map_err(|e| format!("{file}: {e}"))?;
    let entries: Vec<Entry> = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{file}: not a salvo: {e}. It is a JSON array of connections, such as \
             [{{\"receiver\": \"MON 1\", \"sender\": \"CAM 2\"}}, {{\"receiver\": \"MON 2\", \"sdp\": \"feed.sdp\"}}, \
             {{\"receiver\": \"MON 3\", \"disconnect\": true}}]"
        )
    })?;
    if entries.is_empty() {
        return Err(format!("{file}: the salvo holds no connections"));
    }
    let base = path.parent().unwrap_or(Path::new(""));
    entries
        .into_iter()
        .enumerate()
        .map(|(i, entry)| {
            let take = take(entry.sender.as_deref(), entry.sdp.as_deref(), entry.disconnect, base)
                .map_err(|e| format!("{file}: connection {}: {e}", i + 1))?;
            Ok(Route { receiver: entry.receiver, take })
        })
        .collect()
}

fn activation(args: &Args) -> Result<Option<Activation>, String> {
    match (&args.at, args.after) {
        (Some(text), _) if text.trim().eq_ignore_ascii_case("now") => Ok(Some(Activation::Immediate)),
        (Some(text), _) => {
            let at = read_time(text, args.tai_utc).ok_or_else(|| {
                format!(
                    "--at {text}: not now, a PTP time such as 1790510437:0 or 1790510437.5, or a UTC time such as \
                     2026-09-27T12:00:00Z"
                )
            })?;
            if at <= now(args.tai_utc)? {
                return Err(format!("--at {text} has passed"));
            }
            Ok(Some(Activation::At(at)))
        }
        (None, Some(after)) => {
            let after =
                Duration::try_from_secs_f64(after).map_err(|_| format!("--in {after} is not a number of seconds"))?;
            let nanos =
                u64::try_from(after.as_nanos()).map_err(|_| format!("--in {} is too far off", after.as_secs()))?;
            Ok(Some(Activation::After(nanos)))
        }
        (None, None) => Ok(None),
    }
}

/// Makes the connections asked for.
fn make(args: &Args, format: Format) -> Result<ExitCode, Failure> {
    let routes = routes(args)?;
    let settings = Settings {
        activation: activation(args)?,
        lead: seconds("--lead", args.lead)?,
        force: args.force,
        dry_run: args.dry_run,
        wait: seconds("--wait", args.wait)?,
        tai_utc: args.tai_utc,
    };
    let timeout = seconds("--timeout", args.timeout)?;
    if timeout.is_zero() {
        return Err(Failure::Usage("--timeout 0 is not a number of seconds above 0".into()));
    }
    let (snapshot, registry) = load(&args.target, timeout, false)?;
    let client = ConnectionClient::new(&client::Options { timeout, ..client::Options::default() });
    let outcome = controller::connect(&snapshot, &routes, &client, registry.as_ref(), &settings)?;
    let mut out = io::stdout().lock();
    match format {
        Format::Text => write_outcome(&mut out, &outcome, args.tai_utc, Style::detect())?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &outcome)?;
            writeln!(out)?;
        }
    }
    Ok(if outcome.succeeded() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn write_outcome(out: &mut impl Write, outcome: &Outcome, tai_utc: i32, style: Style) -> io::Result<()> {
    for connection in &outcome.connections {
        let state = connection.state;
        let code = match state {
            State::Planned | State::Scheduled | State::Done => "1;32",
            State::RolledBack | State::Held => "1;33",
            _ => "1;31",
        };
        let mut line = format!(
            "{} ← {}: {}",
            style.paint("1", &connection.receiver.describe()),
            connection.describe_take(),
            style.paint(code, state.describe())
        );
        if let Some(time) = connection.activation_time.as_deref().and_then(PtpTime::parse) {
            let when = if state == State::Scheduled { "for" } else { "at" };
            line.push_str(&format!(" {when} {} UTC", time.utc(tai_utc)));
        }
        writeln!(out, "{line}")?;
        for (i, leg) in legs(connection).iter().enumerate() {
            writeln!(out, "  leg {}: {leg}", i + 1)?;
        }
        for (label, texts) in
            [("note", &connection.notes), ("problem", &connection.problems), ("warning", &connection.warnings)]
        {
            for text in texts {
                writeln!(out, "  {label}: {text}")?;
            }
        }
    }
    let mut counts: Vec<(State, usize)> = Vec::new();
    for connection in &outcome.connections {
        match counts.iter_mut().find(|(state, _)| *state == connection.state) {
            Some((_, count)) => *count += 1,
            None => counts.push((connection.state, 1)),
        }
    }
    let counts: Vec<String> = counts.iter().map(|(state, count)| format!("{count} {}", state.describe())).collect();
    writeln!(out, "{}: {}", plural(outcome.connections.len(), "connection"), counts.join(", "))
}

/// Each leg of a connection's request, as `239.10.10.1:5004 from 192.168.10.21` or `off`.
fn legs(connection: &Connection) -> Vec<String> {
    let Some(params) = connection.request.as_ref().and_then(|r| r.get("transport_params")).and_then(Value::as_array)
    else {
        return Vec::new();
    };
    params
        .iter()
        .map(|leg| {
            let text = |name: &str| leg.get(name).and_then(Value::as_str);
            if leg.get("rtp_enabled") == Some(&Value::Bool(false)) {
                return "off".to_string();
            }
            let address = text("multicast_ip").or(text("interface_ip")).unwrap_or("?");
            let address = if address.contains(':') { format!("[{address}]") } else { address.to_string() };
            let port = leg.get("destination_port").map_or_else(|| "?".to_string(), |p| p.to_string());
            match (text("source_ip"), text("multicast_ip")) {
                (Some(source), _) => format!("{address}:{port} from {source}"),
                (None, Some(_)) => format!("{address}:{port} from any source"),
                (None, None) => format!("{address}:{port}, unicast"),
            }
        })
        .collect()
}
