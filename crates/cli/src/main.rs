//! `st2110`: check SMPTE ST 2110 SDP files from the command line.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use st2110_sdp::{Diagnostic, Report, Rule, Severity, Stream, rules};

#[derive(Parser)]
#[command(name = "st2110", version, about = "Check SMPTE ST 2110 SDP files against the standards")]
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
    /// List the lint rules, or show the ones named.
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

/// Reads a file, or standard input for `-`. Bytes that are not UTF-8, as in a
/// Latin-1 session name, become U+FFFD rather than stopping the check.
fn read(path: &Path) -> io::Result<String> {
    let bytes = if path.as_os_str() == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        bytes
    } else {
        fs::read(path)?
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// ANSI colours, used only when writing to a terminal and `NO_COLOR` is unset.
#[derive(Clone, Copy)]
struct Style {
    color: bool,
}

impl Style {
    fn detect() -> Self {
        Self { color: io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
    }

    fn severity(self, severity: Severity) -> String {
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

fn describe(stream: &Stream) -> String {
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

fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

fn list_rules(ids: &[String], format: RulesFormat) -> io::Result<ExitCode> {
    let mut selected: Vec<&Rule> = Vec::new();
    for id in ids {
        match rules::find(id) {
            Some(rule) => selected.push(rule),
            None => {
                eprintln!("st2110: no rule is named {id}; `st2110 rules` lists them all");
                return Ok(ExitCode::from(2));
            }
        }
    }
    if ids.is_empty() {
        selected = rules::ALL.to_vec();
    }
    let mut out = io::stdout().lock();
    match format {
        RulesFormat::Markdown if ids.is_empty() => write!(out, "{}", rules::markdown())?,
        RulesFormat::Markdown => write!(out, "{}", rules::markdown_table(&selected))?,
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
