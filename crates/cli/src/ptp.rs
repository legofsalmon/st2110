//! `st2110 ptp`: decode PTP messages and check them against ST 2059-2.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use st2110_ptp::{Finding, Message};
use st2110_sdp::Severity;

use crate::{Format, Style, plural, read_bytes};

/// One file's messages.
#[derive(Serialize)]
struct Checked {
    file: String,
    messages: Vec<Entry>,
}

/// One message: where it was, and what it said or why it could not be read.
#[derive(Serialize)]
struct Entry {
    /// Its line, in a file of hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Outcome {
    Decoded { summary: Vec<String>, message: Box<Message>, findings: Vec<Finding> },
    Failed { error: String },
}

impl Entry {
    fn errors(&self) -> usize {
        match &self.outcome {
            Outcome::Decoded { findings, .. } => count(findings, Severity::Error),
            Outcome::Failed { .. } => 1,
        }
    }

    fn findings(&self) -> &[Finding] {
        match &self.outcome {
            Outcome::Decoded { findings, .. } => findings,
            Outcome::Failed { .. } => &[],
        }
    }
}

fn count(findings: &[Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

pub(crate) fn run(files: &[PathBuf], format: Format, quiet: bool, deny_warnings: bool) -> io::Result<ExitCode> {
    let mut checked = Vec::new();
    let mut unreadable = false;
    for path in files {
        let file = path.display().to_string();
        match read_bytes(path) {
            Ok(bytes) => checked.push(Checked { file, messages: entries(&bytes) }),
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
    let failed = checked
        .iter()
        .flat_map(|c| &c.messages)
        .any(|e| e.errors() > 0 || (deny_warnings && count(e.findings(), Severity::Warning) > 0));
    Ok(match (unreadable, failed) {
        (true, _) => ExitCode::from(2),
        (false, true) => ExitCode::from(1),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// The messages in a file: one per line of hex, as `tshark -T fields -e udp.payload`
/// writes them, or the whole file as one message in binary.
fn entries(bytes: &[u8]) -> Vec<Entry> {
    // A binary message always has control characters: its second octet is 02h or 12h.
    if !bytes.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        return vec![Entry { line: None, outcome: outcome(Ok(bytes.to_vec())) }];
    }
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let line = line.split('#').next().unwrap_or_default().trim();
            (!line.is_empty()).then(|| Entry { line: Some(i + 1), outcome: outcome(hex(line)) })
        })
        .collect()
}

fn outcome(bytes: Result<Vec<u8>, String>) -> Outcome {
    match bytes.and_then(|bytes| st2110_ptp::decode(&bytes).map_err(|e| e.to_string())) {
        Ok(message) => Outcome::Decoded {
            summary: st2110_ptp::describe::summary(&message),
            findings: st2110_ptp::check(&message),
            message: Box::new(message),
        },
        Err(error) => Outcome::Failed { error },
    }
}

/// Reads hex digits, ignoring spaces and the colons some tools put between octets.
fn hex(line: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = line.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b':').collect();
    if let Some(bad) = digits.iter().find(|b| !b.is_ascii_hexdigit()) {
        return Err(format!("{:?} is not a hex digit; each line should be one message in hex", char::from(*bad)));
    }
    if digits.len() % 2 == 1 {
        return Err(format!("{} hex digits, an odd number", digits.len()));
    }
    let value = |b: u8| (b as char).to_digit(16).expect("checked above") as u8;
    Ok(digits.as_chunks::<2>().0.iter().map(|&[high, low]| value(high) << 4 | value(low)).collect())
}

fn write_text(out: &mut impl Write, c: &Checked, quiet: bool, style: Style) -> io::Result<()> {
    for entry in &c.messages {
        let location = match entry.line {
            Some(line) => format!("{}:{line}", c.file),
            None => c.file.clone(),
        };
        match &entry.outcome {
            Outcome::Decoded { summary, findings, .. } => {
                if !quiet && let Some((first, rest)) = summary.split_first() {
                    writeln!(out, "{}: {first}", style.paint("1", &location))?;
                    for line in rest {
                        writeln!(out, "  {line}")?;
                    }
                }
                for f in findings.iter().filter(|f| !quiet || f.severity != Severity::Info) {
                    writeln!(
                        out,
                        "{location}: {}[{}]: {} ({})",
                        style.severity(f.severity),
                        f.rule,
                        f.message,
                        f.reference
                    )?;
                }
            }
            Outcome::Failed { error } => writeln!(out, "{location}: {}: {error}", style.severity(Severity::Error))?,
        }
    }
    let findings: Vec<&Finding> = c.messages.iter().flat_map(Entry::findings).collect();
    let errors = c.messages.iter().map(Entry::errors).sum::<usize>();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let notes = findings.iter().filter(|f| f.severity == Severity::Info).count();
    let messages = plural(c.messages.len(), "message");
    if errors + warnings + notes == 0 {
        if !quiet {
            writeln!(out, "{}: {messages}, no problems found", c.file)?;
        }
    } else if !quiet || errors + warnings > 0 {
        writeln!(
            out,
            "{}: {messages}, {}, {}, {}",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hex() {
        assert_eq!(hex("00 02 00:2c"), Ok(vec![0x00, 0x02, 0x00, 0x2C]));
        assert_eq!(hex("0A0b"), Ok(vec![0x0A, 0x0B]));
        assert!(hex("0x02").unwrap_err().contains("'x' is not a hex digit"));
        assert!(hex("+1").is_err());
        assert_eq!(hex("abc"), Err("3 hex digits, an odd number".into()));
    }
}
