//! Checks on the format parameter list itself: repeats, quoting, spelling.

use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rules;
use crate::stream::Media;

/// Parameters ST 2110-10 and -21 define for every essence.
const SHARED: [&str; 6] = ["MAXUDP", "TSMODE", "TSDELAY", "TROFF", "CMAX", "TP"];

/// What an essence standard says about its parameter names.
pub(super) struct Names<'a> {
    /// The standard spellings of the essence's own parameters.
    pub known: &'a [&'a str],
    /// Report names outside `known` and the shared set.
    pub strict: bool,
    /// Names that may appear more than once.
    pub repeatable: &'a [&'a str],
}

pub(super) fn check(m: &Media<'_>, line: usize, fmtp: &Fmtp, names: &Names<'_>, d: &mut Diagnostics) {
    let mut seen: Vec<String> = Vec::new();
    let mut repeated: Vec<String> = Vec::new();
    for p in &fmtp.params {
        let lower = p.name.to_ascii_lowercase();
        if seen.contains(&lower) {
            let may_repeat = names.repeatable.iter().any(|r| r.eq_ignore_ascii_case(&p.name));
            if !may_repeat && !repeated.contains(&lower) {
                d.report(&rules::FMTP_DUPLICATE_PARAM, m.index, line, format!("{} appears more than once", p.name));
                repeated.push(lower);
            }
        } else {
            seen.push(lower);
        }
        if p.quoted {
            d.report(
                &rules::FMTP_QUOTED_VALUE,
                m.index,
                line,
                format!(
                    "{}=\"{}\" is quoted; write {}={}",
                    p.name,
                    p.value.as_deref().unwrap_or(""),
                    p.name,
                    p.value.as_deref().unwrap_or("")
                ),
            );
        }
        let spelling = SHARED.iter().chain(names.known).find(|k| k.eq_ignore_ascii_case(&p.name));
        match spelling {
            Some(standard) if *standard != p.name => {
                d.report(
                    &rules::FMTP_PARAM_CASE,
                    m.index,
                    line,
                    format!("{}: the standard spells it {standard}", p.name),
                );
            }
            None if names.strict => {
                d.report(
                    &rules::FMTP_UNKNOWN_PARAM,
                    m.index,
                    line,
                    format!("{} is not an ST 2110-20, -21 or -10 parameter; receivers may ignore or reject it", p.name),
                );
            }
            _ => {}
        }
    }
}

/// Reports a missing required parameter.
pub(super) fn require(
    m: &Media<'_>,
    line: usize,
    fmtp: &Fmtp,
    name: &str,
    reference: &'static str,
    d: &mut Diagnostics,
) {
    if !fmtp.has(name) {
        d.report(&rules::PARAM_MISSING, m.index, line, format!("{name} is required")).cite(reference);
    }
}

/// Returns the value when it is one of `allowed`, and reports it otherwise.
pub(super) fn one_of<'f>(
    m: &Media<'_>,
    line: usize,
    fmtp: &'f Fmtp,
    name: &str,
    allowed: &[&str],
    reference: &'static str,
    d: &mut Diagnostics,
) -> Option<&'f str> {
    let param = fmtp.get(name)?;
    let Some(value) = param.value.as_deref() else {
        d.report(&rules::PARAM_VALUE, m.index, line, format!("{name} needs a value")).cite(reference);
        return None;
    };
    if allowed.contains(&value) {
        return Some(value);
    }
    let message = match allowed.iter().find(|a| a.eq_ignore_ascii_case(value)) {
        Some(spelling) => format!("{name}={value}: the standard spells it {spelling}"),
        None => format!("{name}={value} is not defined; use one of {}", allowed.join(", ")),
    };
    d.report(&rules::PARAM_VALUE, m.index, line, message).cite(reference);
    None
}

/// Returns the value when it is a whole number in `range`, and reports it otherwise.
pub(super) fn number(
    m: &Media<'_>,
    line: usize,
    fmtp: &Fmtp,
    name: &str,
    range: std::ops::RangeInclusive<u32>,
    reference: &'static str,
    d: &mut Diagnostics,
) -> Option<u32> {
    let param = fmtp.get(name)?;
    let value = param.value.as_deref().unwrap_or("");
    match crate::rational::digits(value).and_then(|n| u32::try_from(n).ok()) {
        Some(n) if range.contains(&n) => Some(n),
        _ => {
            d.report(
                &rules::PARAM_VALUE,
                m.index,
                line,
                format!("{name}={value} is not a whole number from {} to {}", range.start(), range.end()),
            )
            .cite(reference);
            None
        }
    }
}
