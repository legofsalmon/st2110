//! Diagnostics: what a check found, how serious it is and where the rule comes from.

use std::fmt;

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(rename_all = "lowercase"))]
pub enum Severity {
    /// An observation that needs no action on its own.
    Info,
    /// A "should" in the standards, or a known interoperability hazard.
    Warning,
    /// A "shall" (or an RFC "MUST") is broken: receivers may reject or misread the stream.
    Error,
}

impl Severity {
    /// The lowercase name: `info`, `warning` or `error`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lint rule: what it checks and which document requires it.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Rule {
    /// Stable identifier, such as `mediaclk-offset`.
    pub id: &'static str,
    /// Severity of every diagnostic the rule raises.
    pub severity: Severity,
    /// The document and clause the rule comes from.
    pub reference: &'static str,
    /// One sentence on what the rule checks.
    pub summary: &'static str,
}

/// One finding in a session description.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Diagnostic {
    /// Identifier of the rule that raised it.
    pub rule: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong and, where it helps, what to write instead.
    pub message: String,
    /// Line in the input, counting from 1.
    pub line: Option<usize>,
    /// Index into [`Report::streams`](crate::Report::streams) when the finding is about one stream.
    pub stream: Option<usize>,
    /// The document and clause behind this finding.
    pub reference: &'static str,
}

impl Diagnostic {
    pub(crate) fn at(&mut self, line: usize) -> &mut Self {
        self.line = Some(line);
        self
    }

    pub(crate) fn in_stream(&mut self, index: usize) -> &mut Self {
        self.stream = Some(index);
        self
    }

    /// Replaces the rule's general reference with the clause this finding comes from.
    pub(crate) fn cite(&mut self, reference: &'static str) -> &mut Self {
        self.reference = reference;
        self
    }
}

/// Collects diagnostics while a description is checked.
#[derive(Debug, Default)]
pub(crate) struct Diagnostics(Vec<Diagnostic>);

impl Diagnostics {
    pub(crate) fn add(&mut self, rule: &'static Rule, message: impl Into<String>) -> &mut Diagnostic {
        self.0.push(Diagnostic {
            rule: rule.id,
            severity: rule.severity,
            message: message.into(),
            line: None,
            stream: None,
            reference: rule.reference,
        });
        self.0.last_mut().expect("just pushed")
    }

    /// Adds a finding about one stream at one line.
    pub(crate) fn report(
        &mut self,
        rule: &'static Rule,
        stream: usize,
        line: usize,
        message: impl Into<String>,
    ) -> &mut Diagnostic {
        self.add(rule, message).at(line).in_stream(stream)
    }

    /// Findings in line order; the most serious first within a line.
    pub(crate) fn into_sorted(mut self) -> Vec<Diagnostic> {
        self.0.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
        self.0
    }
}
