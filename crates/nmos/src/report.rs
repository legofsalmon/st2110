//! What a check of a registry found.

use serde::Serialize;
use st2110_sdp::{Rule, Severity, Stream};

use crate::model::{Core, Kind};

/// Which resource a finding is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceRef {
    /// Its type.
    pub kind: Kind,
    /// Its `id`, when it has a readable one.
    pub id: Option<String>,
    /// Its `label`, which may be empty.
    pub label: String,
    /// Its position in the snapshot's list of this type, counting from 0.
    pub index: usize,
}

impl ResourceRef {
    pub(crate) fn of(core: &Core<'_>) -> Self {
        Self { kind: core.kind, id: core.id.map(str::to_string), label: core.label.to_string(), index: core.index }
    }

    /// A short name for messages: the label and the first 8 characters of the id,
    /// such as `"CAM 1 video" (3f2c1d0e)`.
    pub fn describe(&self) -> String {
        let id = match &self.id {
            Some(id) => id.chars().take(8).collect(),
            None => format!("#{}", self.index),
        };
        if self.label.is_empty() {
            format!("{} {id}", self.kind.as_str())
        } else {
            format!("{} \"{}\" ({id})", self.kind.as_str(), self.label)
        }
    }
}

/// One finding: a registry rule broken by a resource, or a problem in a Sender's SDP file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Identifier of the rule, from [`crate::rules`] or, for a finding in an SDP file,
    /// from [`st2110_sdp::rules`].
    pub rule: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub message: String,
    /// The document and clause behind the rule.
    pub reference: &'static str,
    /// The resource it is about; `None` for the registry as a whole.
    pub resource: Option<ResourceRef>,
    /// For a finding in a Sender's SDP file, the line, counting from 1.
    pub line: Option<usize>,
}

/// Collects findings while a snapshot is checked.
#[derive(Default)]
pub(crate) struct Findings(Vec<Finding>);

impl Findings {
    pub fn add(&mut self, rule: &'static Rule, core: &Core<'_>, message: impl Into<String>) {
        self.0.push(Finding {
            rule: rule.id,
            severity: rule.severity,
            message: message.into(),
            reference: rule.reference,
            resource: Some(ResourceRef::of(core)),
            line: None,
        });
    }

    /// Adds what the SDP linter found in a Sender's transport file.
    pub fn sdp(&mut self, sender: &Core<'_>, diagnostics: Vec<st2110_sdp::Diagnostic>) {
        for d in diagnostics {
            self.0.push(Finding {
                rule: d.rule,
                severity: d.severity,
                message: d.message,
                reference: d.reference,
                resource: Some(ResourceRef::of(sender)),
                line: d.line,
            });
        }
    }

    /// Findings grouped by resource type, then label and id, in the order they were
    /// found within a resource except that SDP findings follow in line order.
    pub fn into_sorted(mut self) -> Vec<Finding> {
        self.0.sort_by(|a, b| {
            let key =
                |f: &Finding| f.resource.as_ref().map(|r| (r.kind, r.label.to_lowercase(), r.id.clone(), r.index));
            key(a).cmp(&key(b)).then(a.line.cmp(&b.line))
        });
        self.0
    }
}

/// A Sender, as a controller would list it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SenderView {
    /// Its `id`.
    pub id: Option<String>,
    /// Its `label`.
    pub label: String,
    /// The label of its Node.
    pub node: Option<String>,
    /// The label of its Device.
    pub device: Option<String>,
    /// The transport URN, such as `urn:x-nmos:transport:rtp.mcast`.
    pub transport: Option<String>,
    /// Whether it is sending; `None` for a Sender from before IS-04 v1.2.
    pub active: Option<bool>,
    /// The `id` of the Flow it sends.
    pub flow_id: Option<String>,
    /// The Flow's media type, such as `video/raw`.
    pub media_type: Option<String>,
    /// Where its SDP file is published.
    pub manifest_href: Option<String>,
    /// The streams its SDP file declares, when the file was fetched.
    pub streams: Vec<Stream>,
    /// The Receivers that are taking its stream.
    pub receivers: Vec<String>,
}

/// A Receiver, as a controller would list it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReceiverView {
    /// Its `id`.
    pub id: Option<String>,
    /// Its `label`.
    pub label: String,
    /// The label of its Node.
    pub node: Option<String>,
    /// The label of its Device.
    pub device: Option<String>,
    /// The transport URN.
    pub transport: Option<String>,
    /// The format URN, such as `urn:x-nmos:format:video`.
    pub format: Option<String>,
    /// Whether it is taking a stream.
    pub active: bool,
    /// The Sender it takes its stream from.
    pub sender_id: Option<String>,
    /// That Sender's label, when it is registered.
    pub sender_label: Option<String>,
}

/// A grandmaster and the number of locked PTP clocks that follow it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Grandmaster {
    /// The clock identity, as IS-04 writes it: `08-00-11-ff-fe-21-e1-b0`.
    pub id: String,
    /// How many Node clocks are locked to it.
    pub clocks: usize,
}

/// Counts across the registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Registered Nodes.
    pub nodes: usize,
    /// Registered Devices.
    pub devices: usize,
    /// Registered Sources.
    pub sources: usize,
    /// Registered Flows.
    pub flows: usize,
    /// Registered Senders.
    pub senders: usize,
    /// Registered Receivers.
    pub receivers: usize,
    /// Senders that are sending.
    pub active_senders: usize,
    /// Receivers that are taking a stream.
    pub active_receivers: usize,
    /// Grandmasters the Nodes' PTP clocks are locked to, the most followed first.
    pub grandmasters: Vec<Grandmaster>,
    /// PTP clocks that are not locked.
    pub unlocked_clocks: usize,
}

/// What [`check`](crate::check) found in a registry snapshot.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    /// Where the resources came from.
    pub source: Option<String>,
    /// The Query API version they were read through.
    pub api_version: Option<String>,
    /// Counts across the registry.
    pub summary: Summary,
    /// Every Sender, in label order.
    pub senders: Vec<SenderView>,
    /// Every Receiver, in label order.
    pub receivers: Vec<ReceiverView>,
    /// Every finding, grouped by resource.
    pub findings: Vec<Finding>,
}

impl Report {
    /// True if any finding is an error.
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    /// The number of findings of one severity.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }
}
