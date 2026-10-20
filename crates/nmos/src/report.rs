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

    /// Adds a finding about the system as a whole, such as its System API.
    pub fn system(&mut self, rule: &'static Rule, message: impl Into<String>) {
        self.0.push(Finding {
            rule: rule.id,
            severity: rule.severity,
            message: message.into(),
            reference: rule.reference,
            resource: None,
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
    /// Its IS-11 `status` `state`, such as `constrained`, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat: Option<String>,
    /// How many IS-11 active constraint sets it has, when they were read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_constraints: Option<usize>,
    /// What its BCP-008-02 monitor says, when its Device's IS-12 endpoint was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor: Option<MonitorView>,
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
    /// Its IS-11 `status` `state`, such as `compliant_stream`, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat: Option<String>,
    /// What its BCP-008-01 monitor says, when its Device's IS-12 endpoint was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor: Option<MonitorView>,
}

/// What an IS-12 status monitor says of the Receiver or Sender it watches (BCP-008-01
/// and -02), as a controller shows it: the messages verbatim, as the Device words them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MonitorView {
    /// Its Device's IS-12 control endpoint.
    pub href: String,
    /// Its role in the Device model.
    pub role: String,
    /// Its `overallStatus`: `Inactive`, `Healthy`, `PartiallyHealthy` or `Unhealthy`.
    pub overall: Option<String>,
    /// Its `overallStatusMessage`.
    pub overall_message: Option<String>,
    /// Each domain's status: link, connection or transmission, synchronization, and
    /// stream or essence.
    pub domains: Vec<DomainStatus>,
    /// Its `synchronizationSourceId`.
    pub synchronization_source: Option<String>,
    /// Its lost and late packet counters, or its transmission error counters.
    pub counters: Vec<MonitorCounter>,
}

/// One domain of a status monitor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DomainStatus {
    /// `link`, `connection`, `transmission`, `synchronization`, `stream` or `essence`.
    pub domain: String,
    /// Its status, such as `Healthy`, `AllUp` or `NotUsed`.
    pub status: String,
    /// Why, as the Device says.
    pub message: Option<String>,
    /// How often it has become less healthy since the counters were last reset.
    pub transitions: Option<u64>,
}

/// A counter a monitor keeps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MonitorCounter {
    /// Which: `lost`, `late` or `transmission_errors`.
    pub kind: String,
    /// The counter's name, as the Device gives it.
    pub name: String,
    /// Its value.
    pub value: u64,
}

/// A Node's network interface, with what LLDP says of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceView {
    /// Its name, such as `eth0`.
    pub name: String,
    /// The LLDP chassis ID the Node sends; `None` where it sends none.
    pub chassis_id: Option<String>,
    /// The LLDP port ID: the interface's MAC address.
    pub port_id: Option<String>,
    /// The switch it is plugged into, by the chassis ID the switch sends in LLDP.
    pub switch: Option<String>,
    /// The switch port it is plugged into, by the port ID the switch sends in LLDP.
    pub switch_port: Option<String>,
}

/// A Node, with its network interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeView {
    /// Its `id`.
    pub id: Option<String>,
    /// Its `label`.
    pub label: String,
    /// Its interfaces; empty where it lists none.
    pub interfaces: Vec<InterfaceView>,
}

/// One channel of an IS-08 Output, and what is routed to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelRoute {
    /// The Input routed to it; `None` for silence.
    pub input: Option<String>,
    /// The channel of that Input, counting from 0.
    pub channel_index: Option<u64>,
}

/// An IS-08 Output and what each of its channels takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputMap {
    /// The Output's identifier.
    pub id: String,
    /// Its name, from its `properties`.
    pub name: Option<String>,
    /// Each channel, in order.
    pub channels: Vec<ChannelRoute>,
}

/// A Device's IS-08 active channel map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelMapView {
    /// The Device's `id`.
    pub device_id: String,
    /// The Device's `label`.
    pub device: String,
    /// Each Output, in identifier order.
    pub outputs: Vec<OutputMap>,
}

/// What the IS-09 System API gives the system.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SystemView {
    /// Its `/global` URL.
    pub url: String,
    /// The PTP domain every Node is to use.
    pub ptp_domain: Option<u64>,
    /// Announce intervals before a PTP timeout.
    pub announce_receipt_timeout: Option<u64>,
    /// Seconds between each Node's IS-04 heartbeats.
    pub heartbeat_interval: Option<u64>,
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
    /// Every Node, in label order, with its interfaces.
    pub nodes: Vec<NodeView>,
    /// Each IS-08 channel map read, in Device label order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub channel_maps: Vec<ChannelMapView>,
    /// What the IS-09 System API gives, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemView>,
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
