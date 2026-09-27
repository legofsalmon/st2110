//! Typed views of IS-04 resources, read tolerantly from the registry's JSON.
//!
//! A registry may hold resources registered at any IS-04 version from v1.0, so only
//! the attributes every version requires are treated as required. Anything present
//! but of the wrong type is noted as a problem and otherwise ignored.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value};
use st2110_sdp::Rational;

use crate::Snapshot;

/// The six IS-04 resource types, in registration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A Node: a host that runs the Node API.
    Node,
    /// A Device: a logical group of Sources, Flows, Senders and Receivers.
    Device,
    /// A Source: the origin of one or more Flows.
    Source,
    /// A Flow: one encoding of a Source.
    Flow,
    /// A Sender: puts a Flow on the network.
    Sender,
    /// A Receiver: takes a stream from the network.
    Receiver,
}

impl Kind {
    /// Every type, in registration order.
    pub const ALL: [Self; 6] = [Self::Node, Self::Device, Self::Source, Self::Flow, Self::Sender, Self::Receiver];

    /// The lowercase name, such as `sender`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Device => "device",
            Self::Source => "source",
            Self::Flow => "flow",
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }

    /// The Query API path segment, such as `senders`.
    pub fn plural(self) -> &'static str {
        match self {
            Self::Node => "nodes",
            Self::Device => "devices",
            Self::Source => "sources",
            Self::Flow => "flows",
            Self::Sender => "senders",
            Self::Receiver => "receivers",
        }
    }
}

/// Reads attributes from one JSON object, noting each that is present but malformed.
pub(crate) struct Fields<'a> {
    map: Option<&'a Map<String, Value>>,
    path: String,
    pub problems: Vec<String>,
}

impl<'a> Fields<'a> {
    pub fn new(value: &'a Value) -> Self {
        let mut fields = Self { map: value.as_object(), path: String::new(), problems: Vec::new() };
        if fields.map.is_none() {
            fields.problems.push("it is not a JSON object".into());
        }
        fields
    }

    fn name(&self, key: &str) -> String {
        format!("`{}{key}`", self.path)
    }

    fn value(&self, key: &str) -> Option<&'a Value> {
        self.map?.get(key)
    }

    fn wrong(&mut self, key: &str, expected: &str) {
        let problem = format!("{} is not {expected}", self.name(key));
        self.problems.push(problem);
    }

    /// Notes a required attribute that is absent. Says nothing when the resource is
    /// not an object at all, which is already noted.
    fn require(&mut self, key: &str) -> bool {
        if self.map.is_some() && self.value(key).is_none() {
            let problem = format!("{} is missing", self.name(key));
            self.problems.push(problem);
            return false;
        }
        true
    }

    pub fn str(&mut self, key: &str) -> Option<&'a str> {
        match self.value(key)? {
            Value::String(s) => Some(s),
            _ => {
                self.wrong(key, "a string");
                None
            }
        }
    }

    pub fn required_str(&mut self, key: &str) -> Option<&'a str> {
        if self.require(key) { self.str(key) } else { None }
    }

    /// A string that may also be `null`.
    pub fn nullable_str(&mut self, key: &str) -> Option<&'a str> {
        match self.value(key)? {
            Value::Null => None,
            Value::String(s) => Some(s),
            _ => {
                self.wrong(key, "a string or null");
                None
            }
        }
    }

    pub fn required_nullable_str(&mut self, key: &str) -> Option<&'a str> {
        if self.require(key) { self.nullable_str(key) } else { None }
    }

    pub fn uint(&mut self, key: &str) -> Option<u64> {
        let value = self.value(key)?;
        let n = value.as_u64();
        if n.is_none() {
            self.wrong(key, "a whole number");
        }
        n
    }

    pub fn bool(&mut self, key: &str) -> Option<bool> {
        let value = self.value(key)?;
        let b = value.as_bool();
        if b.is_none() {
            self.wrong(key, "true or false");
        }
        b
    }

    /// An IS-04 rational, `{"numerator": n, "denominator": d}`, where the denominator
    /// defaults to 1. A zero or negative value reads as absent: the schemas allow it,
    /// but it is no rate.
    pub fn rational(&mut self, key: &str) -> Option<Rational> {
        let value = self.value(key)?;
        let parts = value.as_object().and_then(|o| {
            let num = o.get("numerator")?.as_i64()?;
            let den = match o.get("denominator") {
                None => 1,
                Some(d) => d.as_i64()?,
            };
            Some((num, den))
        });
        let Some((num, den)) = parts else {
            self.wrong(key, "a rational, {\"numerator\": n, \"denominator\": d}");
            return None;
        };
        Rational::new(u64::try_from(num).ok()?, u64::try_from(den).ok()?)
    }

    /// An array; empty when absent or malformed.
    pub fn array(&mut self, key: &str) -> &'a [Value] {
        match self.value(key) {
            None => &[],
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.wrong(key, "an array");
                &[]
            }
        }
    }

    /// An array of strings, or `None` when absent.
    pub fn strings(&mut self, key: &str) -> Option<Vec<&'a str>> {
        self.value(key)?;
        let items = self.array(key);
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item.as_str() {
                Some(s) => out.push(s),
                None => self.wrong(&format!("{key}[{i}]"), "a string"),
            }
        }
        Some(out)
    }

    /// Reads a nested object with `read`, keeping its problems.
    pub fn object<R>(&mut self, key: &str, read: impl FnOnce(&mut Fields<'a>) -> R) -> Option<R> {
        let value = self.value(key)?;
        let Some(map) = value.as_object() else {
            self.wrong(key, "an object");
            return None;
        };
        let mut nested = Fields { map: Some(map), path: format!("{}{key}.", self.path), problems: Vec::new() };
        let result = read(&mut nested);
        self.problems.append(&mut nested.problems);
        Some(result)
    }

    /// Reads each object in an array with `read`; `None` when the array is absent.
    pub fn objects<R>(&mut self, key: &str, mut read: impl FnMut(&mut Fields<'a>) -> R) -> Option<Vec<R>> {
        self.value(key)?;
        let items = self.array(key);
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let Some(map) = item.as_object() else {
                self.wrong(&format!("{key}[{i}]"), "an object");
                continue;
            };
            let mut nested = Fields { map: Some(map), path: format!("{}{key}[{i}].", self.path), problems: Vec::new() };
            out.push(read(&mut nested));
            self.problems.append(&mut nested.problems);
        }
        Some(out)
    }
}

/// What every resource has.
#[derive(Debug)]
pub(crate) struct Core<'a> {
    pub kind: Kind,
    /// Position in the snapshot's list of this type.
    pub index: usize,
    pub id: Option<&'a str>,
    pub version: Option<&'a str>,
    pub label: &'a str,
}

impl<'a> Core<'a> {
    fn read(kind: Kind, index: usize, f: &mut Fields<'a>) -> Self {
        Self {
            kind,
            index,
            id: f.required_str("id"),
            version: f.required_str("version"),
            label: f.required_str("label").unwrap_or_default(),
        }
    }
}

/// A clock a Node reports.
#[derive(Debug)]
pub(crate) struct Clock<'a> {
    pub name: &'a str,
    /// `internal` or `ptp`.
    pub ref_type: &'a str,
    pub gmid: Option<&'a str>,
    pub locked: Option<bool>,
    /// Whether the clock is traceable to TAI.
    pub traceable: Option<bool>,
}

impl Clock<'_> {
    pub fn is_ptp(&self) -> bool {
        self.ref_type == "ptp"
    }
}

#[derive(Debug)]
pub(crate) struct Node<'a> {
    pub core: Core<'a>,
    /// `None` for a Node from before IS-04 v1.1, which had no clocks.
    pub clocks: Option<Vec<Clock<'a>>>,
    /// Interface names; `None` for a Node from before IS-04 v1.2.
    pub interfaces: Option<Vec<&'a str>>,
}

#[derive(Debug)]
pub(crate) struct Device<'a> {
    pub core: Core<'a>,
    pub node_id: Option<&'a str>,
}

#[derive(Debug)]
pub(crate) struct Source<'a> {
    pub core: Core<'a>,
    pub device_id: Option<&'a str>,
    pub format: Option<&'a str>,
    pub clock_name: Option<&'a str>,
    pub grain_rate: Option<Rational>,
    /// Number of audio channels.
    pub channels: Option<usize>,
}

/// One component of a video Flow, such as `Y` or `Cb`.
#[derive(Debug)]
pub(crate) struct Component<'a> {
    pub name: &'a str,
    pub width: Option<u64>,
    pub height: Option<u64>,
    pub bit_depth: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct Flow<'a> {
    pub core: Core<'a>,
    pub device_id: Option<&'a str>,
    pub source_id: Option<&'a str>,
    pub format: Option<&'a str>,
    pub media_type: Option<&'a str>,
    pub grain_rate: Option<Rational>,
    pub frame_width: Option<u64>,
    pub frame_height: Option<u64>,
    pub interlace_mode: Option<&'a str>,
    pub colorspace: Option<&'a str>,
    pub transfer_characteristic: Option<&'a str>,
    pub components: Vec<Component<'a>>,
    pub sample_rate: Option<Rational>,
    pub bit_depth: Option<u64>,
    pub bit_rate: Option<u64>,
    pub profile: Option<&'a str>,
    pub level: Option<&'a str>,
    pub sublevel: Option<&'a str>,
}

/// A Sender's or Receiver's connection state.
#[derive(Debug)]
pub(crate) struct Subscription<'a> {
    /// `None` before IS-04 v1.2.
    pub active: Option<bool>,
    /// The Receiver a Sender sends to, or the Sender a Receiver takes from.
    pub peer: Option<&'a str>,
}

#[derive(Debug)]
pub(crate) struct Sender<'a> {
    pub core: Core<'a>,
    pub device_id: Option<&'a str>,
    pub flow_id: Option<&'a str>,
    pub transport: Option<&'a str>,
    pub manifest_href: Option<&'a str>,
    /// `None` before IS-04 v1.2.
    pub interface_bindings: Option<Vec<&'a str>>,
    pub subscription: Option<Subscription<'a>>,
    pub bit_rate: Option<u64>,
    pub st2110_21_sender_type: Option<&'a str>,
    pub packet_transmission_mode: Option<&'a str>,
    pub hkep: Option<bool>,
    pub privacy: Option<bool>,
}

impl Sender<'_> {
    pub fn active(&self) -> Option<bool> {
        self.subscription.as_ref()?.active
    }
}

#[derive(Debug)]
pub(crate) struct Receiver<'a> {
    pub core: Core<'a>,
    pub device_id: Option<&'a str>,
    pub format: Option<&'a str>,
    pub transport: Option<&'a str>,
    pub interface_bindings: Option<Vec<&'a str>>,
    pub subscription: Option<Subscription<'a>>,
    pub media_types: Option<Vec<&'a str>>,
    /// BCP-004-01 constraint sets, kept as JSON for [`crate::caps`].
    pub constraint_sets: Option<&'a [Value]>,
}

impl Receiver<'_> {
    /// True when the Receiver is taking a stream. A Receiver from before IS-04 v1.2
    /// has no `active` flag, so a Sender in its subscription counts as active.
    pub fn active(&self) -> bool {
        self.subscription.as_ref().is_some_and(|s| s.active.unwrap_or(s.peer.is_some()))
    }

    pub fn sender_id(&self) -> Option<&str> {
        self.subscription.as_ref()?.peer
    }
}

fn subscription<'a>(f: &mut Fields<'a>, peer: &str) -> Option<Subscription<'a>> {
    f.object("subscription", |s| Subscription { active: s.bool("active"), peer: s.nullable_str(peer) })
}

/// Every resource in a snapshot, with the problems found reading each.
#[derive(Default)]
pub(crate) struct Model<'a> {
    pub nodes: Vec<Node<'a>>,
    pub devices: Vec<Device<'a>>,
    pub sources: Vec<Source<'a>>,
    pub flows: Vec<Flow<'a>>,
    pub senders: Vec<Sender<'a>>,
    pub receivers: Vec<Receiver<'a>>,
    /// Problems per resource: kind, index and what is wrong.
    pub problems: Vec<(Kind, usize, Vec<String>)>,
    ids: HashMap<(Kind, &'a str), usize>,
}

impl<'a> Model<'a> {
    pub fn read(snapshot: &'a Snapshot) -> Self {
        let mut model = Self::default();
        for (index, value) in snapshot.nodes.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Node, index, &mut f);
            f.require("href");
            let clocks = f.objects("clocks", |c| {
                let ref_type = c.required_str("ref_type").unwrap_or_default();
                let gmid = c.str("gmid");
                if let Some(gmid) = gmid
                    && !is_gmid(gmid)
                {
                    c.wrong("gmid", "a lowercase clock identity, such as 08-00-11-ff-fe-21-e1-b0");
                }
                Clock {
                    name: c.required_str("name").unwrap_or_default(),
                    ref_type,
                    gmid,
                    locked: c.bool("locked"),
                    traceable: c.bool("traceable"),
                }
            });
            let interfaces = f.objects("interfaces", |i| i.required_str("name").unwrap_or_default());
            model.add_problems(Kind::Node, index, f);
            model.nodes.push(Node { core, clocks, interfaces });
        }
        for (index, value) in snapshot.devices.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Device, index, &mut f);
            f.required_str("type");
            let node_id = f.required_str("node_id");
            model.add_problems(Kind::Device, index, f);
            model.devices.push(Device { core, node_id });
        }
        for (index, value) in snapshot.sources.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Source, index, &mut f);
            let source = Source {
                core,
                device_id: f.required_str("device_id"),
                format: f.required_str("format"),
                clock_name: f.nullable_str("clock_name"),
                grain_rate: f.rational("grain_rate"),
                channels: f.objects("channels", |_| ()).map(|c| c.len()),
            };
            f.array("parents");
            model.add_problems(Kind::Source, index, f);
            model.sources.push(source);
        }
        for (index, value) in snapshot.flows.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Flow, index, &mut f);
            let flow = Flow {
                core,
                device_id: f.str("device_id"),
                source_id: f.required_str("source_id"),
                format: f.required_str("format"),
                media_type: f.str("media_type"),
                grain_rate: f.rational("grain_rate"),
                frame_width: f.uint("frame_width"),
                frame_height: f.uint("frame_height"),
                interlace_mode: f.str("interlace_mode"),
                colorspace: f.str("colorspace"),
                transfer_characteristic: f.str("transfer_characteristic"),
                components: f
                    .objects("components", |c| Component {
                        name: c.required_str("name").unwrap_or_default(),
                        width: c.uint("width"),
                        height: c.uint("height"),
                        bit_depth: c.uint("bit_depth"),
                    })
                    .unwrap_or_default(),
                sample_rate: f.rational("sample_rate"),
                bit_depth: f.uint("bit_depth"),
                bit_rate: f.uint("bit_rate"),
                profile: f.str("profile"),
                level: f.str("level"),
                sublevel: f.str("sublevel"),
            };
            f.array("parents");
            // IS-04 v1.1 added media_type, and with it these attributes.
            if flow.media_type.is_some() {
                match flow.format.map(short_urn) {
                    Some("video") => {
                        for key in ["frame_width", "frame_height", "colorspace"] {
                            f.require(key);
                        }
                    }
                    Some("audio") => {
                        f.require("sample_rate");
                    }
                    _ => {}
                }
            }
            model.add_problems(Kind::Flow, index, f);
            model.flows.push(flow);
        }
        for (index, value) in snapshot.senders.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Sender, index, &mut f);
            let sender = Sender {
                core,
                device_id: f.required_str("device_id"),
                flow_id: f.required_nullable_str("flow_id"),
                transport: f.required_str("transport"),
                manifest_href: f.required_nullable_str("manifest_href"),
                interface_bindings: f.strings("interface_bindings"),
                subscription: subscription(&mut f, "receiver_id"),
                bit_rate: f.uint("bit_rate"),
                st2110_21_sender_type: f.str("st2110_21_sender_type"),
                packet_transmission_mode: f.str("packet_transmission_mode"),
                hkep: f.bool("hkep"),
                privacy: f.bool("privacy"),
            };
            model.add_problems(Kind::Sender, index, f);
            model.senders.push(sender);
        }
        for (index, value) in snapshot.receivers.iter().enumerate() {
            let mut f = Fields::new(value);
            let core = Core::read(Kind::Receiver, index, &mut f);
            let device_id = f.required_str("device_id");
            let format = f.required_str("format");
            let transport = f.required_str("transport");
            let interface_bindings = f.strings("interface_bindings");
            f.require("subscription");
            let subscription = subscription(&mut f, "sender_id");
            let (media_types, constraint_sets) = f
                .object("caps", |c| {
                    let media_types = c.strings("media_types");
                    let sets = c.value("constraint_sets").map(|_| c.array("constraint_sets"));
                    (media_types, sets)
                })
                .unwrap_or_default();
            model.add_problems(Kind::Receiver, index, f);
            model.receivers.push(Receiver {
                core,
                device_id,
                format,
                transport,
                interface_bindings,
                subscription,
                media_types,
                constraint_sets,
            });
        }
        model.index();
        model
    }

    fn add_problems(&mut self, kind: Kind, index: usize, fields: Fields<'_>) {
        if !fields.problems.is_empty() {
            self.problems.push((kind, index, fields.problems));
        }
    }

    /// Indexes resources by id. The first of two resources with one id wins.
    fn index(&mut self) {
        let mut ids = HashMap::new();
        for core in self.cores() {
            if let Some(id) = core.id {
                ids.entry((core.kind, id)).or_insert(core.index);
            }
        }
        self.ids = ids;
    }

    /// Every resource, in registration order.
    pub fn cores(&self) -> impl Iterator<Item = &Core<'a>> {
        self.nodes
            .iter()
            .map(|r| &r.core)
            .chain(self.devices.iter().map(|r| &r.core))
            .chain(self.sources.iter().map(|r| &r.core))
            .chain(self.flows.iter().map(|r| &r.core))
            .chain(self.senders.iter().map(|r| &r.core))
            .chain(self.receivers.iter().map(|r| &r.core))
    }

    pub fn core(&self, kind: Kind, index: usize) -> &Core<'a> {
        match kind {
            Kind::Node => &self.nodes[index].core,
            Kind::Device => &self.devices[index].core,
            Kind::Source => &self.sources[index].core,
            Kind::Flow => &self.flows[index].core,
            Kind::Sender => &self.senders[index].core,
            Kind::Receiver => &self.receivers[index].core,
        }
    }

    /// Where the first resource with this kind and id is in its list.
    pub fn position(&self, kind: Kind, id: &str) -> Option<usize> {
        self.ids.get(&(kind, id)).copied()
    }

    pub fn node(&self, id: &str) -> Option<&Node<'a>> {
        self.position(Kind::Node, id).map(|i| &self.nodes[i])
    }

    pub fn device(&self, id: &str) -> Option<&Device<'a>> {
        self.position(Kind::Device, id).map(|i| &self.devices[i])
    }

    pub fn source(&self, id: &str) -> Option<&Source<'a>> {
        self.position(Kind::Source, id).map(|i| &self.sources[i])
    }

    pub fn flow(&self, id: &str) -> Option<&Flow<'a>> {
        self.position(Kind::Flow, id).map(|i| &self.flows[i])
    }

    pub fn sender(&self, id: &str) -> Option<&Sender<'a>> {
        self.position(Kind::Sender, id).map(|i| &self.senders[i])
    }

    pub fn receiver(&self, id: &str) -> Option<&Receiver<'a>> {
        self.position(Kind::Receiver, id).map(|i| &self.receivers[i])
    }

    /// The first resource registered with this kind and id.
    pub fn first(&self, kind: Kind, id: &str) -> Option<&Core<'a>> {
        self.position(kind, id).map(|index| self.core(kind, index))
    }

    /// The Node a Device belongs to.
    pub fn node_of(&self, device_id: Option<&str>) -> Option<&Node<'a>> {
        self.node(self.device(device_id?)?.node_id?)
    }

    /// A Sender's Flow and that Flow's Source.
    pub fn flow_of(&self, sender: &Sender<'_>) -> (Option<&Flow<'a>>, Option<&Source<'a>>) {
        let flow = sender.flow_id.and_then(|id| self.flow(id));
        let source = flow.and_then(|f| f.source_id).and_then(|id| self.source(id));
        (flow, source)
    }
}

/// The last part of an NMOS URN: `video` for `urn:x-nmos:format:video`.
pub(crate) fn short_urn(urn: &str) -> &str {
    urn.rsplit(':').next().unwrap_or(urn)
}

/// True for a clock identity as IS-04 writes it: eight lowercase hex pairs.
fn is_gmid(text: &str) -> bool {
    text.len() == 23
        && text.split('-').count() == 8
        && text.split('-').all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// True for a UUID as IS-04 writes it.
pub(crate) fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    let lower_hex = |g: &str| g.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    groups.len() == 5
        && groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|g| lower_hex(g))
        && matches!(groups[2].as_bytes()[0], b'1'..=b'5')
        && matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn uuids() {
        assert!(is_uuid("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
        assert!(!is_uuid("F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6"));
        assert!(!is_uuid("f81d4fae-7dec-01d0-a765-00a0c91e6bf6"), "version nibble 0");
        assert!(!is_uuid("f81d4fae-7dec-11d0-c765-00a0c91e6bf6"), "variant c");
        assert!(!is_uuid("f81d4fae7dec11d0a76500a0c91e6bf6"));
    }

    #[test]
    fn fields_note_what_is_malformed() {
        let value = json!({
            "id": "x", "version": "1:0", "label": 7,
            "subscription": {"active": "yes", "receiver_id": null},
            "interface_bindings": ["eth0", 1],
            "grain_rate": {"numerator": 50},
        });
        let mut f = Fields::new(&value);
        assert_eq!(f.required_str("label"), None);
        assert_eq!(f.required_str("transport"), None);
        let sub = subscription(&mut f, "receiver_id").expect("present");
        assert_eq!((sub.active, sub.peer), (None, None));
        assert_eq!(f.strings("interface_bindings"), Some(vec!["eth0"]));
        assert_eq!(f.rational("grain_rate"), Rational::new(50, 1));
        assert_eq!(
            f.problems,
            [
                "`label` is not a string",
                "`transport` is missing",
                "`subscription.active` is not true or false",
                "`interface_bindings[1]` is not a string",
            ]
        );
        let not_object = json!([1]);
        assert_eq!(Fields::new(&not_object).problems, ["it is not a JSON object"]);
    }
}
