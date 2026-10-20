//! A demo facility for `st2110 router --demo`: an IS-04 Query API and the IS-05
//! Connection API of each Node, served alongside the router page, so the router can be
//! tried with no equipment. Its Receivers stage, schedule and activate as IS-05 v1.2
//! describes ([`crate::node::connection`]), and the registry hears of each activation,
//! as a Node tells its registry.
//!
//! Four cameras send video on an ST 2022-7 pair and stereo tone; a graphics machine
//! sends a smaller picture on one leg. Three monitors take the cameras' video on two legs
//! and audio, and a fourth takes only the graphics machine's size, so some crosspoints
//! cannot be made. A PTZ camera sends unicast, to one Receiver at a time, and only
//! Monitor 3's video, which takes unicast as well as multicast, can take it.
//!
//! Its Senders can be turned on and off and sent elsewhere through their Connection
//! APIs too, and their `/transportfile` follows what each sends.
//!
//! The streams are real: [`super::signal::start`] sends each Sender's from this
//! machine, on the loopback interface, so the router can show them. They are small
//! pictures at 25 frames a second, so that a laptop carries them all with ease. A
//! Sender's stream stops while it is off, and follows it to another group; the PTZ
//! camera's unicast stream is not sent, since no Receiver's address is this machine's.
//!
//! Its Query API takes subscriptions, and pushes each change to them over a WebSocket,
//! as a registry does. Its Registration API takes other Nodes, such as `st2110 send
//! --nmos`, and forgets one 12 seconds after its last heartbeat. With `--demo-auth` it asks for IS-10 tokens too, and serves the
//! Authorization Server to get them from, whose tokens last a minute: to [`CLIENT_ID`]
//! with [`CLIENT_SECRET`], and to any client that registers by RFC 7591 with the initial
//! access token [`INITIAL_TOKEN`], for a secret or for `private_key_jwt`, as the router
//! itself does. Its tokens are opaque strings it keeps a list of, where a real
//! Authorization Server issues signed JWTs for each Resource Server to check for itself.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::format::{AudioFormat, VideoFormat};
use st2110_ptp::PtpTime;
use st2110_sdp::Rational;

use st2110_nmos::auth;

use super::signal::Live;
use crate::http::{Request, Response};
use crate::node::connection::{self, Control, Endpoint, Side, error, tai};
use crate::timing::now;

const VIDEO: &str = "urn:x-nmos:format:video";
const AUDIO: &str = "urn:x-nmos:format:audio";
const MCAST: &str = "urn:x-nmos:transport:rtp.mcast";
const UCAST: &str = "urn:x-nmos:transport:rtp.ucast";
/// RTP of either kind: a Receiver that joins a group or takes a stream sent to it.
const RTP: &str = "urn:x-nmos:transport:rtp";
const GMID: &str = "08-00-11-FF-FE-21-E1-B0";
/// The chassis of the leaf switch on each network: red for each Node's first
/// interface, blue for its second.
const LEAVES: [&str; 2] = ["c8-00-84-ee-00-0a", "c8-00-84-ee-00-0b"];

/// A demo resource id: `prefix` names the type and `n` the resource.
fn id(prefix: &str, n: u32) -> String {
    format!("{prefix}{n:04x}-0000-4000-8000-{n:012x}")
}

/// What every IS-04 resource has.
fn core(id: &str, label: &str) -> Value {
    json!({"id": id, "version": "1790510437:0", "label": label, "description": label, "tags": {}})
}

/// A Sender's or Receiver's BCP-002-01 natural group and its role there.
fn grouphint(group: &str, role: &str) -> Value {
    json!({"tags": {st2110_nmos::groups::GROUPHINT: [format!("{group}:{role}")]}})
}

/// A Node's or Device's BCP-002-02 asset tags: what the box is and which one, and
/// for a Device, what it does.
fn asset(label: &str, n: u32, device: bool) -> Value {
    let function = label.split(' ').next().unwrap_or(label);
    let mut tags = json!({
        "urn:x-nmos:tag:asset:manufacturer/v1.0": ["st2110 demo"],
        "urn:x-nmos:tag:asset:product/v1.0": [format!("Demo {function}")],
        "urn:x-nmos:tag:asset:instance-id/v1.0": [format!("DEMO-{n:04}")],
    });
    if device {
        tags["urn:x-nmos:tag:asset:function/v1.0"] = json!([function]);
    }
    json!({"tags": tags})
}

fn merge(mut base: Value, more: Value) -> Value {
    if let (Some(base), Value::Object(more)) = (base.as_object_mut(), more) {
        base.extend(more);
    }
    base
}

/// A Sender's IS-05 resources, as it sends `legs`: each leg from this machine to a
/// group or address and port.
fn sender_resources(legs: &[Leg], enabled: bool) -> Endpoint {
    let constraints: Vec<Value> = legs
        .iter()
        .map(|_| {
            json!({"source_ip": {"enum": ["auto", LOOPBACK.to_string()]}, "destination_ip": {}, "source_port": {"enum": [5004]},
                   "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}})
        })
        .collect();
    let params: Vec<Value> = legs
        .iter()
        .map(|leg| {
            json!({"source_ip": LOOPBACK.to_string(), "destination_ip": leg.destination.ip().to_string(),
                   "source_port": 5004, "destination_port": leg.destination.port(), "rtp_enabled": true})
        })
        .collect();
    Endpoint::sender(constraints, params, enabled)
}

fn constraints(interfaces: &[String]) -> Vec<Value> {
    interfaces
        .iter()
        .map(|i| {
            json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["auto", i]},
                   "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}})
        })
        .collect()
}

/// The demo Authorization Server's one client.
pub(crate) const CLIENT_ID: &str = "st2110-demo";

/// Its secret: this is a demo, on this machine.
pub(crate) const CLIENT_SECRET: &str = "demo-secret";

/// The initial access token the demo Authorization Server asks for to register a client
/// (RFC 7591 §3), as IS-10 has a server authenticate registrations for the Client
/// Credentials grant.
pub(crate) const INITIAL_TOKEN: &str = "demo-registration";

/// Where the demo Authorization Server registers clients.
const REGISTER_PATH: &str = "/x-nmos/auth/v1.0/register";

/// A client registered with the demo Authorization Server, and how it authenticates.
enum Client {
    Secret(String),
    /// `private_key_jwt`, with the keys at its `jwks_uri`.
    Key(String),
}

/// The scopes the demo Authorization Server issues tokens for.
const SCOPES: [&str; 3] = ["query", "connection", "registration"];

/// How long a demo token lasts, short enough to see one renewed.
const TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// Where the demo Authorization Server hands out tokens.
const TOKEN_PATH: &str = "/x-nmos/auth/v1.0/token";

/// Where its metadata is (RFC 8414).
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// How long a Node registered through the Registration API is kept without a
/// heartbeat: the 12 seconds IS-04 suggests.
const EXPIRY: Duration = Duration::from_secs(12);

/// Where the Query API's subscriptions are heard.
pub(crate) const WS_PATH: &str = "/x-nmos/query/v1.3/ws/";

/// A token the demo Authorization Server issued.
struct Issued {
    scopes: Vec<String>,
    expires: Instant,
}

/// The registry, and every Node's Connection API.
pub(crate) struct Facility {
    /// Where it is served, such as `http://127.0.0.1:8110`.
    base: String,
    tai_utc: i32,
    /// The registry's resources, by type: `nodes`, `devices` and so on.
    registry: BTreeMap<&'static str, Vec<Value>>,
    receivers: BTreeMap<String, Endpoint>,
    senders: BTreeMap<String, Endpoint>,
    /// What each Sender's `/transportfile` serves, keyed by Sender `id`.
    sdp: BTreeMap<String, String>,
    /// Each Sender's stream, keyed by Sender `id`: its label and description, as it was
    /// made, and what it is told to send now.
    streams: BTreeMap<String, (String, Description, Arc<Live>)>,
    /// How many times the Senders' SDP files have changed, for their `o=` versions.
    edits: u64,
    /// The Query API's subscriptions, by `id`.
    subscriptions: BTreeMap<String, Value>,
    /// Changes to the registry not yet pushed to subscriptions: the resource type, and
    /// the resource before and after.
    changes: Vec<(&'static str, Value, Value)>,
    /// The tokens issued, with `--demo-auth`.
    tokens: Option<HashMap<String, Issued>>,
    /// The clients registered with the Authorization Server, by id.
    clients: HashMap<String, Client>,
    /// The `jti` of each client assertion taken, so that none is taken twice.
    assertions: HashSet<String>,
    /// Whether a Receiver changed since the facility was last kept.
    dirty: bool,
    /// The Nodes registered through the Registration API, by `id`, and when each was
    /// last heard from.
    heard: HashMap<String, Instant>,
}

/// A Sender to build: its label, Flow facts and SDP file.
struct Sending {
    label: String,
    description: Description,
    /// The transport, multicast or unicast.
    transport: &'static str,
    /// Whether it is sending to start with.
    enabled: bool,
}

/// Where the demo's streams go from: this machine's loopback interface.
const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The cameras' picture, and the graphics machine's.
const CAMERA: (u32, u32) = (480, 270);
const GRAPHICS: (u32, u32) = (320, 180);

/// A stream from this machine to `groups`, each `(group, port)`.
fn description(name: &str, media: Media, groups: &[(&str, u16)]) -> Description {
    let payload_type = if matches!(media, Media::Video(_)) { 96 } else { 97 };
    Description {
        name: name.to_string(),
        media,
        payload_type,
        legs: groups
            .iter()
            .map(|(group, port)| Leg {
                destination: SocketAddrV4::new(group.parse().expect("a demo group"), *port),
                source: Some(LOOPBACK),
            })
            .collect(),
        clock: Clock::parse(&format!("{GMID}:127")).ok(),
        ttl: 1,
        rtp_offset: 0,
    }
}

fn video(width: u32, height: u32) -> Media {
    Media::Video(VideoFormat::new(width, height, Rational::new(25, 1).expect("25")))
}

impl Facility {
    /// The facility, with URLs on `base`, such as `http://127.0.0.1:8110`, and two
    /// monitors already taking cameras.
    pub(crate) fn new(base: &str, tai_utc: i32) -> Self {
        let mut facility = Self {
            base: base.to_string(),
            tai_utc,
            registry: BTreeMap::new(),
            receivers: BTreeMap::new(),
            senders: BTreeMap::new(),
            sdp: BTreeMap::new(),
            streams: BTreeMap::new(),
            edits: 0,
            subscriptions: BTreeMap::new(),
            changes: Vec::new(),
            tokens: None,
            clients: HashMap::from([(CLIENT_ID.to_string(), Client::Secret(CLIENT_SECRET.to_string()))]),
            assertions: HashSet::new(),
            dirty: false,
            heard: HashMap::new(),
        };
        for kind in ["nodes", "devices", "sources", "flows", "senders", "receivers"] {
            facility.registry.insert(kind, Vec::new());
        }
        let mut node = 0;
        for camera in 1..=4u32 {
            node += 1;
            let red = format!("192.168.10.2{camera}");
            let blue = format!("192.168.20.2{camera}");
            let label = format!("CAM {camera} video");
            let groups = [format!("239.10.{camera}.1"), format!("239.20.{camera}.1")];
            let video = Sending {
                description: description(&label, video(CAMERA.0, CAMERA.1), &[(&groups[0], 5004), (&groups[1], 5004)]),
                label,
                transport: MCAST,
                enabled: true,
            };
            let label = format!("CAM {camera} audio");
            let audio = Sending {
                description: description(
                    &label,
                    Media::Audio(AudioFormat::new(2)),
                    &[(&format!("239.10.{camera}.2"), 5006)],
                ),
                label,
                transport: MCAST,
                enabled: true,
            };
            facility.add_sender_node(base, node, &format!("Camera {camera}"), &[&red, &blue], &[video, audio]);
        }
        node += 1;
        let graphics = Sending {
            label: "GFX 1 video".into(),
            description: description("GFX 1 video", video(GRAPHICS.0, GRAPHICS.1), &[("239.10.41.1", 5004)]),
            transport: MCAST,
            enabled: true,
        };
        facility.add_sender_node(base, node, "Graphics 1", &["192.168.10.41"], &[graphics]);
        for monitor in 1..=4u32 {
            node += 1;
            let red = format!("192.168.10.3{monitor}");
            let blue = format!("192.168.20.3{monitor}");
            let video = if monitor == 4 { vec![red.clone()] } else { vec![red.clone(), blue] };
            facility.add_monitor(base, node, monitor, &video, &red);
        }
        // A PTZ camera that sends unicast, off until a Receiver is connected to it.
        node += 1;
        let ptz = Sending {
            label: "PTZ 1 video".into(),
            description: description("PTZ 1 video", video(CAMERA.0, CAMERA.1), &[("192.168.10.33", 5004)]),
            transport: UCAST,
            enabled: false,
        };
        facility.add_sender_node(base, node, "PTZ 1", &["192.168.10.51"], &[ptz]);
        // Monitors 1 and 2 are on cameras 1 and 2 already.
        let now = now(tai_utc).unwrap_or_else(|_| PtpTime::from_utc(0, 0).expect("the epoch"));
        for monitor in 1..=2u32 {
            for (offset, kind) in [(0, "video"), (1, "audio")] {
                let receiver = id("7ecf", monitor * 2 - 1 + offset);
                let sender = id("5e0d", monitor * 2 - 1 + offset);
                let sdp = facility.sdp[&sender].clone();
                let body = json!({
                    "sender_id": sender, "master_enable": true,
                    "transport_file": {"data": sdp, "type": "application/sdp"},
                    "transport_params": facility.legs(&receiver, &sender),
                });
                connection::stage(&mut facility, Side::Receiver, &receiver, &body);
                connection::activate(&mut facility, Side::Receiver, &receiver, now);
                debug_assert_eq!(facility.receivers[&receiver].active["sender_id"], json!(sender), "{kind}");
            }
        }
        facility.changes.clear();
        facility.dirty = false;
        facility
    }

    /// Asks for IS-10 tokens on the Query and Connection APIs, and hands them out.
    pub(crate) fn with_auth(mut self) -> Self {
        self.tokens = Some(HashMap::new());
        self
    }

    /// The Authorization Server's issuer URL, with `--demo-auth`.
    pub(crate) fn auth_server(&self) -> Option<String> {
        self.tokens.as_ref().map(|_| format!("{}/", self.base))
    }

    /// What a Receiver's legs take from an SDP file, for setting up the demo.
    fn legs(&self, receiver: &str, sender: &str) -> Value {
        let legs = &self.streams[sender].1.legs;
        let count = self.receivers[receiver].legs();
        (0..count)
            .map(|i| match legs.get(i) {
                Some(leg) => json!({
                    "multicast_ip": leg.destination.ip().to_string(),
                    "source_ip": leg.source.map(|s| s.to_string()),
                    "destination_port": leg.destination.port(),
                    "rtp_enabled": true,
                }),
                None => json!({"rtp_enabled": false}),
            })
            .collect()
    }

    fn node(&mut self, base: &str, n: u32, label: &str, interfaces: &[&str]) -> String {
        let node_id = id("a0de", n);
        let device_id = id("de71", n);
        let host = interfaces.first().copied().unwrap_or("127.0.0.1");
        let hostname = format!("{}.demo.example", label.to_ascii_lowercase().replace(' ', ""));
        let ports: Vec<Value> = interfaces
            .iter()
            .enumerate()
            .map(|(i, _)| {
                // Each interface is plugged into port n of its network's leaf switch, as
                // LLDP from that switch would say.
                json!({
                    "chassis_id": format!("c8-00-84-10-{n:02x}-00"), "port_id": format!("c8-00-84-10-{n:02x}-{:02x}", i + 1),
                    "name": format!("eth{i}"),
                    "attached_network_device": {"chassis_id": LEAVES[i % LEAVES.len()], "port_id": format!("Ethernet1/{n}")},
                })
            })
            .collect();
        self.registry.get_mut("nodes").expect("nodes").push(merge(
            merge(core(&node_id, label), asset(label, n, false)),
            json!({
                "href": format!("http://{host}/"), "hostname": hostname,
                "api": {"versions": ["v1.3"], "endpoints": [{"host": host, "port": 80, "protocol": "http"}]},
                "caps": {}, "services": [],
                "clocks": [{"name": "clk0", "ref_type": "ptp", "traceable": false, "version": "IEEE1588-2008",
                            "gmid": GMID.to_ascii_lowercase(), "locked": true}],
                "interfaces": ports,
            }),
        ));
        self.registry.get_mut("devices").expect("devices").push(merge(
            merge(core(&device_id, label), asset(label, n, true)),
            json!({
                "type": "urn:x-nmos:device:generic", "node_id": node_id, "senders": [], "receivers": [],
                "controls": [{"href": format!("{base}/node/{n}/x-nmos/connection/v1.1/"), "type": "urn:x-nmos:control:sr-ctrl/v1.1"}],
            }),
        ));
        device_id
    }

    fn add_sender_node(&mut self, base: &str, n: u32, label: &str, interfaces: &[&str], sending: &[Sending]) {
        let device_id = self.node(base, n, label, interfaces);
        for s in sending {
            let k = u32::try_from(self.registry["senders"].len()).expect("a few senders") + 1;
            let (source_id, flow_id, sender_id) = (id("50c0", k), id("f10e", k), id("5e0d", k));
            let (source, flow) = match &s.description.media {
                Media::Video(format) => {
                    let (width, height) = (format.width, format.height);
                    let rate = json!({"numerator": 25});
                    (
                        json!({"format": VIDEO, "grain_rate": rate}),
                        json!({
                            "format": VIDEO, "grain_rate": rate, "frame_width": width, "frame_height": height,
                            "interlace_mode": "progressive", "colorspace": "BT709", "transfer_characteristic": "SDR",
                            "media_type": "video/raw",
                            "components": [
                                {"name": "Y", "width": width, "height": height, "bit_depth": 10},
                                {"name": "Cb", "width": width / 2, "height": height, "bit_depth": 10},
                                {"name": "Cr", "width": width / 2, "height": height, "bit_depth": 10},
                            ],
                        }),
                    )
                }
                Media::Audio(_) => (
                    json!({"format": AUDIO, "channels": [{"label": "Left", "symbol": "L"}, {"label": "Right", "symbol": "R"}]}),
                    json!({"format": AUDIO, "sample_rate": {"numerator": 48000}, "media_type": "audio/L24", "bit_depth": 24}),
                ),
            };
            let common = json!({"device_id": device_id, "parents": []});
            self.registry.get_mut("sources").expect("sources").push(merge(
                merge(merge(core(&source_id, &s.label), json!({"caps": {}, "clock_name": "clk0"})), common.clone()),
                source,
            ));
            self.registry
                .get_mut("flows")
                .expect("flows")
                .push(merge(merge(merge(core(&flow_id, &s.label), json!({"source_id": source_id})), common), flow));
            let legs = s.description.legs.len();
            let bindings: Vec<String> = (0..legs).map(|i| format!("eth{i}")).collect();
            let mut sender = merge(
                core(&sender_id, &s.label),
                json!({
                    "caps": {}, "flow_id": flow_id, "transport": s.transport, "device_id": device_id,
                    "manifest_href": format!("{base}/node/{n}/x-nmos/connection/v1.1/single/senders/{sender_id}/transportfile"),
                    "interface_bindings": bindings, "subscription": {"receiver_id": null, "active": s.enabled},
                }),
            );
            if matches!(s.description.media, Media::Video(_)) {
                // The demo sends a millisecond's packets at a time, which only the wide
                // sender model allows; its SDP says the same.
                sender["st2110_21_sender_type"] = json!("2110TPW");
            }
            // A camera's video and audio are one natural group, as BCP-002-01 has a
            // Node say; the graphics Node says nothing, as many do not.
            if !label.starts_with("Graphics") {
                let role = if matches!(s.description.media, Media::Video(_)) { "Video" } else { "Audio 1" };
                sender = merge(sender, grouphint(label, role));
            }
            self.registry.get_mut("senders").expect("senders").push(sender);
            self.senders.insert(sender_id.clone(), sender_resources(&s.description.legs, s.enabled));
            let live = Arc::new(Live::new(None));
            self.streams.insert(sender_id.clone(), (s.label.clone(), s.description.clone(), live));
            self.send(&sender_id);
        }
    }

    fn add_monitor(&mut self, base: &str, n: u32, monitor: u32, video: &[String], audio: &str) {
        let interfaces: Vec<&str> = video.iter().map(String::as_str).collect();
        let device_id = self.node(base, n, &format!("Monitor {monitor}"), &interfaces);
        let ((width, height), label) = if monitor == 4 { (GRAPHICS, "180p") } else { (CAMERA, "270p") };
        let video_caps = json!({
            "media_types": ["video/raw"],
            "constraint_sets": [{
                "urn:x-nmos:cap:meta:label": label,
                "urn:x-nmos:cap:format:frame_width": {"enum": [width]},
                "urn:x-nmos:cap:format:frame_height": {"enum": [height]},
                "urn:x-nmos:cap:format:interlace_mode": {"enum": ["progressive"]},
                "urn:x-nmos:cap:format:grain_rate": {"enum": [{"numerator": 25}, {"numerator": 50}]},
                "urn:x-nmos:cap:format:color_sampling": {"enum": ["YCbCr-4:2:2"]},
                "urn:x-nmos:cap:format:component_depth": {"enum": [10]},
            }],
            "version": "1790510437:0",
        });
        let audio_caps = json!({
            "media_types": ["audio/L24", "audio/L16"],
            "constraint_sets": [{
                "urn:x-nmos:cap:format:channel_count": {"minimum": 1, "maximum": 16},
                "urn:x-nmos:cap:format:sample_rate": {"enum": [{"numerator": 48000}]},
                "urn:x-nmos:cap:format:sample_depth": {"enum": [16, 24]},
                "urn:x-nmos:cap:transport:packet_time": {"enum": [0.125, 1]},
            }],
            "version": "1790510437:0",
        });
        let legs = [
            (format!("MON {monitor} video"), VIDEO, video.to_vec(), video_caps),
            (format!("MON {monitor} audio"), AUDIO, vec![audio.to_string()], audio_caps),
        ];
        for (label, format, interfaces, caps) in legs {
            let k = u32::try_from(self.registry["receivers"].len()).expect("a few receivers") + 1;
            let receiver_id = id("7ecf", k);
            let bindings: Vec<String> = (0..interfaces.len()).map(|i| format!("eth{i}")).collect();
            // Monitor 3's video takes the PTZ camera's unicast too.
            let transport = if monitor == 3 && format == VIDEO { RTP } else { MCAST };
            let role = if format == VIDEO { "Video" } else { "Audio 1" };
            self.registry.get_mut("receivers").expect("receivers").push(merge(
                merge(core(&receiver_id, &label), grouphint(&format!("Monitor {monitor}"), role)),
                json!({
                    "device_id": device_id, "transport": transport, "interface_bindings": bindings,
                    "subscription": {"sender_id": null, "active": false}, "format": format, "caps": caps,
                }),
            ));
            self.receivers.insert(receiver_id, Endpoint::idle_receiver(&interfaces, constraints(&interfaces)));
        }
    }

    /// Each Sender's label, the stream it sends, and what it is told to send now, for
    /// [`super::signal::start`].
    pub(crate) fn streams(&self) -> Vec<(String, Description, Arc<Live>)> {
        self.streams.values().cloned().collect()
    }

    /// Makes a Sender's SDP file and stream follow its `/active` endpoint: where each leg
    /// goes, and whether it sends at all.
    fn send(&mut self, id: &str) {
        let (Some(resources), Some((_, made, live))) = (self.senders.get(id), self.streams.get(id)) else {
            return;
        };
        let active = &resources.active;
        let legs: Vec<Leg> = active["transport_params"]
            .as_array()
            .into_iter()
            .flatten()
            .zip(&made.legs)
            .filter(|(params, _)| params["rtp_enabled"] != false)
            .filter_map(|(params, leg)| {
                let ip = params["destination_ip"].as_str()?.parse::<Ipv4Addr>().ok()?;
                let port = params["destination_port"].as_u64().and_then(|p| u16::try_from(p).ok())?;
                Some(Leg { destination: SocketAddrV4::new(ip, port), ..*leg })
            })
            .collect();
        let sending = active["master_enable"] == true && !legs.is_empty();
        // Only multicast goes out on the loopback interface; a unicast address is not this
        // machine's.
        let streamed = legs.iter().all(|leg| leg.destination.ip().is_multicast());
        live.set((sending && streamed).then(|| legs.clone()));
        // The file says where it sends when on, and still does while it is off; with
        // every leg off it keeps the last.
        if !legs.is_empty() {
            self.edits += 1;
            let description = Description { legs, ..made.clone() };
            self.sdp.insert(id.to_string(), description.sdp(self.edits));
        }
    }

    /// Whether a request is for the facility, rather than the router.
    pub(crate) fn serves(path: &str) -> bool {
        path.starts_with("/x-nmos/") || path.starts_with("/node/") || path.starts_with(METADATA_PATH)
    }

    /// Answers a request for the registry, a Connection API or the Authorization Server.
    pub(crate) fn answer(&mut self, request: &Request) -> Response {
        self.settle();
        if request.path.starts_with(METADATA_PATH) || request.path == TOKEN_PATH || request.path == REGISTER_PATH {
            return self.authorization_server(request);
        }
        if let Err(refused) = self.authorized(request) {
            return refused;
        }
        let body: Value = if request.body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&request.body) {
                Ok(body) => body,
                Err(e) => return Response::json(400, &error(400, "Bad Request", &e.to_string()).1),
            }
        };
        let path = request.path.trim_end_matches('/');
        // `/node/<n>/x-nmos/connection/v1.1/...`: each Node's own Connection API.
        if let Some(rest) = path
            .strip_prefix("/node/")
            .and_then(|rest| rest.split_once('/'))
            .and_then(|(_, rest)| rest.strip_prefix("x-nmos/connection/v1.1"))
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        {
            return connection::route(self, &request.method, rest, &body);
        }
        match self.route(&request.method, path, &body) {
            (204, _) => {
                Response { status: 204, content_type: "application/json", headers: Vec::new(), body: Vec::new() }
            }
            (status, body) => Response::json(status, &body),
        }
    }

    /// Answers a request for the Query API or the Registration API.
    fn route(&mut self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        if let Some(rest) = path.strip_prefix("/x-nmos/query") {
            if method == "POST" && rest == "/v1.3/subscriptions" {
                return self.subscribe(body);
            }
            if method != "GET" {
                return error(405, "Method Not Allowed", "the Query API only reads, and takes subscriptions");
            }
            return self.query(rest);
        }
        if let Some(rest) = path.strip_prefix("/x-nmos/registration") {
            if method == "POST" && rest == "/v1.3/resource" {
                return self.register_resource(body);
            }
            return self.registration(method, rest);
        }
        error(404, "Not Found", path)
    }

    /// The Query API: its versions, a collection or one resource. Collections are not
    /// paged, and query parameters are ignored.
    fn query(&self, rest: &str) -> (u16, Value) {
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        match parts.as_slice() {
            [] => (200, json!(["v1.3/"])),
            ["v1.3"] => {
                (200, json!(["nodes/", "devices/", "sources/", "flows/", "senders/", "receivers/", "subscriptions/"]))
            }
            ["v1.3", "subscriptions"] => (200, Value::Array(self.subscriptions.values().cloned().collect())),
            ["v1.3", "subscriptions", id] => match self.subscriptions.get(*id) {
                Some(subscription) => (200, subscription.clone()),
                None => error(404, "Not Found", "no such subscription"),
            },
            ["v1.3", kind] => match self.registry.get(kind) {
                Some(list) => (200, Value::Array(list.clone())),
                None => error(404, "Not Found", "no such resource type"),
            },
            ["v1.3", kind, id] => match self.registry.get(kind).and_then(|l| l.iter().find(|r| r["id"] == *id)) {
                Some(resource) => (200, resource.clone()),
                None => error(404, "Not Found", "no such resource"),
            },
            _ => error(404, "Not Found", "this registry serves IS-04 v1.3"),
        }
    }

    /// Carries out the scheduled activations that are due, and forgets the Nodes that
    /// have stopped sending heartbeats.
    pub(crate) fn settle(&mut self) {
        connection::settle(self);
        let now = Instant::now();
        let gone: Vec<String> =
            self.heard.iter().filter(|(_, at)| now.duration_since(**at) > EXPIRY).map(|(id, _)| id.clone()).collect();
        for id in gone {
            self.unregister("nodes", &id);
        }
    }

    /// The Registration API, for Nodes beyond the demo's own (IS-04 v1.3 APIs:
    /// Registration API).
    fn registration(&mut self, method: &str, rest: &str) -> (u16, Value) {
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        match (method, parts.as_slice()) {
            ("GET", []) => (200, json!(["v1.3/"])),
            ("GET", ["v1.3"]) => (200, json!(["resource/", "health/"])),
            ("GET", ["v1.3", "resource", kind, id]) => {
                match self.registry.get(kind).and_then(|l| l.iter().find(|r| r["id"] == *id)) {
                    Some(resource) => (200, resource.clone()),
                    None => error(404, "Not Found", "no such resource"),
                }
            }
            ("DELETE", ["v1.3", "resource", kind, id]) => {
                if !self.registry.get(kind).is_some_and(|l| l.iter().any(|r| r["id"] == *id)) {
                    return error(404, "Not Found", "no such resource");
                }
                self.unregister(kind, id);
                (204, Value::Null)
            }
            ("GET" | "POST", ["v1.3", "health", "nodes", id]) => match self.heard.get_mut(*id) {
                Some(heard) => {
                    if method == "POST" {
                        *heard = Instant::now();
                    }
                    (200, json!({"health": self.now().seconds().to_string()}))
                }
                None => error(404, "Not Found", "no such Node: register it"),
            },
            (_, ["v1.3", "resource" | "health", ..]) => error(405, "Method Not Allowed", ""),
            _ => error(404, "Not Found", "this registry serves IS-04 v1.3"),
        }
    }

    /// `POST /resource`: registers a resource, or updates one registered before.
    fn register_resource(&mut self, body: &Value) -> (u16, Value) {
        let data = &body["data"];
        let (kind, parent) = match body["type"].as_str() {
            Some("node") => ("nodes", None),
            Some("device") => ("devices", Some(("nodes", "node_id"))),
            Some("source") => ("sources", Some(("devices", "device_id"))),
            Some("flow") => ("flows", Some(("devices", "device_id"))),
            Some("sender") => ("senders", Some(("devices", "device_id"))),
            Some("receiver") => ("receivers", Some(("devices", "device_id"))),
            _ => return error(400, "Bad Request", "type is node, device, source, flow, sender or receiver"),
        };
        let Some(id) = data["id"].as_str().map(str::to_string) else {
            return error(400, "Bad Request", "the resource has no id");
        };
        if data["version"].as_str().is_none() {
            return error(400, "Bad Request", "the resource has no version");
        }
        if let Some((parents, field)) = parent
            && !self.registry[parents].iter().any(|r| r["id"] == data[field])
        {
            return error(400, "Bad Request", &format!("its {field} names nothing registered"));
        }
        if kind == "nodes" {
            self.heard.insert(id.clone(), Instant::now());
        }
        let list = self.registry.get_mut(kind).expect("a resource type");
        match list.iter_mut().find(|r| r["id"] == id.as_str()) {
            Some(registered) => {
                let pre = std::mem::replace(registered, data.clone());
                self.changes.push((kind, pre, data.clone()));
                (200, data.clone())
            }
            None => {
                list.push(data.clone());
                self.changes.push((kind, Value::Null, data.clone()));
                (201, data.clone())
            }
        }
    }

    /// Removes a resource from the registry, with those that belong to it.
    fn unregister(&mut self, kind: &str, id: &str) {
        let Some((kind, list)) = self.registry.iter_mut().find(|(k, _)| **k == kind) else {
            return;
        };
        let kind: &'static str = kind;
        let Some(at) = list.iter().position(|r| r["id"] == id) else {
            return;
        };
        let removed = list.remove(at);
        self.changes.push((kind, removed, Value::Null));
        let children: Vec<(&'static str, String)> = match kind {
            "nodes" => {
                self.heard.remove(id);
                self.registry["devices"]
                    .iter()
                    .filter(|d| d["node_id"] == id)
                    .filter_map(|d| Some(("devices", d["id"].as_str()?.to_string())))
                    .collect()
            }
            "devices" => ["sources", "flows", "senders", "receivers"]
                .into_iter()
                .flat_map(|k| {
                    self.registry[k]
                        .iter()
                        .filter(|r| r["device_id"] == id)
                        .filter_map(move |r| Some((k, r["id"].as_str()?.to_string())))
                })
                .collect(),
            _ => Vec::new(),
        };
        for (kind, id) in children {
            self.unregister(kind, &id);
        }
    }

    /// Tells the registry what a Sender sends or a Receiver takes now, as its Node would,
    /// and has a Sender's stream follow.
    fn registered(&mut self, side: Side, id: &str, at: PtpTime) {
        let active = &self.endpoints(side)[id].active;
        let enabled = active["master_enable"] == true;
        let subscription = match side {
            // A Sender names its Receiver only while active (IS-04 v1.3 Behaviour: Nodes).
            Side::Sender => json!({
                "receiver_id": if enabled { active["receiver_id"].clone() } else { Value::Null },
                "active": enabled,
            }),
            Side::Receiver => json!({"sender_id": active["sender_id"], "active": active["master_enable"]}),
        };
        if side == Side::Sender {
            self.send(id);
        }
        self.register(side.plural(), id, subscription, at);
    }

    /// Tells the registry a resource's new subscription, as its Node would.
    fn register(&mut self, kind: &'static str, id: &str, subscription: Value, at: PtpTime) {
        if let Some(registered) = self.registry.get_mut(kind).and_then(|list| list.iter_mut().find(|r| r["id"] == id)) {
            let pre = registered.clone();
            registered["subscription"] = subscription;
            registered["version"] = json!(tai(at));
            self.changes.push((kind, pre, registered.clone()));
        }
    }

    /// Each Sender's and Receiver's staged and active parameters, to keep for the next run.
    pub(crate) fn export(&self) -> Value {
        let kept = |map: &BTreeMap<String, Endpoint>| -> serde_json::Map<String, Value> {
            map.iter().map(|(id, r)| (id.clone(), json!({"staged": r.staged, "active": r.active}))).collect()
        };
        json!({"receivers": kept(&self.receivers), "senders": kept(&self.senders)})
    }

    /// Puts back what [`Facility::export`] kept: each Receiver takes what it took, and
    /// each Sender sends where it sent. What was scheduled and not yet due is not
    /// scheduled again.
    pub(crate) fn restore(&mut self, kept: &Value) {
        let now = self.now();
        for side in [Side::Sender, Side::Receiver] {
            let ids: Vec<String> = self.endpoints(side).keys().cloned().collect();
            for id in ids {
                let Some(saved) = kept[side.plural()].get(&id) else { continue };
                let legs = self.endpoints(side)[&id].legs();
                let fits = |v: &Value| v["transport_params"].as_array().is_some_and(|p| p.len() == legs);
                if !fits(&saved["staged"]) || !fits(&saved["active"]) {
                    continue;
                }
                let resources = self.endpoints(side).get_mut(&id).expect("a known Sender or Receiver");
                resources.staged = saved["staged"].clone();
                resources.staged["activation"] = json!({"mode": null, "requested_time": null, "activation_time": null});
                resources.active = saved["active"].clone();
                resources.pending = None;
                self.registered(side, &id, now);
            }
        }
        self.changes.clear();
        self.dirty = false;
    }

    /// Whether a Sender or Receiver changed since this was last asked.
    pub(crate) fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// `POST /subscriptions`: a subscription to changes under one resource path.
    fn subscribe(&mut self, body: &Value) -> (u16, Value) {
        let path = body["resource_path"].as_str().unwrap_or_default().trim_end_matches('/');
        let kind = path.trim_start_matches('/');
        if path.is_empty() || !self.registry.contains_key(kind) {
            return error(
                400,
                "Bad Request",
                "resource_path is one of /nodes, /devices, /sources, /flows, /senders and /receivers",
            );
        }
        if body["persist"] == true {
            return error(400, "Bad Request", "the demo registry keeps no persistent subscriptions");
        }
        let authorization = self.tokens.is_some();
        // The same request has the same subscription (IS-04 Query API: Subscriptions).
        if let Some(existing) = self.subscriptions.values().find(|s| s["resource_path"] == path) {
            return (200, existing.clone());
        }
        let n = u32::try_from(self.subscriptions.len()).unwrap_or(u32::MAX) + 1;
        let id = id("5ab5", n);
        let ws_base = self.base.replacen("http://", "ws://", 1);
        let subscription = json!({
            "id": id, "ws_href": format!("{ws_base}{WS_PATH}?uid={id}"),
            "max_update_rate_ms": body["max_update_rate_ms"].as_u64().unwrap_or(100),
            "persist": false, "secure": false, "resource_path": path, "params": {},
            "authorization": authorization,
        });
        self.subscriptions.insert(id, subscription.clone());
        (201, subscription)
    }

    /// The subscription a WebSocket to `uid` hears.
    pub(crate) fn subscription(&self, uid: &str) -> Option<&Value> {
        self.subscriptions.get(uid)
    }

    /// The first message on a subscription's WebSocket: everything under its path.
    pub(crate) fn sync(&self, uid: &str) -> Option<String> {
        let subscription = self.subscriptions.get(uid)?;
        let kind = subscription["resource_path"].as_str()?.trim_start_matches('/');
        let data: Vec<Value> =
            self.registry.get(kind)?.iter().map(|r| json!({"path": r["id"], "pre": r, "post": r})).collect();
        Some(self.grain(uid, kind, data))
    }

    /// The changes since this was last asked, as messages for each subscription: its
    /// `id`, and the message.
    pub(crate) fn take_changes(&mut self) -> Vec<(String, String)> {
        let changes = std::mem::take(&mut self.changes);
        let mut out = Vec::new();
        for (uid, subscription) in &self.subscriptions {
            let kind = subscription["resource_path"].as_str().unwrap_or_default().trim_start_matches('/');
            let data: Vec<Value> = changes
                .iter()
                .filter(|(k, ..)| *k == kind)
                .map(|(_, pre, post)| {
                    let mut change = json!({"path": if post.is_null() { &pre["id"] } else { &post["id"] }});
                    // A resource added has no `pre`, and one removed no `post`.
                    for (name, resource) in [("pre", pre), ("post", post)] {
                        if !resource.is_null() {
                            change[name] = resource.clone();
                        }
                    }
                    change
                })
                .collect();
            if !data.is_empty() {
                out.push((uid.clone(), self.grain(uid, kind, data)));
            }
        }
        out
    }

    /// A Query API WebSocket message (IS-04 v1.3 APIs: Query API, WebSocket messages).
    fn grain(&self, uid: &str, kind: &str, data: Vec<Value>) -> String {
        let now = tai(self.now());
        json!({
            "grain_type": "event", "source_id": id("9e57", 1), "flow_id": uid,
            "origin_timestamp": now, "sync_timestamp": now, "creation_timestamp": now,
            "rate": {"numerator": 0, "denominator": 1}, "duration": {"numerator": 0, "denominator": 1},
            "grain": {"type": "urn:x-nmos:format:data.event", "topic": format!("/{kind}/"), "data": data},
        })
        .to_string()
    }

    /// Whether a request carries a token for what it asks, with `--demo-auth`: `Err`
    /// with the refusal when it does not (IS-10 v1.0 Behaviour: Resource Servers). A
    /// WebSocket may carry it as `access_token` in the query, as IS-10 allows.
    pub(crate) fn authorized(&mut self, request: &Request) -> Result<(), Response> {
        let Some(tokens) = &mut self.tokens else {
            return Ok(());
        };
        let scope = if request.path.starts_with("/x-nmos/query") {
            "query"
        } else if request.path.starts_with("/x-nmos/registration") {
            "registration"
        } else if request.path.starts_with("/node/") {
            "connection"
        } else {
            return Ok(());
        };
        let now = Instant::now();
        tokens.retain(|_, issued| issued.expires > now);
        let from_query = request.path.starts_with(WS_PATH).then(|| request.param("access_token")).flatten();
        let token = request.header("Authorization").and_then(auth::bearer_token).map(str::to_string).or(from_query);
        let refuse = |status: u16, error: &str, why: &str| {
            let mut response = Response::error(status, why);
            response.headers.push((
                "WWW-Authenticate",
                format!("Bearer realm=\"st2110 demo\", error=\"{error}\", scope=\"{scope}\""),
            ));
            Err(response)
        };
        match token.as_deref().map(|t| tokens.get(t)) {
            None => {
                refuse(401, "invalid_request", "this demo asks for an IS-10 token: run the router with --demo-auth")
            }
            Some(None) => refuse(401, "invalid_token", "the token has expired, or was never issued here"),
            Some(Some(issued)) if !issued.scopes.iter().any(|s| s == scope) => {
                refuse(403, "insufficient_scope", &format!("the token's scopes do not include {scope}"))
            }
            Some(Some(_)) => Ok(()),
        }
    }

    /// Registers a client (RFC 7591 §2 and §3.2.1), for the demo Authorization Server's
    /// registration endpoint and for the router itself, which needs no HTTP for it.
    pub(crate) fn register_client(&mut self, asked: &Value) -> Result<Value, (u16, Value)> {
        let refuse = |error: &str, description: &str| (400, json!({"error": error, "error_description": description}));
        let text = |name: &str| asked.get(name).and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty());
        let name =
            text("client_name").ok_or_else(|| refuse("invalid_client_metadata", "IS-10 asks for a client_name"))?;
        let scope = text("scope").ok_or_else(|| refuse("invalid_client_metadata", "IS-10 asks for a scope"))?;
        if scope.split_whitespace().any(|s| !SCOPES.contains(&s)) {
            return Err(refuse("invalid_client_metadata", "this demo's scopes are query, connection and registration"));
        }
        let grants = asked.get("grant_types").and_then(Value::as_array);
        if grants.is_some_and(|g| g.iter().any(|g| g.as_str() != Some("client_credentials"))) {
            return Err(refuse("invalid_client_metadata", "this demo registers clients for client_credentials only"));
        }
        let method = text("token_endpoint_auth_method").unwrap_or("client_secret_basic");
        let client = match method {
            "client_secret_basic" => Client::Secret(random_token()),
            "private_key_jwt" => match text("jwks_uri") {
                Some(uri) => Client::Key(uri.to_string()),
                None => {
                    return Err(refuse("invalid_client_metadata", "private_key_jwt needs a jwks_uri, as IS-10 asks"));
                }
            },
            other => return Err(refuse("invalid_client_metadata", &format!("this demo does not take {other}"))),
        };
        // IS-10: at least 20 characters, unique to each client.
        let client_id = format!("demo-{}", random_token());
        let mut issued = json!({
            "client_id": client_id, "client_id_issued_at": 0, "client_name": name, "scope": scope,
            "grant_types": ["client_credentials"], "token_endpoint_auth_method": method,
        });
        match &client {
            Client::Secret(secret) => {
                issued["client_secret"] = json!(secret);
                issued["client_secret_expires_at"] = json!(0);
            }
            Client::Key(uri) => issued["jwks_uri"] = json!(uri),
        }
        self.clients.insert(client_id, client);
        Ok(issued)
    }

    /// The client a token request comes from, by its Basic credentials or its signed
    /// assertion (RFC 7523 §2.2).
    fn client_of(&mut self, request: &Request, form: &HashMap<String, String>) -> Result<String, &'static str> {
        if let Some((id, secret)) = request.header("Authorization").and_then(auth::basic_credentials) {
            return match self.clients.get(&id) {
                Some(Client::Secret(kept)) if *kept == secret => Ok(id),
                _ => Err("the client id or secret is not one this demo issued"),
            };
        }
        let (Some(id), Some(assertion)) = (form.get("client_id"), form.get("client_assertion")) else {
            return Err("give the client's id and secret, or a signed client_assertion");
        };
        if form.get("client_assertion_type").map(String::as_str) != Some(auth::ASSERTION_TYPE) {
            return Err("the client_assertion_type is not a JWT bearer assertion");
        }
        let Some(Client::Key(jwks_uri)) = self.clients.get(id) else {
            return Err("the client is not registered here for private_key_jwt");
        };
        // The client's keys, fetched as a real server would; the router serves its own.
        let jwks =
            auth::get_jwks(jwks_uri, Duration::from_secs(2)).map_err(|_| "the client's jwks_uri does not answer")?;
        let audience = format!("{}{TOKEN_PATH}", self.base);
        let jti = auth::verify_assertion(assertion, &jwks, id, &audience)
            .map_err(|_| "the client_assertion does not verify")?;
        if !self.assertions.insert(jti) {
            return Err("the client_assertion was used before");
        }
        Ok(id.clone())
    }

    /// The demo Authorization Server: its metadata, its registration endpoint and its
    /// token endpoint.
    fn authorization_server(&mut self, request: &Request) -> Response {
        let base = self.base.clone();
        if self.tokens.is_none() {
            return Response::error(404, "this demo asks for no tokens: run the router with --demo-auth for them");
        }
        if request.path.starts_with(METADATA_PATH) {
            return Response::json(
                200,
                &json!({
                    "issuer": format!("{base}/"),
                    "token_endpoint": format!("{base}{TOKEN_PATH}"),
                    "registration_endpoint": format!("{base}{REGISTER_PATH}"),
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
                    "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                    "response_types_supported": ["none"],
                    "scopes_supported": SCOPES,
                }),
            );
        }
        if request.path == REGISTER_PATH {
            if request.method != "POST" {
                return Response::json(
                    405,
                    &json!({"error": "invalid_request", "error_description": "register with POST"}),
                );
            }
            let token = request.header("Authorization").and_then(auth::bearer_token);
            if token != Some(INITIAL_TOKEN) {
                let mut response = Response::json(
                    401,
                    &json!({"error": "invalid_token", "error_description": format!("register with the initial access token {INITIAL_TOKEN}")}),
                );
                response
                    .headers
                    .push(("WWW-Authenticate", "Bearer realm=\"st2110 demo\", error=\"invalid_token\"".into()));
                return response;
            }
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            return match self.register_client(&asked) {
                Ok(issued) => Response::json(201, &issued),
                Err((status, body)) => Response::json(status, &body),
            };
        }
        let oauth_error = |status: u16, error: &str, description: &str| {
            let mut response = Response::json(status, &json!({"error": error, "error_description": description}));
            if status == 401 {
                response.headers.push(("WWW-Authenticate", "Basic realm=\"st2110 demo\"".into()));
            }
            response
        };
        if request.method != "POST" {
            return oauth_error(405, "invalid_request", "ask for a token with POST");
        }
        let form: HashMap<String, String> = String::from_utf8_lossy(&request.body)
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (auth::form_decode(name), auth::form_decode(value)))
            .collect();
        if let Err(why) = self.client_of(request, &form) {
            return oauth_error(401, "invalid_client", why);
        }
        let Some(tokens) = &mut self.tokens else {
            return oauth_error(404, "invalid_request", "this demo asks for no tokens");
        };
        if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
            return oauth_error(400, "unsupported_grant_type", "this demo issues tokens by client_credentials only");
        }
        let asked = form.get("scope").map_or("query connection", String::as_str);
        let scopes: Vec<String> = asked.split_whitespace().map(str::to_string).collect();
        if scopes.is_empty() || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
            return oauth_error(400, "invalid_scope", "this demo's scopes are query, connection and registration");
        }
        let token = random_token();
        let now = Instant::now();
        tokens.retain(|_, issued| issued.expires > now);
        tokens.insert(token.clone(), Issued { scopes: scopes.clone(), expires: now + TOKEN_LIFETIME });
        Response::json(
            200,
            &json!({
                "access_token": token, "token_type": "Bearer",
                "expires_in": TOKEN_LIFETIME.as_secs(), "scope": scopes.join(" "),
            }),
        )
    }
}

impl Control for Facility {
    fn endpoints(&mut self, side: Side) -> &mut BTreeMap<String, Endpoint> {
        match side {
            Side::Sender => &mut self.senders,
            Side::Receiver => &mut self.receivers,
        }
    }

    fn now(&self) -> PtpTime {
        now(self.tai_utc).unwrap_or_else(|_| PtpTime::from_utc(0, 0).expect("the epoch"))
    }

    fn activated(&mut self, side: Side, id: &str, at: PtpTime) {
        self.dirty = true;
        self.registered(side, id, at);
    }

    fn transport_file(&self, id: &str) -> Option<String> {
        self.sdp.get(id).cloned()
    }

    fn transport_type(&self, side: Side, id: &str) -> Option<String> {
        let resource = self.registry.get(side.plural())?.iter().find(|r| r["id"] == id)?;
        resource["transport"].as_str().map(str::to_string)
    }

    fn touched(&mut self) {
        self.dirty = true;
    }
}

/// A token no one can guess ahead, for the demo: the standard library's random hash keys.
fn random_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    (0..4)
        .map(|n| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u32(n);
            format!("{:016x}", hasher.finish())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use st2110_nmos::Snapshot;

    /// The facility as a registry snapshot, with the SDP files.
    fn snapshot(facility: &Facility) -> Snapshot {
        let list = |kind: &str| facility.registry[kind].clone();
        let manifests = facility
            .sdp
            .iter()
            .map(|(id, sdp)| (id.clone(), st2110_nmos::Manifest::fetched(format!("demo:{id}"), sdp.clone())))
            .collect();
        Snapshot {
            nodes: list("nodes"),
            devices: list("devices"),
            sources: list("sources"),
            flows: list("flows"),
            senders: list("senders"),
            receivers: list("receivers"),
            manifests,
            ..Snapshot::default()
        }
    }

    #[test]
    fn the_demo_files_are_clean() {
        let facility = Facility::new("http://127.0.0.1:8110", 37);
        for (id, sdp) in &facility.sdp {
            let report = st2110_sdp::lint(sdp);
            assert!(!report.has_errors(), "{id}: {:#?}", report.diagnostics);
        }
    }

    #[test]
    fn some_crosspoints_cannot_be_made() {
        let facility = Facility::new("http://127.0.0.1:8110", 37);
        let matrix = st2110_nmos::routing::matrix(&snapshot(&facility));
        let fits: BTreeMap<String, Vec<String>> = matrix
            .receivers
            .iter()
            .map(|row| {
                (row.receiver.label.clone(), row.fits.iter().map(|&i| matrix.senders[i].label.clone()).collect())
            })
            .collect();
        assert_eq!(fits["MON 1 video"], ["CAM 1 video", "CAM 2 video", "CAM 3 video", "CAM 4 video"]);
        assert_eq!(fits["MON 4 video"], ["GFX 1 video"]);
        assert_eq!(fits["MON 3 audio"].len(), 4);
        let current: Vec<&str> = matrix
            .receivers
            .iter()
            .filter_map(|row| Some((row.receiver.label.as_str(), matrix.senders[row.current?].label.as_str())))
            .map(|(r, _)| r)
            .collect();
        assert_eq!(current, ["MON 1 audio", "MON 1 video", "MON 2 audio", "MON 2 video"]);
    }
}
