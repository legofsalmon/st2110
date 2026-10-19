//! A demo facility for `st2110 router --demo`: an IS-04 Query API and the IS-05
//! Connection API of each Node, served alongside the router page, so the router can be
//! tried with no equipment. Its Receivers stage, schedule and activate as IS-05 v1.2
//! describes, and the registry hears of each activation, as a Node tells its registry.
//!
//! Four cameras send video on an ST 2022-7 pair and stereo tone; a graphics machine
//! sends a smaller picture on one leg. Three monitors take the cameras' video on two legs
//! and audio, and a fourth takes only the graphics machine's size, so some crosspoints
//! cannot be made.
//!
//! The streams are real: [`super::signal::start`] sends each Sender's from this
//! machine, on the loopback interface, so the router can show them. They are small
//! pictures at 25 frames a second, so that a laptop carries them all with ease.
//!
//! Its Query API takes subscriptions, and pushes each change to them over a WebSocket,
//! as a registry does. With `--demo-auth` it asks for IS-10 tokens too, and serves the
//! Authorization Server to get them from: one client, [`CLIENT_ID`] with
//! [`CLIENT_SECRET`], whose tokens last a minute. Its tokens are opaque strings it keeps
//! a list of, where a real Authorization Server issues signed JWTs for each Resource
//! Server to check for itself.

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::format::{AudioFormat, VideoFormat};
use st2110_ptp::PtpTime;
use st2110_sdp::Rational;

use st2110_nmos::auth;

use super::http::{Request, Response};
use crate::timing::now;

const VIDEO: &str = "urn:x-nmos:format:video";
const AUDIO: &str = "urn:x-nmos:format:audio";
const MCAST: &str = "urn:x-nmos:transport:rtp.mcast";
const GMID: &str = "08-00-11-FF-FE-21-E1-B0";

/// A demo resource id: `prefix` names the type and `n` the resource.
fn id(prefix: &str, n: u32) -> String {
    format!("{prefix}{n:04x}-0000-4000-8000-{n:012x}")
}

fn tai(time: PtpTime) -> String {
    format!("{}:{}", time.seconds(), time.subsec_nanos())
}

/// What every IS-04 resource has.
fn core(id: &str, label: &str) -> Value {
    json!({"id": id, "version": "1790510437:0", "label": label, "description": label, "tags": {}})
}

fn merge(mut base: Value, more: Value) -> Value {
    if let (Some(base), Value::Object(more)) = (base.as_object_mut(), more) {
        base.extend(more);
    }
    base
}

/// One Receiver's IS-05 resources.
struct Receiver {
    constraints: Value,
    staged: Value,
    active: Value,
    /// When a scheduled activation is due.
    pending: Option<PtpTime>,
}

fn idle(interfaces: &[String]) -> Value {
    let legs: Vec<Value> = interfaces
        .iter()
        .map(|i| json!({"source_ip": null, "multicast_ip": null, "interface_ip": i, "destination_port": 5004, "rtp_enabled": true}))
        .collect();
    json!({
        "sender_id": null, "master_enable": false,
        "activation": {"mode": null, "requested_time": null, "activation_time": null},
        "transport_file": {"data": null, "type": null},
        "transport_params": legs,
    })
}

fn constraints(interfaces: &[String]) -> Value {
    interfaces
        .iter()
        .map(|i| {
            json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["auto", i]},
                   "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}})
        })
        .collect()
}

fn error(code: u16, message: &str, debug: &str) -> (u16, Value) {
    (code, json!({"code": code, "error": message, "debug": debug}))
}

/// The demo Authorization Server's one client.
pub(crate) const CLIENT_ID: &str = "st2110-demo";

/// Its secret: this is a demo, on this machine.
pub(crate) const CLIENT_SECRET: &str = "demo-secret";

/// How long a demo token lasts, short enough to see one renewed.
const TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// Where the demo Authorization Server hands out tokens.
const TOKEN_PATH: &str = "/x-nmos/auth/v1.0/token";

/// Where its metadata is (RFC 8414).
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

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
    receivers: BTreeMap<String, Receiver>,
    sdp: BTreeMap<String, String>,
    /// Each Sender's stream, keyed by Sender `id`: its label and description.
    streams: BTreeMap<String, (String, Description)>,
    /// The Query API's subscriptions, by `id`.
    subscriptions: BTreeMap<String, Value>,
    /// Changes to the registry not yet pushed to subscriptions: the resource type, and
    /// the resource before and after.
    changes: Vec<(&'static str, Value, Value)>,
    /// The tokens issued, with `--demo-auth`.
    tokens: Option<HashMap<String, Issued>>,
    /// Whether a Receiver changed since the facility was last kept.
    dirty: bool,
}

/// A Sender to build: its label, Flow facts and SDP file.
struct Sending {
    label: String,
    description: Description,
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
            sdp: BTreeMap::new(),
            streams: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            changes: Vec::new(),
            tokens: None,
            dirty: false,
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
            };
            let label = format!("CAM {camera} audio");
            let audio = Sending {
                description: description(
                    &label,
                    Media::Audio(AudioFormat::new(2)),
                    &[(&format!("239.10.{camera}.2"), 5006)],
                ),
                label,
            };
            facility.add_sender_node(base, node, &format!("Camera {camera}"), &[&red, &blue], &[video, audio]);
        }
        node += 1;
        let graphics = Sending {
            label: "GFX 1 video".into(),
            description: description("GFX 1 video", video(GRAPHICS.0, GRAPHICS.1), &[("239.10.41.1", 5004)]),
        };
        facility.add_sender_node(base, node, "Graphics 1", &["192.168.10.41"], &[graphics]);
        for monitor in 1..=4u32 {
            node += 1;
            let red = format!("192.168.10.3{monitor}");
            let blue = format!("192.168.20.3{monitor}");
            let video = if monitor == 4 { vec![red.clone()] } else { vec![red.clone(), blue] };
            facility.add_monitor(base, node, monitor, &video, &red);
        }
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
                facility.stage(&receiver, &body);
                facility.activate(&receiver, now);
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
        let count = self.receivers[receiver].constraints.as_array().map_or(0, Vec::len);
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
            .map(|(i, _)| json!({"chassis_id": format!("c8-00-84-10-{n:02x}-00"), "port_id": format!("c8-00-84-10-{n:02x}-{:02x}", i + 1), "name": format!("eth{i}")}))
            .collect();
        self.registry.get_mut("nodes").expect("nodes").push(merge(
            core(&node_id, label),
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
            core(&device_id, label),
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
                    "caps": {}, "flow_id": flow_id, "transport": MCAST, "device_id": device_id,
                    "manifest_href": format!("{base}/node/{n}/x-nmos/connection/v1.1/single/senders/{sender_id}/transportfile"),
                    "interface_bindings": bindings, "subscription": {"receiver_id": null, "active": true},
                }),
            );
            if matches!(s.description.media, Media::Video(_)) {
                sender["st2110_21_sender_type"] = json!("2110TPN");
            }
            self.registry.get_mut("senders").expect("senders").push(sender);
            self.sdp.insert(sender_id.clone(), s.description.sdp(u64::from(k)));
            self.streams.insert(sender_id, (s.label.clone(), s.description.clone()));
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
            self.registry.get_mut("receivers").expect("receivers").push(merge(
                core(&receiver_id, &label),
                json!({
                    "device_id": device_id, "transport": MCAST, "interface_bindings": bindings,
                    "subscription": {"sender_id": null, "active": false}, "format": format, "caps": caps,
                }),
            ));
            self.receivers.insert(
                receiver_id,
                Receiver {
                    constraints: constraints(&interfaces),
                    staged: idle(&interfaces),
                    active: idle(&interfaces),
                    pending: None,
                },
            );
        }
    }

    /// Each Sender's label and the stream it sends, for [`super::signal::start`].
    pub(crate) fn streams(&self) -> Vec<(String, Description)> {
        self.streams.values().cloned().collect()
    }

    /// Whether a request is for the facility, rather than the router.
    pub(crate) fn serves(path: &str) -> bool {
        path.starts_with("/x-nmos/") || path.starts_with("/node/") || path.starts_with(METADATA_PATH)
    }

    /// Answers a request for the registry, a Connection API or the Authorization Server.
    pub(crate) fn answer(&mut self, request: &Request) -> Response {
        self.settle();
        if request.path.starts_with(METADATA_PATH) || request.path == TOKEN_PATH {
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
        let (status, body) = self.route(&request.method, &request.path, &body);
        match body {
            Value::String(sdp) => {
                Response { status, content_type: "application/sdp", headers: Vec::new(), body: sdp.into_bytes() }
            }
            body => Response::json(status, &body),
        }
    }

    fn route(&mut self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        let path = path.trim_end_matches('/');
        if let Some(rest) = path.strip_prefix("/x-nmos/query") {
            if method == "POST" && rest == "/v1.3/subscriptions" {
                return self.subscribe(body);
            }
            if method != "GET" {
                return error(405, "Method Not Allowed", "the Query API only reads, and takes subscriptions");
            }
            return self.query(rest);
        }
        // `/node/<n>/x-nmos/connection/v1.1/...`: each Node's own Connection API.
        let Some(rest) = path
            .strip_prefix("/node/")
            .and_then(|rest| rest.split_once('/'))
            .and_then(|(_, rest)| rest.strip_prefix("x-nmos/connection/v1.1/"))
        else {
            return error(404, "Not Found", path);
        };
        if let Some(id) = rest.strip_prefix("single/senders/").and_then(|r| r.strip_suffix("/transportfile")) {
            return match self.sdp.get(id) {
                Some(sdp) if method == "GET" => (200, Value::String(sdp.clone())),
                Some(_) => error(405, "Method Not Allowed", ""),
                None => error(404, "Not Found", "no such Sender"),
            };
        }
        if rest == "bulk/receivers" {
            if method != "POST" {
                return error(405, "Method Not Allowed", "");
            }
            let Some(items) = body.as_array() else {
                return error(400, "Bad Request", "a bulk request is an array");
            };
            self.dirty = true;
            let results = items
                .iter()
                .map(|item| {
                    let id = item["id"].as_str().unwrap_or_default();
                    let (code, response) = if self.receivers.contains_key(id) {
                        self.stage(id, &item["params"])
                    } else {
                        error(404, "Not Found", "no such Receiver")
                    };
                    let mut result = json!({"id": id, "code": code});
                    if code >= 400 {
                        result["error"] = response["error"].clone();
                        result["debug"] = response["debug"].clone();
                    }
                    result
                })
                .collect();
            return (200, Value::Array(results));
        }
        let Some((id, resource)) = rest.strip_prefix("single/receivers/").and_then(|r| r.split_once('/')) else {
            return error(404, "Not Found", path);
        };
        let Some(receiver) = self.receivers.get(id) else {
            return error(404, "Not Found", "no such Receiver");
        };
        match (method, resource) {
            ("GET", "constraints") => (200, receiver.constraints.clone()),
            ("GET", "staged") => (200, receiver.staged.clone()),
            ("GET", "active") => (200, receiver.active.clone()),
            ("PATCH", "staged") => {
                self.dirty = true;
                self.stage(id, body)
            }
            _ => error(405, "Method Not Allowed", ""),
        }
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

    fn now(&self) -> PtpTime {
        now(self.tai_utc).unwrap_or_else(|_| PtpTime::from_utc(0, 0).expect("the epoch"))
    }

    /// Carries out the scheduled activations that are due.
    pub(crate) fn settle(&mut self) {
        let now = self.now();
        let due: Vec<(String, PtpTime)> = self
            .receivers
            .iter()
            .filter_map(|(id, r)| r.pending.filter(|&due| due <= now).map(|due| (id.clone(), due)))
            .collect();
        for (id, due) in due {
            self.activate(&id, due);
        }
    }

    /// What a `PATCH` to `/staged` does.
    fn stage(&mut self, id: &str, body: &Value) -> (u16, Value) {
        let now = self.now();
        let receiver = self.receivers.get_mut(id).expect("a known Receiver");
        let mode = body.get("activation").map(|a| &a["mode"]);
        if receiver.pending.is_some() && mode != Some(&Value::Null) {
            return error(423, "Locked", "an activation is scheduled");
        }
        if let Some(params) = body.get("transport_params") {
            let legs = receiver.constraints.as_array().cloned().unwrap_or_default();
            let Some(params) = params.as_array().filter(|p| p.len() == legs.len()) else {
                return error(400, "Invalid transport_params", "one entry per leg");
            };
            for (leg, (constraints, params)) in legs.iter().zip(params).enumerate() {
                for (name, value) in params.as_object().into_iter().flatten() {
                    let Some(constraint) = constraints.get(name) else {
                        return error(400, "Invalid transport_params", &format!("leg {leg} has no {name}"));
                    };
                    let allowed = constraint.get("enum").and_then(Value::as_array).is_none_or(|e| e.contains(value));
                    let in_range = value.as_f64().is_none_or(|n| {
                        constraint.get("minimum").and_then(Value::as_f64).is_none_or(|m| n >= m)
                            && constraint.get("maximum").and_then(Value::as_f64).is_none_or(|m| n <= m)
                    });
                    if !allowed || !in_range {
                        return error(400, "Constraint violation", &format!("leg {leg}: {name} {value}"));
                    }
                }
            }
            let staged = receiver.staged["transport_params"].as_array_mut().expect("legs");
            for (staged, params) in staged.iter_mut().zip(params) {
                for (name, value) in params.as_object().into_iter().flatten() {
                    staged[name] = value.clone();
                }
            }
        }
        for field in ["sender_id", "master_enable", "transport_file"] {
            if let Some(value) = body.get(field) {
                receiver.staged[field] = value.clone();
            }
        }
        let requested = body["activation"]["requested_time"].as_str().and_then(PtpTime::parse);
        match mode.and_then(Value::as_str) {
            Some("activate_immediate") => {
                self.activate(id, now);
                let mut response = self.receivers[id].staged.clone();
                response["activation"] =
                    json!({"mode": "activate_immediate", "requested_time": null, "activation_time": tai(now)});
                (200, response)
            }
            Some(mode @ ("activate_scheduled_absolute" | "activate_scheduled_relative")) => {
                let Some(requested) = requested else {
                    return error(400, "Bad Request", "a scheduled activation needs a requested_time");
                };
                let due = if mode == "activate_scheduled_absolute" {
                    requested
                } else {
                    now.add_nanos(requested.nanos()).unwrap_or(now)
                };
                receiver.pending = Some(due);
                receiver.staged["activation"] = json!({
                    "mode": mode, "requested_time": body["activation"]["requested_time"], "activation_time": tai(due),
                });
                (202, receiver.staged.clone())
            }
            Some(other) => error(400, "Bad Request", &format!("no activation mode {other}")),
            None => {
                if mode.is_some() {
                    receiver.pending = None;
                    receiver.staged["activation"] =
                        json!({"mode": null, "requested_time": null, "activation_time": null});
                }
                (200, receiver.staged.clone())
            }
        }
    }

    fn activate(&mut self, id: &str, at: PtpTime) {
        let receiver = self.receivers.get_mut(id).expect("a known Receiver");
        let mut active = receiver.staged.clone();
        let legs = receiver.constraints.as_array().cloned().unwrap_or_default();
        for (leg, constraints) in active["transport_params"].as_array_mut().into_iter().flatten().zip(&legs) {
            if leg["interface_ip"] == "auto" {
                leg["interface_ip"] = constraints["interface_ip"]["enum"][1].clone();
            }
        }
        active["activation"] = json!({
            "mode": receiver.staged["activation"]["mode"].as_str().unwrap_or("activate_immediate"),
            "requested_time": receiver.staged["activation"]["requested_time"],
            "activation_time": tai(at),
        });
        receiver.active = active;
        receiver.pending = None;
        receiver.staged["activation"] = json!({"mode": null, "requested_time": null, "activation_time": null});
        let subscription =
            json!({"sender_id": receiver.active["sender_id"], "active": receiver.active["master_enable"]});
        self.register(id, subscription, at);
        self.dirty = true;
    }

    /// Tells the registry what a Receiver takes now, as its Node would.
    fn register(&mut self, id: &str, subscription: Value, at: PtpTime) {
        if let Some(registered) =
            self.registry.get_mut("receivers").and_then(|list| list.iter_mut().find(|r| r["id"] == id))
        {
            let pre = registered.clone();
            registered["subscription"] = subscription;
            registered["version"] = json!(tai(at));
            self.changes.push(("receivers", pre, registered.clone()));
        }
    }

    /// Each Receiver's staged and active parameters, to keep for the next run.
    pub(crate) fn export(&self) -> Value {
        let receivers: serde_json::Map<String, Value> = self
            .receivers
            .iter()
            .map(|(id, r)| (id.clone(), json!({"staged": r.staged, "active": r.active})))
            .collect();
        json!({"receivers": receivers})
    }

    /// Puts back what [`Facility::export`] kept: each Receiver takes what it took. What
    /// was scheduled and not yet due is not scheduled again.
    pub(crate) fn restore(&mut self, kept: &Value) {
        let now = self.now();
        let ids: Vec<String> = self.receivers.keys().cloned().collect();
        for id in ids {
            let Some(saved) = kept["receivers"].get(&id) else { continue };
            let legs = self.receivers[&id].constraints.as_array().map_or(0, Vec::len);
            let fits = |v: &Value| v["transport_params"].as_array().is_some_and(|p| p.len() == legs);
            if !fits(&saved["staged"]) || !fits(&saved["active"]) {
                continue;
            }
            let receiver = self.receivers.get_mut(&id).expect("a known Receiver");
            receiver.staged = saved["staged"].clone();
            receiver.staged["activation"] = json!({"mode": null, "requested_time": null, "activation_time": null});
            receiver.active = saved["active"].clone();
            receiver.pending = None;
            let subscription =
                json!({"sender_id": receiver.active["sender_id"], "active": receiver.active["master_enable"]});
            self.register(&id, subscription, now);
        }
        self.changes.clear();
        self.dirty = false;
    }

    /// Whether a Receiver changed since this was last asked.
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
                .map(|(_, pre, post)| json!({"path": post["id"], "pre": pre, "post": post}))
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

    /// The demo Authorization Server: its metadata, and its token endpoint.
    fn authorization_server(&mut self, request: &Request) -> Response {
        let base = self.base.clone();
        let Some(tokens) = &mut self.tokens else {
            return Response::error(404, "this demo asks for no tokens: run the router with --demo-auth for them");
        };
        if request.path.starts_with(METADATA_PATH) {
            return Response::json(
                200,
                &json!({
                    "issuer": format!("{base}/"),
                    "token_endpoint": format!("{base}{TOKEN_PATH}"),
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "response_types_supported": ["none"],
                    "scopes_supported": ["query", "connection"],
                }),
            );
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
        let credentials = request.header("Authorization").and_then(auth::basic_credentials);
        if credentials.as_ref().is_none_or(|(id, secret)| id != CLIENT_ID || secret != CLIENT_SECRET) {
            return oauth_error(401, "invalid_client", "the client id or secret is not this demo's");
        }
        let form: HashMap<String, String> = String::from_utf8_lossy(&request.body)
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (auth::form_decode(name), auth::form_decode(value)))
            .collect();
        if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
            return oauth_error(400, "unsupported_grant_type", "this demo issues tokens by client_credentials only");
        }
        let asked = form.get("scope").map_or("query connection", String::as_str);
        let scopes: Vec<String> = asked.split_whitespace().map(str::to_string).collect();
        if scopes.is_empty() || scopes.iter().any(|s| s != "query" && s != "connection") {
            return oauth_error(400, "invalid_scope", "this demo's scopes are query and connection");
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
