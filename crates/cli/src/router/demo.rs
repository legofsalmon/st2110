//! A demo facility for `st2110 router --demo`: an IS-04 Query API and the IS-05
//! Connection API of each Node, served alongside the router page, so the router can be
//! tried with no equipment. Its Receivers stage, schedule and activate as IS-05 v1.2
//! describes, and the registry hears of each activation, as a Node tells its registry.
//!
//! Four cameras send 1080p50 video on an ST 2022-7 pair and stereo audio; a graphics
//! machine sends 720p50 video on one leg. Three monitors take 1080p video on two legs
//! and audio, and a fourth takes only 720p video, so some crosspoints cannot be made.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use st2110_ptp::PtpTime;

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

/// The registry, and every Node's Connection API.
pub(crate) struct Facility {
    tai_utc: i32,
    /// The registry's resources, by type: `nodes`, `devices` and so on.
    registry: BTreeMap<&'static str, Vec<Value>>,
    receivers: BTreeMap<String, Receiver>,
    sdp: BTreeMap<String, String>,
}

/// A Sender to build: its label, Flow facts and SDP file.
struct Sending {
    label: String,
    video: Option<(u32, u32)>,
    sdp: String,
}

impl Facility {
    /// The facility, with URLs on `base`, such as `http://127.0.0.1:8110`, and two
    /// monitors already taking cameras.
    pub(crate) fn new(base: &str, tai_utc: i32) -> Self {
        let mut facility =
            Self { tai_utc, registry: BTreeMap::new(), receivers: BTreeMap::new(), sdp: BTreeMap::new() };
        for kind in ["nodes", "devices", "sources", "flows", "senders", "receivers"] {
            facility.registry.insert(kind, Vec::new());
        }
        let mut node = 0;
        for camera in 1..=4u32 {
            node += 1;
            let red = format!("192.168.10.2{camera}");
            let blue = format!("192.168.20.2{camera}");
            let video = Sending {
                label: format!("CAM {camera} video"),
                video: Some((1920, 1080)),
                sdp: video_sdp(
                    &format!("CAM {camera} video"),
                    1920,
                    1080,
                    &[(&red, &format!("239.10.{camera}.1")), (&blue, &format!("239.20.{camera}.1"))],
                ),
            };
            let audio = Sending {
                label: format!("CAM {camera} audio"),
                video: None,
                sdp: audio_sdp(&format!("CAM {camera} audio"), &red, &format!("239.10.{camera}.2")),
            };
            facility.add_sender_node(base, node, &format!("Camera {camera}"), &[&red, &blue], &[video, audio]);
        }
        node += 1;
        let graphics = Sending {
            label: "GFX 1 video".into(),
            video: Some((1280, 720)),
            sdp: video_sdp("GFX 1 video", 1280, 720, &[("192.168.10.41", "239.10.41.1")]),
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
                    "transport_params": facility.legs(&receiver, &sdp),
                });
                facility.stage(&receiver, &body);
                facility.activate(&receiver, now);
                debug_assert_eq!(facility.receivers[&receiver].active["sender_id"], json!(sender), "{kind}");
            }
        }
        facility
    }

    /// What a Receiver's legs take from an SDP file, for setting up the demo.
    fn legs(&self, receiver: &str, sdp: &str) -> Value {
        let groups: Vec<(String, String)> = sdp
            .lines()
            .filter_map(|line| line.strip_prefix("a=source-filter: incl IN IP4 "))
            .filter_map(|rest| rest.split_once(' '))
            .map(|(group, source)| (group.to_string(), source.to_string()))
            .collect();
        let count = self.receivers[receiver].constraints.as_array().map_or(0, Vec::len);
        (0..count)
            .map(|leg| match groups.get(leg) {
                Some((group, source)) => {
                    json!({"multicast_ip": group, "source_ip": source, "destination_port": 5004, "rtp_enabled": true})
                }
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
            let (source, flow) = match s.video {
                Some((width, height)) => (
                    json!({"format": VIDEO, "grain_rate": {"numerator": 50}}),
                    json!({
                        "format": VIDEO, "grain_rate": {"numerator": 50}, "frame_width": width, "frame_height": height,
                        "interlace_mode": "progressive", "colorspace": "BT709", "transfer_characteristic": "SDR",
                        "media_type": "video/raw",
                        "components": [
                            {"name": "Y", "width": width, "height": height, "bit_depth": 10},
                            {"name": "Cb", "width": width / 2, "height": height, "bit_depth": 10},
                            {"name": "Cr", "width": width / 2, "height": height, "bit_depth": 10},
                        ],
                    }),
                ),
                None => (
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
            let legs = s.sdp.matches("m=").count();
            let bindings: Vec<String> = (0..legs).map(|i| format!("eth{i}")).collect();
            let mut sender = merge(
                core(&sender_id, &s.label),
                json!({
                    "caps": {}, "flow_id": flow_id, "transport": MCAST, "device_id": device_id,
                    "manifest_href": format!("{base}/node/{n}/x-nmos/connection/v1.1/single/senders/{sender_id}/transportfile"),
                    "interface_bindings": bindings, "subscription": {"receiver_id": null, "active": true},
                }),
            );
            if s.video.is_some() {
                sender["st2110_21_sender_type"] = json!("2110TPN");
            }
            self.registry.get_mut("senders").expect("senders").push(sender);
            self.sdp.insert(sender_id, s.sdp.clone());
        }
    }

    fn add_monitor(&mut self, base: &str, n: u32, monitor: u32, video: &[String], audio: &str) {
        let interfaces: Vec<&str> = video.iter().map(String::as_str).collect();
        let device_id = self.node(base, n, &format!("Monitor {monitor}"), &interfaces);
        let (width, height, label) = if monitor == 4 { (1280, 720, "720p") } else { (1920, 1080, "1080p") };
        let video_caps = json!({
            "media_types": ["video/raw"],
            "constraint_sets": [{
                "urn:x-nmos:cap:meta:label": label,
                "urn:x-nmos:cap:format:frame_width": {"enum": [width]},
                "urn:x-nmos:cap:format:frame_height": {"enum": [height]},
                "urn:x-nmos:cap:format:interlace_mode": {"enum": ["progressive"]},
                "urn:x-nmos:cap:format:grain_rate": {"enum": [{"numerator": 50}, {"numerator": 60000, "denominator": 1001}]},
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

    /// Whether a request is for the facility, rather than the router.
    pub(crate) fn serves(path: &str) -> bool {
        path.starts_with("/x-nmos/") || path.starts_with("/node/")
    }

    /// Answers a request for the registry or a Connection API.
    pub(crate) fn answer(&mut self, request: &Request) -> Response {
        self.settle();
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
            if method != "GET" {
                return error(405, "Method Not Allowed", "the Query API only reads");
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
            ("PATCH", "staged") => self.stage(id, body),
            _ => error(405, "Method Not Allowed", ""),
        }
    }

    /// The Query API: its versions, a collection or one resource. Collections are not
    /// paged, and query parameters are ignored.
    fn query(&self, rest: &str) -> (u16, Value) {
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        match parts.as_slice() {
            [] => (200, json!(["v1.3/"])),
            ["v1.3"] => (200, json!(["nodes/", "devices/", "sources/", "flows/", "senders/", "receivers/"])),
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
    fn settle(&mut self) {
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
        if let Some(registered) =
            self.registry.get_mut("receivers").and_then(|list| list.iter_mut().find(|r| r["id"] == id))
        {
            registered["subscription"] = subscription;
            registered["version"] = json!(tai(at));
        }
    }
}

/// An ST 2110-20 SDP file, with one media section per leg: `(source, group)`.
fn video_sdp(name: &str, width: u32, height: u32, legs: &[(&str, &str)]) -> String {
    let mut sdp = format!("v=0\r\no=- 1790510437 1790510437 IN IP4 {}\r\ns={name}\r\nt=0 0\r\n", legs[0].0);
    let mids = ["primary", "secondary"];
    if legs.len() == 2 {
        sdp.push_str("a=group:DUP primary secondary\r\n");
    }
    for (i, (source, group)) in legs.iter().enumerate() {
        sdp.push_str(&format!(
            "m=video 5004 RTP/AVP 96\r\nc=IN IP4 {group}/32\r\na=source-filter: incl IN IP4 {group} {source}\r\n\
             a=rtpmap:96 raw/90000\r\n\
             a=fmtp:96 sampling=YCbCr-4:2:2; width={width}; height={height}; exactframerate=50; depth=10; TCS=SDR; \
             colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN; TSMODE=SAMP\r\n\
             a=ts-refclk:ptp=IEEE1588-2008:{GMID}:127\r\na=mediaclk:direct=0\r\n"
        ));
        if legs.len() == 2 {
            sdp.push_str(&format!("a=mid:{}\r\n", mids[i]));
        }
    }
    sdp
}

/// An ST 2110-30 SDP file of stereo, 24-bit, 1 ms packets.
fn audio_sdp(name: &str, source: &str, group: &str) -> String {
    format!(
        "v=0\r\no=- 1790510437 1790510437 IN IP4 {source}\r\ns={name}\r\nt=0 0\r\n\
         m=audio 5006 RTP/AVP 97\r\nc=IN IP4 {group}/32\r\na=source-filter: incl IN IP4 {group} {source}\r\n\
         a=rtpmap:97 L24/48000/2\r\na=fmtp:97 channel-order=SMPTE2110.(ST); TSMODE=SAMP\r\na=ptime:1\r\n\
         a=ts-refclk:ptp=IEEE1588-2008:{GMID}:127\r\na=mediaclk:direct=0\r\n"
    )
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
