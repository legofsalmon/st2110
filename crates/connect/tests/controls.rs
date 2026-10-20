//! The control APIs beyond IS-05 against a mock Device: IS-11 holding a Sender to what
//! its Receivers take, IS-08 changing a channel map, and IS-05 routing an IS-07 event
//! Receiver, which has no SDP file to take.

#![cfg(feature = "client")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use st2110_connect::client::{ConnectionClient, Options};
use st2110_connect::compat::{Hold, constrain};
use st2110_connect::controller::{Route as Connect, Settings, State, Take, connect};
use st2110_connect::mapping::{Remap, Route, remap};
use st2110_nmos::Snapshot;

const FACILITY: &str = include_str!("../../nmos/tests/fixtures/facility.json");
const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const VIDEO_RECEIVER: &str = "7ecf0001-0000-4000-8000-000000000001";
const MON_2_VIDEO: &str = "7ecf0009-0000-4000-8000-000000000009";
const CAMERA: &str = "de710001-0000-4000-8000-000000000001";
const MONITOR: &str = "de710002-0000-4000-8000-000000000002";
const TALLY_SOURCE: &str = "50c0000a-0000-4000-8000-00000000000a";
const TALLY_FLOW: &str = "f10e000a-0000-4000-8000-00000000000a";
const TALLY_SENDER: &str = "5e0d000a-0000-4000-8000-00000000000a";
const TALLY_RECEIVER: &str = "7ecf000a-0000-4000-8000-00000000000a";
const EVENTS: &str = "ws://192.168.10.21:8870/x-nmos/events/1.0/5e0d000a";

type Answer = Box<dyn FnMut(&str, &str, &Value) -> (u16, Value) + Send>;

/// A Device's control APIs, answering as `answer` says, with every request logged.
struct Mock {
    port: u16,
    log: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Mock {
    fn start(answer: impl FnMut(&str, &str, &Value) -> (u16, Value) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let answer: Arc<Mutex<Answer>> = Arc::new(Mutex::new(Box::new(answer)));
        let serving = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (log, answer) = (serving.clone(), answer.clone());
                std::thread::spawn(move || handle(stream, &log, &answer));
            }
        });
        Self { port, log }
    }

    /// The facility, with a second video Monitor, a tally Sender and Receiver over
    /// IS-07 WebSockets, and every Device's control APIs at the mock.
    fn snapshot(&self) -> Snapshot {
        let mut value: Value = serde_json::from_str(FACILITY).unwrap();
        let base = format!("http://127.0.0.1:{}/x-nmos", self.port);
        for device in value["devices"].as_array_mut().unwrap() {
            device["controls"] = json!([
                {"href": format!("{base}/connection/v1.1/"), "type": "urn:x-nmos:control:sr-ctrl/v1.1"},
                {"href": format!("{base}/streamcompatibility/v1.0/"), "type": "urn:x-nmos:control:stream-compat/v1.0"},
                {"href": format!("{base}/channelmapping/v1.0/"), "type": "urn:x-nmos:control:cm-ctrl/v1.0"},
            ]);
        }
        let receivers = value["receivers"].as_array_mut().unwrap();
        let mut second = receivers.iter().find(|r| r["id"] == VIDEO_RECEIVER).unwrap().clone();
        second["id"] = json!(MON_2_VIDEO);
        second["label"] = json!("MON 2 video");
        second["subscription"] = json!({"sender_id": null, "active": false});
        second["caps"]["constraint_sets"] = json!([{
            "urn:x-nmos:cap:meta:preference": 10,
            "urn:x-nmos:cap:format:frame_width": {"enum": [1920]},
            "urn:x-nmos:cap:format:grain_rate": {"enum": [{"numerator": 50}]},
        }, {
            "urn:x-nmos:cap:meta:enabled": false,
            "urn:x-nmos:cap:format:frame_width": {"enum": [1280]},
        }]);
        receivers.push(second);
        receivers.push(json!({
            "id": TALLY_RECEIVER, "version": "1790510437:0", "label": "TALLY in", "description": "", "tags": {},
            "device_id": MONITOR, "transport": "urn:x-nmos:transport:websocket", "interface_bindings": [],
            "subscription": {"sender_id": null, "active": false}, "format": "urn:x-nmos:format:data",
            "caps": {"media_types": ["application/json"], "event_types": ["boolean"]},
        }));
        value["sources"].as_array_mut().unwrap().push(json!({
            "id": TALLY_SOURCE, "version": "1790510437:0", "label": "TALLY", "description": "", "tags": {},
            "device_id": CAMERA, "parents": [], "clock_name": null, "caps": {}, "format": "urn:x-nmos:format:data",
            "event_type": "boolean",
        }));
        value["flows"].as_array_mut().unwrap().push(json!({
            "id": TALLY_FLOW, "version": "1790510437:0", "label": "TALLY", "description": "", "tags": {},
            "device_id": CAMERA, "source_id": TALLY_SOURCE, "parents": [], "format": "urn:x-nmos:format:data",
            "media_type": "application/json", "event_type": "boolean",
        }));
        value["senders"].as_array_mut().unwrap().push(json!({
            "id": TALLY_SENDER, "version": "1790510437:0", "label": "TALLY out", "description": "", "tags": {},
            "device_id": CAMERA, "flow_id": TALLY_FLOW, "transport": "urn:x-nmos:transport:websocket",
            "manifest_href": null, "interface_bindings": [], "subscription": {"receiver_id": null, "active": true},
        }));
        value["manifests"] = json!({});
        serde_json::from_value(value).unwrap()
    }

    /// The requests made so far other than `GET`s, as `METHOD path`, with their bodies.
    fn changes(&self) -> Vec<(String, Value)> {
        let log = self.log.lock().unwrap();
        log.iter().filter(|(method, ..)| method != "GET").map(|(m, p, b)| (format!("{m} {p}"), b.clone())).collect()
    }
}

fn handle(mut stream: TcpStream, log: &Mutex<Vec<(String, String, Value)>>, answer: &Mutex<Answer>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    let mut length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let body: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
    let mut words = request.split_whitespace();
    let (method, path) = (words.next().unwrap_or("GET").to_string(), words.next().unwrap_or("/").to_string());
    log.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
    let (status, body) = (answer.lock().unwrap())(&method, &path, &body);
    let text = if body.is_null() { String::new() } else { body.to_string() };
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn error(code: u16, message: &str) -> (u16, Value) {
    (code, json!({"code": code, "error": message, "debug": null}))
}

fn client() -> ConnectionClient {
    ConnectionClient::new(&Options { timeout: Duration::from_millis(800), env_proxy: false, token: None })
}

fn settings() -> Settings {
    Settings { wait: Duration::from_secs(2), ..Settings::default() }
}

const COMPAT: &str = "/x-nmos/streamcompatibility/v1.0/senders/5e0d0001-0000-4000-8000-000000000001/";

/// An IS-11 Sender that can be held to its frame size and rate, and is `constrained`
/// once it is.
fn stream_compat(put: (u16, Value)) -> impl FnMut(&str, &str, &Value) -> (u16, Value) + Send {
    let mut held = false;
    move |method, path, _body| {
        let Some(resource) = path.strip_prefix(COMPAT) else { return error(404, "not found") };
        match (method, resource) {
            ("GET", "constraints/supported") => (
                200,
                json!({"parameter_constraints": [
                    "urn:x-nmos:cap:format:frame_width",
                    "urn:x-nmos:cap:format:frame_height",
                    "urn:x-nmos:cap:format:grain_rate",
                    "urn:x-nmos:cap:meta:label",
                ]}),
            ),
            ("PUT", "constraints/active") => {
                held = put.0 == 200;
                put.clone()
            }
            ("DELETE", "constraints/active") => {
                held = false;
                (200, json!({"constraint_sets": []}))
            }
            ("GET", "status") => (200, json!({"state": if held { "constrained" } else { "unconstrained" }})),
            _ => error(405, "Method Not Allowed"),
        }
    }
}

#[test]
fn holds_a_sender_to_what_its_receivers_all_take() {
    let mock = Mock::start(stream_compat((200, json!({}))));
    let wanted = Hold::For(vec!["MON 1 video".into(), "MON 2 video".into()]);
    let report = constrain(&mock.snapshot(), "CAM 1 video", &wanted, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Done, "{report:#?}");
    assert_eq!(report.status.as_deref(), Some("constrained"));
    assert!(report.problems.is_empty() && report.warnings.is_empty(), "{report:#?}");
    // MON 1's 720p set has no 1920 in common with MON 2; its 1080p set has 50 Hz in
    // common. MON 2's disabled set and both preferences are left out.
    let sets = json!({"constraint_sets": [{
        "urn:x-nmos:cap:format:frame_width": {"enum": [1920]},
        "urn:x-nmos:cap:format:frame_height": {"enum": [1080]},
        "urn:x-nmos:cap:format:grain_rate": {"enum": [{"numerator": 50}]},
    }]});
    assert_eq!(report.request.as_ref(), Some(&sets));
    assert_eq!(mock.changes(), [(format!("PUT {COMPAT}constraints/active"), sets)]);
    // What the Sender cannot be held to is said, not sent.
    assert!(report.notes.iter().any(|n| n.contains("format:color_sampling") && n.contains("supported")), "{report:#?}");
}

#[test]
fn a_sender_that_is_sending_cannot_be_held() {
    let mock = Mock::start(stream_compat(error(423, "Locked")));
    let wanted = Hold::For(vec!["MON 2 video".into()]);
    let report = constrain(&mock.snapshot(), "CAM 1 video", &wanted, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Failed);
    assert!(report.problems[0].contains("turn it off first"), "{report:#?}");
    assert_eq!(report.status, None);
}

#[test]
fn lets_a_sender_go_and_plans_without_sending() {
    let mock = Mock::start(stream_compat((200, json!({}))));
    let snapshot = mock.snapshot();
    let report = constrain(&snapshot, VIDEO_SENDER, &Hold::Nothing, &client(), &settings()).unwrap();
    assert_eq!((report.state, report.status.as_deref()), (State::Done, Some("unconstrained")), "{report:#?}");
    let dry = Settings { dry_run: true, ..settings() };
    let wanted = Hold::For(vec!["MON 2 video".into()]);
    let report = constrain(&snapshot, VIDEO_SENDER, &wanted, &client(), &dry).unwrap();
    assert_eq!(report.state, State::Planned);
    assert!(report.request.is_some());
    assert_eq!(mock.changes().len(), 1, "only the DELETE was sent");
}

#[test]
fn receivers_with_nothing_in_common_are_refused() {
    let mock = Mock::start(stream_compat((200, json!({}))));
    let mut snapshot = mock.snapshot();
    let mon_2 = snapshot.receivers.iter_mut().find(|r| r["id"] == MON_2_VIDEO).unwrap();
    mon_2["caps"]["constraint_sets"] = json!([{"urn:x-nmos:cap:format:frame_width": {"enum": [3840]}}]);
    let wanted = Hold::For(vec!["MON 1 video".into(), "MON 2 video".into()]);
    let report = constrain(&snapshot, VIDEO_SENDER, &wanted, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Refused, "{report:#?}");
    assert!(report.problems[0].contains("MON 2 video"), "{report:#?}");
    assert!(mock.changes().is_empty());
}

const MAPPING: &str = "/x-nmos/channelmapping/v1.0/";

/// An IS-08 Device with one stereo Input and Output, answering an activation as
/// `activate` says and applying the ones it takes at once.
fn channel_mapping(activate: (u16, Value)) -> impl FnMut(&str, &str, &Value) -> (u16, Value) + Send {
    let mut map = json!({
        "out-1": {"0": {"input": null, "channel_index": null}, "1": {"input": null, "channel_index": null}},
    });
    let mut pending: BTreeMap<String, Value> = BTreeMap::from([("9".to_string(), json!({}))]);
    move |method, path, body| {
        let Some(resource) = path.strip_prefix(MAPPING) else { return error(404, "not found") };
        match (method, resource) {
            ("GET", "io") => (
                200,
                json!({
                    "inputs": {"in-1": {"properties": {"name": "mic", "description": ""}, "parent": {"type": null, "id": null},
                                        "channels": [{"label": "L"}, {"label": "R"}],
                                        "caps": {"reordering": true, "block_size": 1}}},
                    "outputs": {"out-1": {"properties": {"name": "main", "description": ""}, "source_id": null,
                                          "channels": [{"label": "L"}, {"label": "R"}],
                                          "caps": {"routable_inputs": ["in-1", null]}}},
                }),
            ),
            ("GET", "map/active") => (200, json!({"activation": {}, "map": map})),
            ("POST", "map/activations") => {
                if activate.0 == 200 {
                    for (output, channels) in body["action"].as_object().unwrap() {
                        for (index, route) in channels.as_object().unwrap() {
                            map[output][index] = route.clone();
                        }
                    }
                }
                activate.clone()
            }
            ("GET", "map/activations") => (200, json!(pending)),
            ("DELETE", activation) => match activation.strip_prefix("map/activations/") {
                Some(id) if pending.remove(id).is_some() => (204, Value::Null),
                _ => error(404, "not found"),
            },
            _ => error(405, "Method Not Allowed"),
        }
    }
}

#[test]
fn maps_channels_at_once_and_reads_them_back() {
    let accepted = json!({"1": {"activation": {"mode": "activate_immediate"}, "action": {}}});
    let mock = Mock::start(channel_mapping((200, accepted)));
    let routes = vec![Route::parse("main:1=mic:2").unwrap(), Route::parse("main:2=mic:1").unwrap()];
    let report = remap(&mock.snapshot(), "Monitor 1", &Remap::Routes(routes), &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Done, "{report:#?}");
    assert_eq!(report.device.id, MONITOR);
    let sent = json!({
        "activation": {"mode": "activate_immediate", "requested_time": null},
        "action": {"out-1": {"0": {"input": "in-1", "channel_index": 1}, "1": {"input": "in-1", "channel_index": 0}}},
    });
    assert_eq!(mock.changes(), [(format!("POST {MAPPING}map/activations"), sent)]);
}

#[test]
fn a_scheduled_map_is_left_with_its_activation_id() {
    let accepted = json!({"7": {"activation": {"mode": "activate_scheduled_relative", "requested_time": "2:0",
                                               "activation_time": "1790510439:0"}, "action": {}}});
    let mock = Mock::start(channel_mapping((202, accepted)));
    let after = Settings { activation: Some(st2110_connect::Activation::After(2_000_000_000)), ..settings() };
    // The Device is named by one of its Receivers.
    let report = remap(
        &mock.snapshot(),
        "MON 1 video",
        &Remap::Routes(vec![Route::parse("main:1=-").unwrap()]),
        &client(),
        &after,
    )
    .unwrap();
    assert_eq!(report.state, State::Scheduled, "{report:#?}");
    assert_eq!((report.activation_id.as_deref(), report.activation_time.as_deref()), (Some("7"), Some("1790510439:0")));
}

#[test]
fn a_map_waiting_on_the_outputs_locks_them_until_it_is_cancelled() {
    let mock = Mock::start(channel_mapping(error(423, "Locked")));
    let snapshot = mock.snapshot();
    let routes = Remap::Routes(vec![Route::parse("main:1=mic:1").unwrap()]);
    let report = remap(&snapshot, MONITOR, &routes, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Failed);
    assert!(report.problems[0].contains("cancel it first"), "{report:#?}");

    let report = remap(&snapshot, MONITOR, &Remap::Cancel, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Done, "{report:#?}");
    assert_eq!(report.notes, ["cancelled activation 9"]);
    assert_eq!(mock.changes().last().unwrap().0, format!("DELETE {MAPPING}map/activations/9"));
}

#[test]
fn routes_that_io_does_not_have_are_refused() {
    let mock = Mock::start(channel_mapping((200, json!({}))));
    let routes = Remap::Routes(vec![Route::parse("main:3=mic:1").unwrap(), Route::parse("main:1=line:1").unwrap()]);
    let report = remap(&mock.snapshot(), MONITOR, &routes, &client(), &settings()).unwrap();
    assert_eq!(report.state, State::Refused);
    assert_eq!(report.problems.len(), 2, "{report:#?}");
    assert!(mock.changes().is_empty());
}

/// An IS-05 Connection API for the tally Sender and Receiver, over IS-07 WebSockets.
fn events() -> impl FnMut(&str, &str, &Value) -> (u16, Value) + Send {
    let sender = format!("/x-nmos/connection/v1.1/single/senders/{TALLY_SENDER}/");
    let receiver = format!("/x-nmos/connection/v1.1/single/receivers/{TALLY_RECEIVER}/");
    let mut staged = json!({
        "sender_id": null, "master_enable": false, "activation": {},
        "transport_params": [{"connection_uri": null, "connection_authorization": "auto"}],
    });
    let mut active = staged.clone();
    move |method, path, body| {
        if let Some(resource) = path.strip_prefix(&sender) {
            return match resource {
                "active" => (
                    200,
                    json!({"sender_id": TALLY_SENDER, "master_enable": true, "receiver_id": null, "activation": {},
                           "transport_params": [{"connection_uri": EVENTS, "connection_authorization": false}]}),
                ),
                _ => error(404, "not found"),
            };
        }
        let Some(resource) = path.strip_prefix(&receiver) else { return error(404, "not found") };
        match (method, resource) {
            ("GET", "constraints") => (200, json!([{"connection_uri": {}, "connection_authorization": {}}])),
            ("GET", "staged") => (200, staged.clone()),
            ("GET", "active") => (200, active.clone()),
            ("PATCH", "staged") => {
                for field in ["sender_id", "master_enable"] {
                    if let Some(value) = body.get(field) {
                        staged[field] = value.clone();
                    }
                }
                for (name, value) in body["transport_params"][0].as_object().into_iter().flatten() {
                    staged["transport_params"][0][name] = value.clone();
                }
                if body["activation"]["mode"] == "activate_immediate" {
                    staged["activation"] = json!({"mode": "activate_immediate", "requested_time": null,
                                                  "activation_time": "1790510439:0"});
                    active = staged.clone();
                }
                (200, staged.clone())
            }
            _ => error(405, "Method Not Allowed"),
        }
    }
}

#[test]
fn routes_an_event_receiver_to_where_the_events_are_without_sdp() {
    let mock = Mock::start(events());
    let route = Connect { receiver: "TALLY in".into(), take: Take::Sender("TALLY out".into()) };
    let outcome = connect(&mock.snapshot(), &[route], &client(), None, &settings()).unwrap();
    let connection = &outcome.connections[0];
    assert_eq!(connection.state, State::Done, "{connection:#?}");
    assert!(connection.problems.is_empty(), "{connection:#?}");
    let (change, body) = &mock.changes()[0];
    assert_eq!(change, &format!("PATCH /x-nmos/connection/v1.1/single/receivers/{TALLY_RECEIVER}/staged"));
    assert_eq!(body["sender_id"], TALLY_SENDER);
    assert_eq!(body["transport_params"], json!([{"connection_uri": EVENTS, "connection_authorization": false}]));
    assert!(body.get("transport_file").is_none(), "no SDP file goes to an event Receiver: {body}");
}
