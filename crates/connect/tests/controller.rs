//! The controller against a mock facility: the two-node test registry, and a Connection
//! API that stages, schedules and activates as IS-05 v1.2 describes, with faults to order.

#![cfg(feature = "client")]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use st2110_connect::Activation;
use st2110_connect::client::{ConnectionClient, Options};
use st2110_connect::controller::{Outcome, Route, Settings, State, Take, cancel, connect};
use st2110_nmos::Snapshot;
use st2110_nmos::client::{self, QueryClient};
use st2110_ptp::PtpTime;

const FACILITY: &str = include_str!("../../nmos/tests/fixtures/facility.json");
const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const AUDIO_SENDER: &str = "5e0d0002-0000-4000-8000-000000000002";
const VIDEO_RECEIVER: &str = "7ecf0001-0000-4000-8000-000000000001";
const AUDIO_RECEIVER: &str = "7ecf0002-0000-4000-8000-000000000002";
/// A Sender outside the facility, for another controller to connect.
const CAMERA_2_VIDEO: &str = "5e0d0003-0000-4000-8000-000000000003";

/// The time now, as the mock and the controller both read it.
fn now() -> PtpTime {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i128;
    PtpTime::from_utc(unix, 37).unwrap()
}

fn tai(time: PtpTime) -> String {
    format!("{}:{}", time.seconds(), time.subsec_nanos())
}

/// One Receiver's IS-05 resources.
struct Receiver {
    constraints: Value,
    staged: Value,
    active: Value,
    /// When a scheduled activation is due.
    pending: Option<PtpTime>,
}

/// Faults to order.
#[derive(Default)]
struct Faults {
    /// Receivers whose requests are refused, with the status.
    refuse: BTreeMap<String, u16>,
    /// Receivers whose next request is acted on, then not answered.
    lose: Vec<String>,
    /// No `/bulk/receivers`.
    no_bulk: bool,
    /// `PATCH` requests are redirected to the same URL with a trailing slash.
    redirect_patch: bool,
    /// The registry does not hear of activations.
    registry_lags: bool,
    /// Requests that cancel an activation are refused.
    refuse_cancel: bool,
    /// Receivers whose next activation is acted on, then answered with a server error.
    fail_after: Vec<String>,
    /// Receivers that bulk responses leave out, though they were staged.
    bulk_omit: Vec<String>,
    /// When a request is refused, another controller has just taken the video Receiver
    /// to Camera 2.
    third_party: bool,
    /// Receivers whose activations are accepted but never take effect.
    stuck: Vec<String>,
}

/// The Connection API of Monitor 1 and Camera 1, and the registry's copy of each Receiver.
struct Facility {
    receivers: BTreeMap<String, Receiver>,
    registry: BTreeMap<String, Value>,
    sdp: BTreeMap<String, String>,
    faults: Faults,
    /// Each request: the method, the path, and the body when there is one.
    log: Vec<(String, String, Value)>,
}

/// A leg of an idle Receiver.
fn idle_leg(interface: &str) -> Value {
    json!({"source_ip": null, "multicast_ip": null, "interface_ip": interface, "destination_port": 5004, "rtp_enabled": true})
}

fn idle(interfaces: &[&str]) -> Value {
    json!({
        "sender_id": null, "master_enable": false,
        "activation": {"mode": null, "requested_time": null, "activation_time": null},
        "transport_file": {"data": null, "type": null},
        "transport_params": interfaces.iter().map(|i| idle_leg(i)).collect::<Vec<_>>(),
    })
}

fn constraints(interfaces: &[&str]) -> Value {
    interfaces
        .iter()
        .map(|i| {
            json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": [i]},
                   "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}})
        })
        .collect()
}

fn error(code: u16, message: &str, debug: &str) -> (u16, Value) {
    (code, json!({"code": code, "error": message, "debug": debug}))
}

impl Facility {
    fn new(facility: &Value) -> Self {
        let receiver = |interfaces: &[&str]| Receiver {
            constraints: constraints(interfaces),
            staged: idle(interfaces),
            active: idle(interfaces),
            pending: None,
        };
        let receivers = BTreeMap::from([
            (VIDEO_RECEIVER.to_string(), receiver(&["192.168.10.31", "192.168.20.31"])),
            (AUDIO_RECEIVER.to_string(), receiver(&["192.168.10.32"])),
        ]);
        // The registry's copy of each Receiver, idle as the Connection API has it.
        let registry = facility["receivers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let mut r = r.clone();
                r["subscription"] = json!({"sender_id": null, "active": false});
                (r["id"].as_str().unwrap().to_string(), r)
            })
            .collect();
        let sdp = [VIDEO_SENDER, AUDIO_SENDER]
            .map(|id| (id.to_string(), facility["manifests"][id]["sdp"].as_str().unwrap().to_string()))
            .into();
        Self { receivers, registry, sdp, faults: Faults::default(), log: Vec::new() }
    }

    /// Answers a request: the status, extra header lines and the body.
    fn answer(&mut self, method: &str, path: &str, body: &Value, port: u16) -> (u16, String, Value) {
        self.log.push((method.to_string(), path.to_string(), body.clone()));
        let (status, body) = self.route(method, path, body);
        let headers =
            if status == 301 { format!("Location: http://127.0.0.1:{port}{path}/\r\n") } else { String::new() };
        (status, headers, body)
    }

    fn route(&mut self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        if let Some(id) = path.strip_prefix("/x-nmos/query/v1.3/receivers/") {
            let id = id.split('?').next().unwrap_or_default();
            return match self.registry.get(id) {
                Some(receiver) => (200, receiver.clone()),
                None => error(404, "not found", ""),
            };
        }
        let transport_file = path
            .strip_prefix("/x-nmos/connection/v1.1/single/senders/")
            .and_then(|rest| rest.strip_suffix("/transportfile"));
        if let Some(id) = path.strip_prefix("/sdp/").or(transport_file) {
            return match self.sdp.get(id) {
                Some(sdp) => (200, Value::String(sdp.clone())),
                None => error(404, "not found", ""),
            };
        }
        if path == "/x-nmos/connection/v1.1/bulk/receivers" && method == "POST" {
            if self.faults.no_bulk {
                return error(501, "Not Implemented", "no bulk interface here");
            }
            let items: Vec<Value> = body
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| {
                    let id = item["id"].as_str().unwrap();
                    let (code, response) = self.stage(id, &item["params"]);
                    if self.faults.bulk_omit.iter().any(|omit| omit == id) {
                        return None;
                    }
                    let mut result = json!({"id": id, "code": code});
                    if code >= 400 {
                        result["error"] = response["error"].clone();
                        result["debug"] = response["debug"].clone();
                    }
                    Some(result)
                })
                .collect();
            return (200, Value::Array(items));
        }
        let Some((id, resource)) =
            path.strip_prefix("/x-nmos/connection/v1.1/single/receivers/").and_then(|r| r.split_once('/'))
        else {
            return error(404, "not found", path);
        };
        let id = id.to_string();
        let Some(receiver) = self.receivers.get_mut(&id) else {
            return error(404, "not found", "no such Receiver");
        };
        match (method, resource) {
            ("GET", "constraints") => (200, receiver.constraints.clone()),
            ("GET", "staged") => (200, receiver.staged.clone()),
            ("GET", "active") => {
                self.settle(&id);
                (200, self.receivers[&id].active.clone())
            }
            ("PATCH", "staged") if self.faults.redirect_patch => (301, Value::Null),
            ("PATCH", "staged") if self.faults.fail_after.contains(&id) && body["activation"]["mode"].is_string() => {
                self.faults.fail_after.retain(|fail| *fail != id);
                self.stage(&id, body);
                error(500, "Internal Server Error", "acted on, then failed")
            }
            ("PATCH", "staged") => self.stage(&id, body),
            _ => error(405, "Method Not Allowed", ""),
        }
    }

    /// Carries out a scheduled activation that is due.
    fn settle(&mut self, id: &str) {
        let receiver = self.receivers.get_mut(id).unwrap();
        if let Some(due) = receiver.pending
            && now() >= due
        {
            self.activate(id, due);
        }
    }

    /// What a `PATCH` to `/staged` does.
    fn stage(&mut self, id: &str, body: &Value) -> (u16, Value) {
        self.settle(id);
        if let Some(&status) = self.faults.refuse.get(id) {
            if self.faults.third_party {
                let video = &mut self.receivers.get_mut(VIDEO_RECEIVER).unwrap().active;
                video["sender_id"] = json!(CAMERA_2_VIDEO);
                video["master_enable"] = json!(true);
            }
            return error(status, "Refused", "as ordered");
        }
        let receiver = self.receivers.get_mut(id).unwrap();
        let mode = body.get("activation").map(|a| &a["mode"]);
        if self.faults.refuse_cancel && mode == Some(&Value::Null) {
            return error(500, "Internal Server Error", "cannot cancel");
        }
        if receiver.pending.is_some() && mode != Some(&Value::Null) {
            return error(423, "Locked", "an activation is scheduled");
        }
        if let Some(params) = body.get("transport_params") {
            let legs = receiver.constraints.as_array().unwrap();
            let Some(params) = params.as_array().filter(|p| p.len() == legs.len()) else {
                return error(400, "Invalid transport_params", "one entry per leg");
            };
            for (leg, (constraints, params)) in legs.iter().zip(params).enumerate() {
                for (name, value) in params.as_object().unwrap() {
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
            for (staged, params) in receiver.staged["transport_params"].as_array_mut().unwrap().iter_mut().zip(params) {
                for (name, value) in params.as_object().unwrap() {
                    staged[name] = value.clone();
                }
            }
        }
        for field in ["sender_id", "master_enable", "transport_file"] {
            if let Some(value) = body.get(field) {
                receiver.staged[field] = value.clone();
            }
        }
        let now = now();
        let requested = || PtpTime::parse(body["activation"]["requested_time"].as_str().unwrap()).unwrap();
        match mode.and_then(Value::as_str) {
            Some("activate_immediate") => {
                self.activate(id, now);
                let mut response = self.receivers[id].staged.clone();
                response["activation"] =
                    json!({"mode": "activate_immediate", "requested_time": null, "activation_time": tai(now)});
                (200, response)
            }
            Some(mode) => {
                let due = if mode == "activate_scheduled_absolute" {
                    requested()
                } else {
                    now.add_nanos(requested().nanos()).unwrap()
                };
                receiver.pending = Some(due);
                receiver.staged["activation"] = json!({"mode": mode, "requested_time": body["activation"]["requested_time"], "activation_time": tai(due)});
                (202, receiver.staged.clone())
            }
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
        let receiver = self.receivers.get_mut(id).unwrap();
        if self.faults.stuck.iter().any(|stuck| stuck == id) {
            receiver.pending = None;
            receiver.staged["activation"] = json!({"mode": null, "requested_time": null, "activation_time": null});
            return;
        }
        let mut active = receiver.staged.clone();
        for (leg, constraints) in
            active["transport_params"].as_array_mut().unwrap().iter_mut().zip(receiver.constraints.as_array().unwrap())
        {
            if leg["interface_ip"] == "auto" {
                leg["interface_ip"] = constraints["interface_ip"]["enum"][0].clone();
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
        if !self.faults.registry_lags {
            let registered = self.registry.get_mut(id).unwrap();
            let active = &self.receivers[id].active;
            registered["subscription"] = json!({"sender_id": active["sender_id"], "active": active["master_enable"]});
            registered["version"] = json!(tai(at));
        }
    }
}

/// The mock, serving on a free port.
struct Mock {
    port: u16,
    facility: Arc<Mutex<Facility>>,
}

impl Mock {
    fn start(change: impl FnOnce(&mut Facility)) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().unwrap().port();
        let value: Value = serde_json::from_str(FACILITY).unwrap();
        let mut facility = Facility::new(&value);
        change(&mut facility);
        let facility = Arc::new(Mutex::new(facility));
        let serving = facility.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let facility = serving.clone();
                std::thread::spawn(move || handle(stream, port, &facility));
            }
        });
        Self { port, facility }
    }

    /// The registry snapshot, with the facility's URLs pointing at the mock and every
    /// Receiver idle.
    fn snapshot(&self) -> Snapshot {
        let mut value: Value = serde_json::from_str(FACILITY).unwrap();
        for sender in value["senders"].as_array_mut().unwrap() {
            let id = sender["id"].as_str().unwrap().to_string();
            sender["manifest_href"] = json!(format!("http://127.0.0.1:{}/sdp/{id}", self.port));
        }
        for device in value["devices"].as_array_mut().unwrap() {
            device["controls"][0]["href"] = json!(format!("http://127.0.0.1:{}/x-nmos/connection/v1.1/", self.port));
        }
        for receiver in value["receivers"].as_array_mut().unwrap() {
            receiver["subscription"] = json!({"sender_id": null, "active": false});
        }
        value["manifests"] = json!({});
        serde_json::from_value(value).unwrap()
    }

    fn registry(&self) -> QueryClient {
        let options =
            client::Options { timeout: Duration::from_secs(5), env_proxy: false, ..client::Options::default() };
        QueryClient::connect(&format!("http://127.0.0.1:{}/x-nmos/query/v1.3/", self.port), &options).unwrap()
    }

    fn connect(&self, routes: &[Route], settings: &Settings) -> Outcome {
        let client = ConnectionClient::new(&Options { timeout: Duration::from_millis(800), env_proxy: false });
        connect(&self.snapshot(), routes, &client, Some(&self.registry()), settings).expect("the names are good")
    }

    /// The requests made so far other than `GET`s, as `METHOD path`.
    fn changes(&self) -> Vec<String> {
        let facility = self.facility.lock().unwrap();
        facility.log.iter().filter(|(method, ..)| method != "GET").map(|(m, p, _)| format!("{m} {p}")).collect()
    }

    fn bodies(&self, method: &str) -> Vec<Value> {
        let facility = self.facility.lock().unwrap();
        facility.log.iter().filter(|(m, ..)| m == method).map(|(.., body)| body.clone()).collect()
    }

    fn active(&self, id: &str) -> Value {
        let mut facility = self.facility.lock().unwrap();
        facility.settle(id);
        facility.receivers[id].active.clone()
    }

    fn registered(&self, id: &str) -> Value {
        self.facility.lock().unwrap().registry[id].clone()
    }

    fn staged(&self, id: &str) -> Value {
        self.facility.lock().unwrap().receivers[id].staged.clone()
    }
}

fn handle(mut stream: TcpStream, port: u16, facility: &Mutex<Facility>) {
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
    let (status, headers, body, lose) = {
        let mut facility = facility.lock().unwrap();
        let id = path.split('/').find(|part| facility.receivers.contains_key(*part)).map(str::to_string);
        let lose = method == "PATCH"
            && id.as_ref().is_some_and(|id| facility.faults.lose.contains(id))
            && body["activation"]["mode"].is_string();
        let (status, headers, body) = facility.answer(&method, &path, &body, port);
        if lose {
            facility.faults.lose.retain(|l| Some(l) != id.as_ref());
        }
        (status, headers, body, lose)
    };
    if lose {
        // Acted on, and the answer never comes.
        std::thread::sleep(Duration::from_millis(1500));
        return;
    }
    let (content_type, text) = match body {
        Value::Null => ("application/json", String::new()),
        Value::String(sdp) => ("application/sdp", sdp),
        json => ("application/json", json.to_string()),
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn route(receiver: &str, take: Take) -> Route {
    Route { receiver: receiver.into(), take }
}

fn sender(name: &str) -> Take {
    Take::Sender(name.into())
}

fn settings() -> Settings {
    Settings { lead: Duration::from_millis(400), wait: Duration::from_secs(3), ..Settings::default() }
}

fn states(outcome: &Outcome) -> Vec<State> {
    outcome.connections.iter().map(|c| c.state).collect()
}

#[test]
fn connects_one_receiver_at_once() {
    let mock = Mock::start(|_| {});
    let outcome = mock.connect(&[route("MON 1 video", sender("CAM 1 video"))], &settings());
    let connection = &outcome.connections[0];
    assert_eq!(connection.state, State::Done, "{connection:#?}");
    assert!(connection.problems.is_empty() && connection.warnings.is_empty() && connection.notes.is_empty());
    assert_eq!(outcome.activation, json!({"mode": "activate_immediate", "requested_time": null}));
    assert_eq!(connection.sdp.as_deref(), Some(format!("http://127.0.0.1:{}/sdp/{VIDEO_SENDER}", mock.port).as_str()));
    assert_eq!(mock.changes(), [format!("PATCH /x-nmos/connection/v1.1/single/receivers/{VIDEO_RECEIVER}/staged")]);

    let active = mock.active(VIDEO_RECEIVER);
    assert_eq!((active["sender_id"].as_str(), active["master_enable"].as_bool()), (Some(VIDEO_SENDER), Some(true)));
    assert_eq!(active["transport_params"][0]["multicast_ip"], "239.10.10.1");
    assert_eq!(active["transport_params"][1]["source_ip"], "192.168.20.21");
    assert_eq!(
        connection.activation_time.as_ref(),
        active["activation"]["activation_time"].as_str().map(String::from).as_ref()
    );
    // The registry heard, and nothing lags.
    assert_eq!(mock.registered(VIDEO_RECEIVER)["subscription"], json!({"sender_id": VIDEO_SENDER, "active": true}));
    assert!(outcome.succeeded());
}

#[test]
fn a_salvo_switches_together_in_one_bulk_request() {
    let mock = Mock::start(|_| {});
    let before = now();
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    assert_eq!(states(&outcome), [State::Done, State::Done], "{outcome:#?}");
    assert_eq!(
        mock.changes(),
        ["POST /x-nmos/connection/v1.1/bulk/receivers"],
        "both Receivers share one Connection API"
    );
    let mode = &outcome.activation["mode"];
    assert_eq!(mode, "activate_scheduled_absolute");
    let requested = PtpTime::parse(outcome.activation["requested_time"].as_str().unwrap()).unwrap();
    let lead = requested.nanos() - before.nanos();
    assert!((400_000_000..3_000_000_000).contains(&lead), "scheduled {lead} ns ahead");
    let bulk = &mock.bodies("POST")[0];
    assert_eq!(bulk[0]["id"], VIDEO_RECEIVER);
    assert_eq!(bulk[1]["params"]["activation"], outcome.activation, "one time for all");
    // Both switched at the time asked for.
    for (connection, id) in outcome.connections.iter().zip([VIDEO_RECEIVER, AUDIO_RECEIVER]) {
        assert_eq!(connection.activation_time.as_deref(), outcome.activation["requested_time"].as_str());
        assert_eq!(mock.active(id)["activation"]["activation_time"], outcome.activation["requested_time"]);
    }
    assert_eq!(mock.active(AUDIO_RECEIVER)["transport_params"][0]["multicast_ip"], "239.10.10.2");
}

#[test]
fn without_bulk_it_sends_one_request_each() {
    let mock = Mock::start(|f| f.faults.no_bulk = true);
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    assert_eq!(states(&outcome), [State::Done, State::Done], "{outcome:#?}");
    // Sent side by side, in no particular order.
    let mut changes = mock.changes();
    changes[1..].sort();
    assert_eq!(
        changes,
        [
            "POST /x-nmos/connection/v1.1/bulk/receivers".to_string(),
            format!("PATCH /x-nmos/connection/v1.1/single/receivers/{VIDEO_RECEIVER}/staged"),
            format!("PATCH /x-nmos/connection/v1.1/single/receivers/{AUDIO_RECEIVER}/staged"),
        ]
    );
}

#[test]
fn a_refusal_cancels_the_rest_of_the_salvo() {
    let mock = Mock::start(|f| {
        f.faults.refuse.insert(AUDIO_RECEIVER.into(), 400);
    });
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    assert_eq!(outcome.connections[1].problems, ["the Connection API refused it: HTTP 400: Refused (as ordered)"]);
    assert!(outcome.connections[0].warnings.is_empty(), "cancelled before it took effect");
    // The video Receiver's scheduled activation was cancelled, and what it had staged
    // again, with no activation, so that none can make the connection later.
    let idle = idle(&["192.168.10.31", "192.168.20.31"]);
    let [cancel, staged] = mock.bodies("PATCH").try_into().unwrap();
    assert_eq!(cancel, json!({"activation": {"mode": null, "requested_time": null}}));
    assert_eq!(
        staged,
        json!({"sender_id": null, "master_enable": false, "transport_file": idle["transport_file"],
               "transport_params": idle["transport_params"]})
    );
    assert_eq!(mock.staged(VIDEO_RECEIVER), idle, "as it was");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(mock.active(VIDEO_RECEIVER)["master_enable"], false, "it never switched");
    assert!(!outcome.succeeded());
}

#[test]
fn an_activation_left_scheduled_fails_the_rollback() {
    let mock = Mock::start(|f| {
        f.faults.refuse.insert(AUDIO_RECEIVER.into(), 400);
        f.faults.refuse_cancel = true;
    });
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    // The video Receiver has not switched yet, but will.
    assert_eq!(states(&outcome), [State::RollbackFailed, State::Failed], "{outcome:#?}");
    assert_eq!(
        outcome.connections[0].warnings,
        ["cancelling its activation was refused: HTTP 500: Internal Server Error (cannot cancel)"]
    );
}

#[test]
fn an_unanswered_part_of_a_salvo_is_cancelled_in_time() {
    let mock = Mock::start(|f| {
        f.faults.no_bulk = true;
        f.faults.lose.push(AUDIO_RECEIVER.into());
    });
    let started = std::time::Instant::now();
    // Less than the client's timeout, 800 ms.
    let settings = Settings { lead: Duration::from_millis(600), ..settings() };
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings,
    );
    // The audio request is given half the lead, so the video one is cancelled before
    // it is due, rather than put back after it took effect.
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    assert!(outcome.connections[0].warnings.is_empty(), "{outcome:#?}");
    assert!(outcome.connections[1].problems[0].starts_with("no answer: "), "{outcome:#?}");
    std::thread::sleep(Duration::from_millis(900).saturating_sub(started.elapsed()));
    for id in [VIDEO_RECEIVER, AUDIO_RECEIVER] {
        assert_eq!(mock.active(id)["master_enable"], false, "{id} never switched");
    }
}

#[test]
fn a_result_left_out_of_a_bulk_response_is_cancelled() {
    let mock = Mock::start(|f| f.faults.bulk_omit.push(AUDIO_RECEIVER.into()));
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    let bulk = format!("http://127.0.0.1:{}/x-nmos/connection/v1.1/bulk/receivers", mock.port);
    assert_eq!(outcome.connections[1].problems, [format!("the response to {bulk} says nothing of it")]);
    // It was staged all the same, so it was cancelled with the rest.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(mock.active(AUDIO_RECEIVER)["master_enable"], false, "it never switched");
    assert_eq!(mock.staged(AUDIO_RECEIVER)["sender_id"], Value::Null);
}

#[test]
fn a_server_error_is_checked_and_put_back() {
    let mock = Mock::start(|f| {
        f.faults.no_bulk = true;
        f.faults.fail_after.push(AUDIO_RECEIVER.into());
    });
    let settings = Settings { activation: Some(Activation::Immediate), ..settings() };
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings,
    );
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    let audio = &outcome.connections[1];
    assert_eq!(audio.problems, ["the Connection API failed: HTTP 500: Internal Server Error (acted on, then failed)"]);
    assert_eq!(audio.warnings, ["it had taken effect, and was put back as it was"]);
    assert_eq!(mock.active(AUDIO_RECEIVER)["master_enable"], false);
}

#[test]
fn a_rollback_leaves_another_controllers_change() {
    let mock = Mock::start(|f| {
        f.faults.no_bulk = true;
        f.faults.refuse.insert(AUDIO_RECEIVER.into(), 400);
        f.faults.third_party = true;
    });
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings(),
    );
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    assert_eq!(
        outcome.connections[0].warnings,
        ["it has changed since it was read, but not to this connection, so it was left as it is"]
    );
    assert_eq!(mock.active(VIDEO_RECEIVER)["sender_id"], CAMERA_2_VIDEO);
}

#[test]
fn an_activation_that_does_not_take_is_reported() {
    let mock = Mock::start(|f| {
        f.faults.stuck.push(AUDIO_RECEIVER.into());
        f.receivers.get_mut(AUDIO_RECEIVER).unwrap().active["activation"]["activation_time"] = json!("1790510000:0");
    });
    let settings = Settings { wait: Duration::from_millis(400), ..settings() };
    let outcome = mock.connect(&[route("MON 1 audio", sender("CAM 1 audio"))], &settings);
    let connection = &outcome.connections[0];
    assert_eq!(connection.state, State::Differs, "{connection:#?}");
    assert_eq!(connection.problems[0], "its /active endpoint shows master_enable is false, not true");
    // When it was to take effect, not the last activation /active shows.
    let at = PtpTime::parse(connection.activation_time.as_deref().unwrap()).unwrap();
    assert!((now().nanos() - at.nanos()).abs() < 5_000_000_000, "{at}");
}

#[test]
fn an_immediate_salvo_is_put_back() {
    let mock = Mock::start(|f| {
        f.faults.no_bulk = true;
        f.faults.refuse.insert(AUDIO_RECEIVER.into(), 500);
    });
    let settings = Settings { activation: Some(Activation::Immediate), ..settings() };
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("MON 1 audio", sender("CAM 1 audio"))],
        &settings,
    );
    assert_eq!(states(&outcome), [State::RolledBack, State::Failed], "{outcome:#?}");
    assert_eq!(outcome.connections[0].warnings, ["it had taken effect, and was put back as it was"]);
    let active = mock.active(VIDEO_RECEIVER);
    assert_eq!((active["sender_id"].clone(), active["master_enable"].clone()), (Value::Null, json!(false)));
    assert_eq!(active["transport_params"], idle(&["192.168.10.31", "192.168.20.31"])["transport_params"]);
}

#[test]
fn an_unanswered_request_is_checked_and_put_back() {
    let mock = Mock::start(|f| f.faults.lose.push(AUDIO_RECEIVER.into()));
    let outcome = mock.connect(&[route("MON 1 audio", sender("CAM 1 audio"))], &settings());
    let connection = &outcome.connections[0];
    assert_eq!(connection.state, State::Failed, "{connection:#?}");
    assert!(connection.problems[0].starts_with("no answer: "), "{:?}", connection.problems);
    assert_eq!(connection.warnings, ["it had taken effect, and was put back as it was"]);
    assert_eq!(mock.active(AUDIO_RECEIVER)["master_enable"], false);
}

#[test]
fn refuses_what_a_receiver_cannot_take() {
    let mock = Mock::start(|_| {});
    let wrong = [route("MON 1 video", sender("CAM 1 audio")), route("MON 1 audio", sender("CAM 1 audio"))];
    let outcome = mock.connect(&wrong, &settings());
    assert_eq!(states(&outcome), [State::Refused, State::Held]);
    assert_eq!(
        outcome.connections[0].problems,
        ["it is a video Receiver, but sender \"CAM 1 audio\" (5e0d0002) sends audio"]
    );
    assert_eq!(
        outcome.connections[0].notes,
        ["the stream has one leg, so the Receiver's leg 2 is turned off: it has no ST 2022-7 protection"]
    );
    assert!(mock.changes().is_empty(), "nothing is sent");

    // Forced, it is sent, and the problem is still reported.
    let forced = mock.connect(&wrong[..1], &Settings { force: true, ..settings() });
    assert_eq!(states(&forced), [State::Done], "{forced:#?}");
    assert_eq!(forced.connections[0].problems.len(), 1);
    assert_eq!(mock.active(VIDEO_RECEIVER)["transport_params"][1]["rtp_enabled"], false);
}

#[test]
fn a_redirect_or_a_lock_fails_the_request() {
    let mock = Mock::start(|f| f.faults.redirect_patch = true);
    let outcome = mock.connect(&[route("MON 1 video", sender("CAM 1 video"))], &settings());
    assert_eq!(
        outcome.connections[0].problems,
        [format!(
            "the Connection API refused it: HTTP 301, redirecting to http://127.0.0.1:{}/x-nmos/connection/v1.1/single/\
             receivers/{VIDEO_RECEIVER}/staged/; IS-05 redirects only GET requests",
            mock.port
        )]
    );
    assert_eq!(mock.changes().len(), 1, "the redirect is not followed");

    let mock = Mock::start(|f| {
        f.receivers.get_mut(AUDIO_RECEIVER).unwrap().pending = Some(now().add_nanos(60_000_000_000).unwrap())
    });
    let outcome = mock.connect(&[route("MON 1 audio", sender("CAM 1 audio"))], &settings());
    assert_eq!(states(&outcome), [State::Failed]);
    assert_eq!(
        outcome.connections[0].problems,
        [
            "the Connection API refused it: HTTP 423: Locked (an activation is scheduled); an activation is already scheduled on it"
        ]
    );
}

#[test]
fn a_dry_run_sends_nothing() {
    let mock = Mock::start(|_| {});
    let outcome = mock.connect(
        &[route("MON 1 video", sender("CAM 1 video")), route("7ecf0002", Take::Nothing)],
        &Settings { dry_run: true, ..settings() },
    );
    assert_eq!(states(&outcome), [State::Planned, State::Planned]);
    assert!(mock.changes().is_empty());
    let request = outcome.connections[1].request.as_ref().unwrap();
    assert_eq!(request["activation"], outcome.activation);
    assert_eq!(request["master_enable"], false);
    assert!(outcome.succeeded());
}

#[test]
fn disconnects_and_takes_streams_from_outside_nmos() {
    let mock = Mock::start(|_| {});
    mock.connect(&[route("MON 1 audio", sender("CAM 1 audio"))], &settings());
    let outcome = mock.connect(&[route("MON 1 audio", Take::Nothing)], &settings());
    assert_eq!(states(&outcome), [State::Done], "{outcome:#?}");
    assert_eq!(mock.registered(AUDIO_RECEIVER)["subscription"], json!({"sender_id": null, "active": false}));

    let sdp = mock.facility.lock().unwrap().sdp[AUDIO_SENDER].replace("239.10.10.2", "239.99.0.2");
    let outcome =
        mock.connect(&[route("MON 1 audio", Take::Sdp { name: "studio-b.sdp".into(), text: sdp })], &settings());
    let connection = &outcome.connections[0];
    assert_eq!((connection.state, connection.sdp.as_deref()), (State::Done, Some("studio-b.sdp")), "{connection:#?}");
    assert_eq!(connection.describe_take(), "the SDP file studio-b.sdp");
    let active = mock.active(AUDIO_RECEIVER);
    assert_eq!(
        (active["sender_id"].clone(), active["transport_params"][0]["multicast_ip"].clone()),
        (Value::Null, json!("239.99.0.2"))
    );
    assert_eq!(mock.registered(AUDIO_RECEIVER)["subscription"], json!({"sender_id": null, "active": true}));
}

#[test]
fn a_lagging_registry_is_a_warning() {
    let mock = Mock::start(|f| f.faults.registry_lags = true);
    let outcome = mock.connect(
        &[route("MON 1 audio", sender("CAM 1 audio"))],
        &Settings { wait: Duration::from_millis(500), ..settings() },
    );
    let connection = &outcome.connections[0];
    assert_eq!(connection.state, State::Done);
    assert_eq!(
        connection.warnings,
        [format!(
            "after 0.5 s the registry does not show the change: its subscription names no sender rather than sender \
             {AUDIO_SENDER} and is inactive, and its version is still 1790510437:0. IS-05 requires the Node to update \
             the Receiver's subscription and version on every activation"
        )]
    );
    assert!(outcome.succeeded(), "the connection itself was made");
}

#[test]
fn a_later_activation_is_left_scheduled() {
    let mock = Mock::start(|_| {});
    let at = now().add_nanos(60_000_000_000).unwrap();
    let outcome = mock.connect(
        &[route("MON 1 audio", sender("CAM 1 audio"))],
        &Settings { activation: Some(Activation::At(at)), ..settings() },
    );
    let connection = &outcome.connections[0];
    assert_eq!(
        (connection.state, connection.activation_time.clone()),
        (State::Scheduled, Some(tai(at))),
        "{connection:#?}"
    );
    assert!(connection.warnings.is_empty(), "it staged what was asked");
    assert_eq!(mock.facility.lock().unwrap().receivers[AUDIO_RECEIVER].pending, Some(at));
    assert!(outcome.succeeded());

    // Until it is cancelled.
    let client = ConnectionClient::new(&Options { env_proxy: false, ..Options::default() });
    let cancelled = cancel(&mock.snapshot(), "MON 1 audio", &client).unwrap();
    assert_eq!((cancelled.was_due, cancelled.problem), (Some(tai(at)), None));
    assert_eq!(mock.facility.lock().unwrap().receivers[AUDIO_RECEIVER].pending, None);
    let again = cancel(&mock.snapshot(), "MON 1 audio", &client).unwrap();
    assert_eq!((again.was_due, again.problem), (None, None), "nothing was left to cancel");
    let refused = Mock::start(|f| f.faults.redirect_patch = true);
    let problem = cancel(&refused.snapshot(), "MON 1 audio", &client).unwrap().problem.unwrap();
    assert!(problem.starts_with("the Connection API refused it: HTTP 301"), "{problem}");
    assert_eq!(cancel(&mock.snapshot(), "MON 9", &client).unwrap_err(), "no receiver has the id or label MON 9");
}

#[test]
fn names_must_find_one_receiver_each() {
    let mock = Mock::start(|_| {});
    let client = ConnectionClient::new(&Options { env_proxy: false, ..Options::default() });
    let error = |routes: &[Route]| connect(&mock.snapshot(), routes, &client, None, &settings()).unwrap_err();
    assert_eq!(error(&[]), "no connection was asked for");
    assert_eq!(error(&[route("MON 9", Take::Nothing)]), "no receiver has the id or label MON 9");
    assert_eq!(error(&[route("MON 1 audio", sender("CAM 9"))]), "no sender has the id or label CAM 9");
    assert_eq!(
        error(&[route("MON 1 audio", Take::Nothing), route(AUDIO_RECEIVER, Take::Nothing)]),
        "receiver \"MON 1 audio\" (7ecf0002) is named twice, but takes one stream at a time"
    );
    assert!(mock.facility.lock().unwrap().log.is_empty(), "nothing was read");
}
