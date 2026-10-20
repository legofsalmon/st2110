//! An IS-05 Connection API: each Sender's and Receiver's constraints, staged and active
//! parameters, staged, scheduled and activated as IS-05 v1.2 describes. The demo
//! facility of `st2110 router --demo` serves one for each of its Nodes, and `st2110
//! send --nmos` and `st2110 receive --nmos` serve their own.
//!
//! What an activation does is left to whoever holds the endpoints ([`Control`]): the
//! demo tells its registry and its streams, and a Node of its own starts, stops or
//! moves the stream it sends or receives.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde_json::{Value, json};
use st2110_ptp::PtpTime;

use crate::http::Response;

/// A time as IS-05 and IS-04 write it: `<seconds>:<nanoseconds>` of TAI.
pub(crate) fn tai(time: PtpTime) -> String {
    format!("{}:{}", time.seconds(), time.subsec_nanos())
}

/// An IS-05 error response: the status, and its body.
pub(crate) fn error(code: u16, message: &str, debug: &str) -> (u16, Value) {
    (code, json!({"code": code, "error": message, "debug": debug}))
}

/// The `activation` of parameters that are not to be activated.
fn no_activation() -> Value {
    json!({"mode": null, "requested_time": null, "activation_time": null})
}

/// Which side of a connection: the Connection API's `senders` or `receivers`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Sender,
    Receiver,
}

impl Side {
    pub(crate) fn plural(self) -> &'static str {
        match self {
            Self::Sender => "senders",
            Self::Receiver => "receivers",
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sender => "Sender",
            Self::Receiver => "Receiver",
        }
    }

    /// What a request may change besides the transport parameters.
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Sender => &["receiver_id", "master_enable"],
            Self::Receiver => &["sender_id", "master_enable", "transport_file"],
        }
    }

    /// The parameter `auto` stands for an interface's address in.
    fn interface(self) -> &'static str {
        match self {
            Self::Sender => "source_ip",
            Self::Receiver => "interface_ip",
        }
    }
}

/// One Sender's or Receiver's IS-05 resources.
pub(crate) struct Endpoint {
    pub constraints: Value,
    pub staged: Value,
    pub active: Value,
    /// When a scheduled activation is due.
    pub pending: Option<PtpTime>,
}

impl Endpoint {
    /// A Sender's resources: each leg from `sources[i]`, as `params[i]` says.
    pub(crate) fn sender(constraints: Vec<Value>, params: Vec<Value>, enabled: bool) -> Self {
        let active = json!({
            "receiver_id": null, "master_enable": enabled, "activation": no_activation(),
            "transport_params": params,
        });
        Self { constraints: Value::Array(constraints), staged: active.clone(), active, pending: None }
    }

    /// A Receiver's resources, taking nothing, on `interfaces`, one for each leg.
    pub(crate) fn idle_receiver(interfaces: &[String], constraints: Vec<Value>) -> Self {
        let legs: Vec<Value> = interfaces
            .iter()
            .map(|i| json!({"source_ip": null, "multicast_ip": null, "interface_ip": i, "destination_port": 5004, "rtp_enabled": true}))
            .collect();
        let idle = json!({
            "sender_id": null, "master_enable": false, "activation": no_activation(),
            "transport_file": {"data": null, "type": null},
            "transport_params": legs,
        });
        Self { constraints: Value::Array(constraints), staged: idle.clone(), active: idle, pending: None }
    }

    /// How many legs it has.
    pub(crate) fn legs(&self) -> usize {
        self.constraints.as_array().map_or(0, Vec::len)
    }
}

/// Whoever holds the endpoints, and makes their activations take effect.
pub(crate) trait Control {
    fn endpoints(&mut self, side: Side) -> &mut BTreeMap<String, Endpoint>;

    /// The time now, in TAI.
    fn now(&self) -> PtpTime;

    /// Whether parameters staged for a Sender or Receiver could be activated: an `Err`
    /// says why not, and the request is refused, leaving what was staged before.
    fn check(&self, _side: Side, _id: &str, _staged: &Value) -> Result<(), String> {
        Ok(())
    }

    /// Makes what a Sender or Receiver was just told to do at `at` take effect, and may
    /// fill in its `/active` parameters, such as the port it sends from.
    fn activated(&mut self, side: Side, id: &str, at: PtpTime);

    /// A Sender's transport file: its SDP file.
    fn transport_file(&self, id: &str) -> Option<String>;

    /// A Sender's or Receiver's transport, such as `urn:x-nmos:transport:rtp.mcast`.
    fn transport_type(&self, side: Side, id: &str) -> Option<String>;

    /// Notes that a request may have changed something.
    fn touched(&mut self) {}
}

/// Answers a request to a Connection API, from the path after its version, such as
/// `single/receivers/<id>/staged`.
pub(crate) fn route(control: &mut impl Control, method: &str, rest: &str, body: &Value) -> Response {
    let rest = rest.trim_matches('/');
    if let Some(id) = rest.strip_prefix("single/senders/").and_then(|r| r.strip_suffix("/transportfile")) {
        let (status, body) = match control.transport_file(id) {
            Some(sdp) if method == "GET" => {
                return Response {
                    status: 200,
                    content_type: "application/sdp",
                    headers: Vec::new(),
                    body: sdp.into_bytes(),
                };
            }
            Some(_) => error(405, "Method Not Allowed", ""),
            None => error(404, "Not Found", "no such Sender"),
        };
        return Response::json(status, &body);
    }
    let (status, body) = answer(control, method, rest, body);
    Response::json(status, &body)
}

/// Answers a request to a Connection API, but for a transport file, with JSON.
fn answer(control: &mut impl Control, method: &str, rest: &str, body: &Value) -> (u16, Value) {
    match rest {
        "" => return listing(method, json!(["bulk/", "single/"])),
        "single" => return listing(method, json!(["senders/", "receivers/"])),
        "bulk" => return listing(method, json!(["senders/", "receivers/"])),
        _ => {}
    }
    for side in [Side::Sender, Side::Receiver] {
        if rest == format!("single/{}", side.plural()) {
            let ids: Vec<String> = control.endpoints(side).keys().map(|id| format!("{id}/")).collect();
            return listing(method, json!(ids));
        }
        if rest == format!("bulk/{}", side.plural()) {
            if method != "POST" {
                return error(405, "Method Not Allowed", "");
            }
            let Some(items) = body.as_array() else {
                return error(400, "Bad Request", "a bulk request is an array");
            };
            control.touched();
            let results = items
                .iter()
                .map(|item| {
                    let id = item["id"].as_str().unwrap_or_default();
                    let (code, response) = if control.endpoints(side).contains_key(id) {
                        stage(control, side, id, &item["params"])
                    } else {
                        error(404, "Not Found", &format!("no such {}", side.name()))
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
        let Some(after) = rest.strip_prefix(&format!("single/{}/", side.plural())) else {
            continue;
        };
        let (id, resource) = after.split_once('/').unwrap_or((after, ""));
        let transport_type = control.transport_type(side, id);
        let Some(endpoint) = control.endpoints(side).get(id) else {
            return error(404, "Not Found", &format!("no such {}", side.name()));
        };
        return match (method, resource) {
            ("GET", "") => {
                let mut list = vec!["constraints/", "staged/", "active/", "transporttype/"];
                if side == Side::Sender {
                    list.push("transportfile/");
                }
                (200, json!(list))
            }
            ("GET", "constraints") => (200, endpoint.constraints.clone()),
            ("GET", "staged") => (200, endpoint.staged.clone()),
            ("GET", "active") => (200, endpoint.active.clone()),
            ("GET", "transporttype") => match transport_type {
                Some(transport) => (200, json!(transport)),
                None => error(404, "Not Found", "no transport type"),
            },
            ("PATCH", "staged") => {
                control.touched();
                stage(control, side, id, body)
            }
            _ => error(405, "Method Not Allowed", ""),
        };
    }
    error(404, "Not Found", rest)
}

/// A list of paths, for `GET` only.
fn listing(method: &str, list: Value) -> (u16, Value) {
    if method == "GET" { (200, list) } else { error(405, "Method Not Allowed", "") }
}

/// What a `PATCH` to `/staged` does: stages what it gives, after checking it against
/// the constraints and with [`Control::check`], and activates it now, later or not at
/// all, as it asks.
pub(crate) fn stage(control: &mut impl Control, side: Side, id: &str, body: &Value) -> (u16, Value) {
    let now = control.now();
    let Some(endpoint) = control.endpoints(side).get(id) else {
        return error(404, "Not Found", &format!("no such {}", side.name()));
    };
    let mode = body.get("activation").map(|a| &a["mode"]);
    if endpoint.pending.is_some() && mode != Some(&Value::Null) {
        return error(423, "Locked", "an activation is scheduled");
    }
    let mut staged = endpoint.staged.clone();
    if let Some(params) = body.get("transport_params") {
        let legs = endpoint.constraints.as_array().cloned().unwrap_or_default();
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
                // The streams go to IPv4 addresses.
                if name == "destination_ip" && value.as_str().and_then(|v| v.parse::<Ipv4Addr>().ok()).is_none() {
                    return error(
                        400,
                        "Constraint violation",
                        &format!("leg {leg}: this Sender sends to IPv4 addresses only, not {value}"),
                    );
                }
            }
        }
        let legs = staged["transport_params"].as_array_mut().expect("legs");
        for (staged, params) in legs.iter_mut().zip(params) {
            for (name, value) in params.as_object().into_iter().flatten() {
                staged[name] = value.clone();
            }
        }
    }
    for field in side.fields() {
        if let Some(value) = body.get(*field) {
            staged[*field] = value.clone();
        }
    }
    if let Err(why) = control.check(side, id, &staged) {
        return error(400, "Bad Request", &why);
    }
    let requested = body["activation"]["requested_time"].as_str().and_then(PtpTime::parse);
    let immediate = match mode.and_then(Value::as_str) {
        Some("activate_immediate") => true,
        Some(mode @ ("activate_scheduled_absolute" | "activate_scheduled_relative")) => {
            let Some(requested) = requested else {
                return error(400, "Bad Request", "a scheduled activation needs a requested_time");
            };
            let due = if mode == "activate_scheduled_absolute" {
                requested
            } else {
                now.add_nanos(requested.nanos()).unwrap_or(now)
            };
            staged["activation"] = json!({
                "mode": mode, "requested_time": body["activation"]["requested_time"], "activation_time": tai(due),
            });
            let endpoint = control.endpoints(side).get_mut(id).expect("a known Sender or Receiver");
            endpoint.staged = staged;
            endpoint.pending = Some(due);
            return (202, endpoint.staged.clone());
        }
        Some(other) => return error(400, "Bad Request", &format!("no activation mode {other}")),
        None => false,
    };
    let endpoint = control.endpoints(side).get_mut(id).expect("a known Sender or Receiver");
    if mode.is_some() {
        // `mode: null` cancels what was scheduled.
        endpoint.pending = None;
        staged["activation"] = no_activation();
    }
    endpoint.staged = staged;
    if immediate {
        activate(control, side, id, now);
        let mut response = control.endpoints(side)[id].staged.clone();
        response["activation"] =
            json!({"mode": "activate_immediate", "requested_time": null, "activation_time": tai(now)});
        return (200, response);
    }
    (200, control.endpoints(side)[id].staged.clone())
}

/// Makes what is staged active, at `at`, resolving `auto` interfaces, and has it take
/// effect.
pub(crate) fn activate(control: &mut impl Control, side: Side, id: &str, at: PtpTime) {
    let endpoint = control.endpoints(side).get_mut(id).expect("a known Sender or Receiver");
    let mut active = endpoint.staged.clone();
    let legs = endpoint.constraints.as_array().cloned().unwrap_or_default();
    let interface = side.interface();
    for (leg, constraints) in active["transport_params"].as_array_mut().into_iter().flatten().zip(&legs) {
        if leg[interface] == "auto" {
            // The constraint's one address besides `auto`.
            let address = constraints[interface]["enum"].as_array().into_iter().flatten().find(|a| *a != "auto");
            leg[interface] = address.cloned().unwrap_or(Value::Null);
        }
    }
    active["activation"] = json!({
        "mode": endpoint.staged["activation"]["mode"].as_str().unwrap_or("activate_immediate"),
        "requested_time": endpoint.staged["activation"]["requested_time"],
        "activation_time": tai(at),
    });
    endpoint.active = active;
    endpoint.pending = None;
    endpoint.staged["activation"] = no_activation();
    control.activated(side, id, at);
}

/// Carries out the scheduled activations that are due.
pub(crate) fn settle(control: &mut impl Control) {
    let now = control.now();
    for side in [Side::Sender, Side::Receiver] {
        let due: Vec<(String, PtpTime)> = control
            .endpoints(side)
            .iter()
            .filter_map(|(id, e)| e.pending.filter(|&due| due <= now).map(|due| (id.clone(), due)))
            .collect();
        for (id, due) in due {
            activate(control, side, &id, due);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One Receiver, whose activations are counted.
    struct One {
        receivers: BTreeMap<String, Endpoint>,
        senders: BTreeMap<String, Endpoint>,
        now: PtpTime,
        activations: Vec<String>,
    }

    impl Control for One {
        fn endpoints(&mut self, side: Side) -> &mut BTreeMap<String, Endpoint> {
            match side {
                Side::Sender => &mut self.senders,
                Side::Receiver => &mut self.receivers,
            }
        }

        fn now(&self) -> PtpTime {
            self.now
        }

        fn check(&self, _: Side, _: &str, staged: &Value) -> Result<(), String> {
            match staged["transport_file"]["data"].as_str() {
                Some(sdp) if !sdp.starts_with("v=0") => Err("not an SDP file".into()),
                _ => Ok(()),
            }
        }

        fn activated(&mut self, _: Side, id: &str, _: PtpTime) {
            self.activations.push(id.into());
        }

        fn transport_file(&self, _: &str) -> Option<String> {
            None
        }

        fn transport_type(&self, _: Side, _: &str) -> Option<String> {
            Some("urn:x-nmos:transport:rtp".into())
        }
    }

    fn one() -> One {
        let interfaces = vec!["192.168.10.31".to_string()];
        let constraints =
            vec![json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["auto", "192.168.10.31"]},
                                      "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}})];
        One {
            receivers: BTreeMap::from([("r".to_string(), Endpoint::idle_receiver(&interfaces, constraints))]),
            senders: BTreeMap::new(),
            now: PtpTime::from_utc(1_790_510_400, 0).unwrap(),
            activations: Vec::new(),
        }
    }

    #[test]
    fn stages_activates_and_schedules() {
        let mut one = one();
        let (code, _) = answer(&mut one, "PATCH", "single/receivers/r/staged", &json!({"master_enable": true}));
        assert_eq!((code, one.activations.len()), (200, 0));
        let body = json!({"transport_params": [{"interface_ip": "auto", "destination_port": 5006}],
                          "activation": {"mode": "activate_immediate"}});
        let (code, response) = answer(&mut one, "PATCH", "single/receivers/r/staged", &body);
        assert_eq!((code, one.activations.len()), (200, 1), "{response}");
        let active = &one.receivers["r"].active;
        assert_eq!(active["transport_params"][0]["interface_ip"], "192.168.10.31");
        assert_eq!(active["transport_params"][0]["destination_port"], 5006);
        assert_eq!(active["master_enable"], true);
        // Out of range, and not an SDP file: refused, and nothing staged.
        let (code, _) = answer(
            &mut one,
            "PATCH",
            "single/receivers/r/staged",
            &json!({"transport_params": [{"destination_port": 80}]}),
        );
        assert_eq!(code, 400);
        let (code, _) = answer(
            &mut one,
            "PATCH",
            "single/receivers/r/staged",
            &json!({"transport_file": {"data": "nonsense", "type": "application/sdp"}}),
        );
        assert_eq!(code, 400);
        assert_eq!(one.receivers["r"].staged["transport_file"]["data"], Value::Null);
        // Scheduled a second ahead: locked until it is done or cancelled.
        let body = json!({"master_enable": false, "activation": {"mode": "activate_scheduled_relative", "requested_time": "1:0"}});
        assert_eq!(answer(&mut one, "PATCH", "single/receivers/r/staged", &body).0, 202);
        assert_eq!(answer(&mut one, "PATCH", "single/receivers/r/staged", &json!({"master_enable": true})).0, 423);
        settle(&mut one);
        assert_eq!(one.activations.len(), 1);
        one.now = one.now.add_nanos(1_000_000_000).unwrap();
        settle(&mut one);
        assert_eq!(one.activations.len(), 2);
        assert_eq!(one.receivers["r"].active["master_enable"], false);
        assert_eq!(
            answer(&mut one, "GET", "single/receivers/r/transporttype", &Value::Null).1,
            "urn:x-nmos:transport:rtp"
        );
        assert_eq!(answer(&mut one, "GET", "single/receivers", &Value::Null).1, json!(["r/"]));
        assert_eq!(answer(&mut one, "GET", "single/receivers/x/active", &Value::Null).0, 404);
    }
}
