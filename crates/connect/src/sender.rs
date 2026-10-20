//! The `PATCH` that turns a Sender on or off or changes where it sends, and the check of
//! its `/active` endpoint afterwards.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::Activation;
use crate::constraints::{Constraints, same, show};

/// Where one leg of a Sender's stream goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// A multicast group, or the unicast address of the Receiver it sends to.
    pub ip: IpAddr,
    /// The UDP port; `None` leaves the Sender's own.
    pub port: Option<u16>,
}

impl Destination {
    /// Reads `239.10.1.1`, `239.10.1.1:5004`, `[ff3e::1]:5004` or `ff3e::1`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(Self { ip, port: None });
        }
        let (host, port) = text.rsplit_once(':').ok_or_else(|| format!("{text} is not an address"))?;
        let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        let ip = host.parse::<IpAddr>().map_err(|_| format!("{host} is not an IP address"))?;
        let port = port.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| format!("{port} is not a UDP port"))?;
        Ok(Self { ip, port: Some(port) })
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ip, self.port) {
            (IpAddr::V6(ip), Some(port)) => write!(f, "[{ip}]:{port}"),
            (ip, Some(port)) => write!(f, "{ip}:{port}"),
            (ip, None) => write!(f, "{ip}"),
        }
    }
}

/// What to change on a Sender.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderChange {
    /// Whether it sends: `master_enable`.
    pub enable: bool,
    /// Where each leg goes, path 1 first; empty leaves where it sends as it is. A leg
    /// past the last one given is turned off.
    pub destinations: Vec<Destination>,
    /// The Receiver a unicast Sender sends to, which the request names as its
    /// `receiver_id`; `None` with destinations sets it to `null`, as for multicast.
    pub receiver_id: Option<String>,
}

/// A change to a Sender: the request that makes it, and what to check afterwards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SenderPlan {
    /// The body to `PATCH` to the Sender's `/staged` endpoint.
    pub request: Value,
    /// What an operator should know, such as an ST 2022-7 leg turned off.
    pub notes: Vec<String>,
    /// Why the Sender would refuse the request, judged against its constraints.
    pub problems: Vec<String>,
}

impl SenderPlan {
    /// Plans a change to a Sender as IS-05 v1.2 asks of a controller (Controllers:
    /// Connection Management):
    ///
    /// - `master_enable` is set, with the destinations in the same request, so that a
    ///   Sender turned on sends where it is told from its first packet;
    /// - `receiver_id` names the Receiver a unicast Sender sends to, and is `null`
    ///   otherwise whenever the destinations change;
    /// - each leg given a destination has `rtp_enabled`, and a leg past the last one
    ///   given is turned off.
    ///
    /// `constraints` are the Sender's, from its `/constraints` endpoint. Values they do
    /// not allow are listed in [`SenderPlan::problems`]. Fails when more destinations are
    /// given than the Sender has legs.
    pub fn configure(change: &SenderChange, constraints: &Constraints, activation: Activation) -> Result<Self, String> {
        let wanted = constraints.legs.len();
        let given = change.destinations.len();
        if given > wanted {
            return Err(format!(
                "{given} destinations are given, but the Sender has {}",
                if wanted == 1 { "one leg".to_string() } else { format!("{wanted} legs") }
            ));
        }
        let mut request = json!({"master_enable": change.enable, "activation": activation.to_json()});
        let mut notes = Vec::new();
        let mut problems = Vec::new();
        if given > 0 || change.receiver_id.is_some() {
            request["receiver_id"] = json!(change.receiver_id);
        }
        if given > 0 {
            if given < wanted {
                notes.push(format!(
                    "{} given, so the Sender's {} turned off: it sends without ST 2022-7 protection",
                    if given == 1 { "one destination is".to_string() } else { format!("{given} destinations are") },
                    if wanted - given == 1 {
                        format!("leg {wanted} is")
                    } else {
                        format!("legs {} to {wanted} are", given + 1)
                    }
                ));
            }
            let mut params = Vec::with_capacity(wanted);
            for i in 0..wanted {
                let mut leg = Map::new();
                let mut set = |name: &str, value: Value| {
                    if let Some(why) = constraints.check(i, name, &value) {
                        problems.push(format!("leg {}: {why}", i + 1));
                    }
                    leg.insert(name.to_string(), value);
                };
                match change.destinations.get(i) {
                    Some(destination) => {
                        set("destination_ip", json!(destination.ip.to_string()));
                        if let Some(port) = destination.port {
                            set("destination_port", json!(port));
                        }
                        set("rtp_enabled", json!(true));
                    }
                    None => set("rtp_enabled", json!(false)),
                }
                params.push(Value::Object(leg));
            }
            request["transport_params"] = Value::Array(params);
        }
        Ok(Self { request, notes, problems })
    }

    /// Plans putting a Sender back as its `/active` endpoint showed it. Fails when
    /// `active` is not a Sender's `/active` resource.
    pub fn restore(active: &Value, activation: Activation) -> Result<Self, String> {
        let master_enable =
            active.get("master_enable").and_then(Value::as_bool).ok_or("the Sender's /active has no master_enable")?;
        let params = active
            .get("transport_params")
            .and_then(Value::as_array)
            .ok_or("the Sender's /active has no transport_params")?;
        let request = json!({
            "master_enable": master_enable,
            "receiver_id": active.get("receiver_id").cloned().unwrap_or(Value::Null),
            "activation": activation.to_json(),
            "transport_params": params,
        });
        Ok(Self { request, notes: Vec::new(), problems: Vec::new() })
    }

    /// Changes when the request takes effect.
    pub fn with_activation(mut self, activation: Activation) -> Self {
        self.request["activation"] = activation.to_json();
        self
    }

    /// Where a Sender's `/active` endpoint differs from what this plan asks for; empty
    /// when it shows the change took effect.
    pub fn verify(&self, active: &Value) -> Vec<String> {
        let mut problems = Vec::new();
        let mut differ = |at: &str, got: Option<&Value>, want: &Value| {
            if !got.is_some_and(|got| same(got, want)) {
                let got = got.map_or_else(|| "absent".to_string(), show);
                problems.push(format!("{at} is {got}, not {}", show(want)));
            }
        };
        for name in ["master_enable", "receiver_id"] {
            if let Some(want) = self.request.get(name) {
                differ(name, active.get(name), want);
            }
        }
        let params = active.get("transport_params").and_then(Value::as_array);
        for (i, want) in
            self.request.get("transport_params").and_then(Value::as_array).into_iter().flatten().enumerate()
        {
            let got = params.and_then(|p| p.get(i));
            for (name, value) in want.as_object().into_iter().flatten() {
                differ(&format!("leg {}: {name}", i + 1), got.and_then(|g| g.get(name)), value);
            }
        }
        problems
    }
}

/// Where a Sender's `/active` endpoint says each leg goes, path 1 first; `None` for a
/// leg that is off or has no address yet.
pub fn destinations(active: &Value) -> Vec<Option<Destination>> {
    let params = active.get("transport_params").and_then(Value::as_array);
    params
        .into_iter()
        .flatten()
        .map(|leg| {
            if leg.get("rtp_enabled") == Some(&Value::Bool(false)) {
                return None;
            }
            let ip = leg.get("destination_ip")?.as_str()?.parse::<IpAddr>().ok()?;
            let port = leg.get("destination_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok());
            Some(Destination { ip, port })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIVER: &str = "7ecf0001-0000-4000-8000-000000000001";

    fn sender(legs: usize) -> Constraints {
        let leg = json!({
            "source_ip": {"enum": ["192.168.10.21"]}, "destination_ip": {}, "source_port": {},
            "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}
        });
        Constraints::from_json(&Value::Array(vec![leg; legs])).unwrap()
    }

    fn to(text: &str) -> Destination {
        Destination::parse(text).unwrap()
    }

    #[test]
    fn destinations_parse() {
        assert_eq!(to("239.10.1.1"), Destination { ip: "239.10.1.1".parse().unwrap(), port: None });
        assert_eq!(to("239.10.1.1:5004").port, Some(5004));
        assert_eq!(to("[ff3e::1]:5004").to_string(), "[ff3e::1]:5004");
        assert_eq!(to("ff3e::1").to_string(), "ff3e::1");
        assert_eq!(Destination::parse("239.10.1.1:0").unwrap_err(), "0 is not a UDP port");
        assert_eq!(Destination::parse("camera:5004").unwrap_err(), "camera is not an IP address");
    }

    #[test]
    fn sends_a_pair_where_it_is_told_as_it_turns_on() {
        let change = SenderChange {
            enable: true,
            destinations: vec![to("239.10.9.1:5004"), to("239.20.9.1:5004")],
            receiver_id: None,
        };
        let plan = SenderPlan::configure(&change, &sender(2), Activation::Immediate).unwrap();
        assert_eq!(
            plan.request,
            json!({
                "master_enable": true,
                "receiver_id": null,
                "activation": {"mode": "activate_immediate", "requested_time": null},
                "transport_params": [
                    {"destination_ip": "239.10.9.1", "destination_port": 5004, "rtp_enabled": true},
                    {"destination_ip": "239.20.9.1", "destination_port": 5004, "rtp_enabled": true},
                ],
            })
        );
        assert!(plan.problems.is_empty() && plan.notes.is_empty());
    }

    #[test]
    fn a_unicast_sender_names_its_receiver() {
        let change =
            SenderChange { enable: true, destinations: vec![to("192.168.10.31")], receiver_id: Some(RECEIVER.into()) };
        let plan = SenderPlan::configure(&change, &sender(2), Activation::Immediate).unwrap();
        assert_eq!(plan.request["receiver_id"], RECEIVER);
        assert_eq!(
            plan.request["transport_params"][0],
            json!({"destination_ip": "192.168.10.31", "rtp_enabled": true})
        );
        assert_eq!(plan.request["transport_params"][1], json!({"rtp_enabled": false}));
        assert_eq!(
            plan.notes,
            ["one destination is given, so the Sender's leg 2 is turned off: it sends without ST 2022-7 protection"]
        );
    }

    #[test]
    fn turning_off_leaves_where_it_sends() {
        let change = SenderChange { enable: false, ..SenderChange::default() };
        let plan = SenderPlan::configure(&change, &sender(1), Activation::Immediate).unwrap();
        assert_eq!(
            plan.request,
            json!({"master_enable": false, "activation": {"mode": "activate_immediate", "requested_time": null}})
        );
        let active = json!({"master_enable": true, "receiver_id": null, "transport_params": [{"rtp_enabled": true}]});
        assert_eq!(plan.verify(&active), ["master_enable is true, not false"]);
        assert_eq!(plan.verify(&json!({"master_enable": false})), Vec::<String>::new());
    }

    #[test]
    fn constraints_and_legs_are_checked() {
        let change = SenderChange { enable: true, destinations: vec![to("239.10.9.1:7000")], receiver_id: None };
        let plan = SenderPlan::configure(&change, &sender(1), Activation::Immediate).unwrap();
        assert_eq!(plan.problems, ["leg 1: destination_port 7000 is above the maximum, 5999"]);
        let change = SenderChange { destinations: vec![to("239.10.9.1"), to("239.20.9.1")], ..change };
        assert_eq!(
            SenderPlan::configure(&change, &sender(1), Activation::Immediate).unwrap_err(),
            "2 destinations are given, but the Sender has one leg"
        );
    }

    #[test]
    fn verifies_and_restores_from_active() {
        let active = json!({
            "master_enable": true, "receiver_id": null,
            "transport_params": [{"source_ip": "192.168.10.21", "destination_ip": "239.10.9.1", "source_port": 5004,
                                  "destination_port": 5004, "rtp_enabled": true}],
        });
        let change = SenderChange { enable: true, destinations: vec![to("239.10.9.1:5004")], receiver_id: None };
        let plan = SenderPlan::configure(&change, &sender(1), Activation::Immediate).unwrap();
        assert_eq!(plan.verify(&active), Vec::<String>::new());
        let elsewhere = SenderChange { destinations: vec![to("239.10.9.2")], ..change };
        let plan = SenderPlan::configure(&elsewhere, &sender(1), Activation::Immediate).unwrap();
        assert_eq!(plan.verify(&active), ["leg 1: destination_ip is 239.10.9.1, not 239.10.9.2"]);
        let restore = SenderPlan::restore(&active, Activation::Immediate).unwrap();
        assert_eq!(restore.request["transport_params"], active["transport_params"]);
        assert_eq!(restore.verify(&active), Vec::<String>::new());
        assert_eq!(destinations(&active), [Some(to("239.10.9.1:5004"))]);
    }
}
