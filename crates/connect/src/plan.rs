//! The `PATCH` that connects or disconnects a Receiver, and the check of its `/active`
//! endpoint afterwards.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use st2110_ptp::PtpTime;

use crate::constraints::{Constraints, same, show};
use crate::legs::{Leg, legs};

/// Nanoseconds in a second.
const NANOS: u64 = 1_000_000_000;

/// When a staged change takes effect (IS-05 v1.2 activation-schema.json).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    /// As soon as the Connection API has the request.
    Immediate,
    /// At a PTP time, when the Device's clock reaches it: how a salvo switches together.
    At(PtpTime),
    /// This many nanoseconds after the Connection API has the request.
    After(u64),
}

impl Activation {
    /// The `activation` object of a request.
    pub fn to_json(self) -> Value {
        match self {
            Self::Immediate => json!({"mode": "activate_immediate", "requested_time": null}),
            Self::At(time) => json!({"mode": "activate_scheduled_absolute", "requested_time": tai(time)}),
            Self::After(nanos) => json!({
                "mode": "activate_scheduled_relative",
                "requested_time": format!("{}:{}", nanos / NANOS, nanos % NANOS),
            }),
        }
    }

    /// Whether the change waits for a time.
    pub fn is_scheduled(self) -> bool {
        self != Self::Immediate
    }
}

/// A PTP time as NMOS writes a TAI timestamp: `<seconds>:<nanoseconds>`.
pub fn tai(time: PtpTime) -> String {
    format!("{}:{}", time.seconds(), time.subsec_nanos())
}

/// What a Receiver's `/active` endpoint should show once a change takes effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expect {
    /// The Sender it takes its stream from; `None` for a stream from outside NMOS, or none.
    pub sender_id: Option<String>,
    /// Whether it is on.
    pub master_enable: bool,
    /// For each of its legs, the stream it receives, or `None` for a leg that is off. Empty
    /// when the legs are not checked, as after a disconnection.
    pub legs: Vec<Option<Leg>>,
}

/// A change to a Receiver: the request that makes it, and what the Receiver should
/// show afterwards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    /// The body to `PATCH` to the Receiver's `/staged` endpoint, or to send as its
    /// `params` in a `/bulk/receivers` request.
    pub request: Value,
    /// What its `/active` endpoint should show once the change takes effect.
    pub expect: Expect,
    /// What an operator should know, such as an ST 2022-7 leg that goes unused.
    pub notes: Vec<String>,
    /// Why the Receiver would refuse the request, judged against its constraints.
    pub problems: Vec<String>,
}

impl Plan {
    /// Plans connecting a Receiver to the stream an SDP file describes, as IS-05 v1.2
    /// asks of a controller (Controllers: Connection Management, and Behaviour: RTP
    /// Transport Type):
    ///
    /// - the SDP file goes in `transport_file`, and each leg's address, port and source
    ///   in `transport_params` too, so that the Receiver needs nothing else;
    /// - `sender_id` names the Sender, or is `null` for a stream from outside NMOS;
    /// - `master_enable` and every leg's `rtp_enabled` are set, whatever they were;
    /// - a Receiver with a leg more than the stream has that leg turned off, and one
    ///   with a leg fewer joins path 1 only.
    ///
    /// `constraints` are the Receiver's, from its `/constraints` endpoint. Values they
    /// do not allow are listed in [`Plan::problems`], as the Receiver would refuse them.
    /// Fails when the SDP file describes no stream to receive, or the Receiver has no legs.
    pub fn connect(
        sdp: &str,
        sender_id: Option<&str>,
        constraints: &Constraints,
        activation: Activation,
    ) -> Result<Self, String> {
        let stream = legs(sdp)?;
        let wanted = constraints.legs.len();
        if wanted == 0 {
            return Err("the Receiver's constraints list no legs".into());
        }
        let mut notes = stream.notes;
        let mut problems = Vec::new();
        let have = stream.legs.len();
        if have > wanted {
            notes.push(format!(
                "the stream has {have} legs (ST 2022-7), but the Receiver takes {wanted}: it joins {} only, \
                 without the protection of the others",
                if wanted == 1 { "path 1".to_string() } else { format!("paths 1 to {wanted}") }
            ));
        } else if have < wanted {
            notes.push(format!(
                "the stream has {}, so the Receiver's {} turned off: it has no ST 2022-7 protection",
                if have == 1 { "one leg".to_string() } else { format!("{have} legs") },
                if wanted - have == 1 {
                    format!("leg {wanted} is")
                } else {
                    format!("legs {} to {wanted} are", have + 1)
                }
            ));
        }
        let mut params = Vec::with_capacity(wanted);
        let mut expect = Vec::with_capacity(wanted);
        for i in 0..wanted {
            let mut leg_params = Map::new();
            let mut check = |name: &str, value: Value, problems: &mut Vec<String>| {
                if let Some(why) = constraints.check(i, name, &value) {
                    problems.push(format!("leg {}: {why}", i + 1));
                }
                leg_params.insert(name.to_string(), value);
            };
            match stream.legs.get(i) {
                Some(leg) => {
                    if leg.multicast && !constraints.has(i, "multicast_ip") {
                        problems.push(format!(
                            "leg {}: the stream goes to multicast group {}, but the Receiver has no multicast_ip \
                             parameter, so it cannot join one",
                            i + 1,
                            leg.destination
                        ));
                    }
                    if constraints.has(i, "multicast_ip") {
                        check(
                            "multicast_ip",
                            if leg.multicast { json!(leg.destination) } else { Value::Null },
                            &mut problems,
                        );
                    }
                    if !leg.multicast {
                        // The stream goes to the Receiver's own address, which is the
                        // interface to receive it on; IS-05 leaves `auto` undefined here.
                        let interface = json!(leg.destination);
                        match constraints.legs[i].get("interface_ip").and_then(|c| c.check(&interface)) {
                            Some(_) => problems.push(format!(
                                "leg {}: the stream goes to {}, which is not one of the Receiver's interfaces",
                                i + 1,
                                leg.destination
                            )),
                            None => check("interface_ip", interface, &mut problems),
                        }
                    }
                    check("source_ip", leg.source_ip.as_deref().map_or(Value::Null, |s| json!(s)), &mut problems);
                    check("destination_port", json!(leg.destination_port), &mut problems);
                    check("rtp_enabled", json!(true), &mut problems);
                    expect.push(Some(leg.clone()));
                }
                None => {
                    check("rtp_enabled", json!(false), &mut problems);
                    expect.push(None);
                }
            }
            params.push(Value::Object(leg_params));
        }
        let request = json!({
            "sender_id": sender_id,
            "master_enable": true,
            "activation": activation.to_json(),
            "transport_file": {"data": sdp, "type": "application/sdp"},
            "transport_params": params,
        });
        let expect = Expect { sender_id: sender_id.map(str::to_string), master_enable: true, legs: expect };
        Ok(Self { request, expect, notes, problems })
    }

    /// Plans disconnecting a Receiver: turning it off, and naming no Sender (IS-05 v1.2
    /// Controllers: Connection Management).
    pub fn disconnect(activation: Activation) -> Self {
        Self {
            request: json!({"sender_id": null, "master_enable": false, "activation": activation.to_json()}),
            expect: Expect { sender_id: None, master_enable: false, legs: Vec::new() },
            notes: Vec::new(),
            problems: Vec::new(),
        }
    }

    /// Plans putting a Receiver back as its `/active` endpoint showed it, as a controller
    /// does when a salvo it was part of fails (IS-05 v1.2 APIs: Client Side
    /// Implementation Notes, Failure Modes). Fails when `active` is not a Receiver's
    /// `/active` resource.
    pub fn restore(active: &Value, activation: Activation) -> Result<Self, String> {
        let master_enable = active
            .get("master_enable")
            .and_then(Value::as_bool)
            .ok_or("the Receiver's /active has no master_enable")?;
        let sender_id = active.get("sender_id").and_then(Value::as_str);
        let params = active
            .get("transport_params")
            .and_then(Value::as_array)
            .ok_or("the Receiver's /active has no transport_params")?;
        let mut request = json!({
            "sender_id": sender_id,
            "master_enable": master_enable,
            "activation": activation.to_json(),
            "transport_params": params,
        });
        // The file goes back too, or none when it had none: a file left staged would
        // still apply its media parameters.
        request["transport_file"] = match active.get("transport_file") {
            Some(file)
                if file.get("data").is_some_and(Value::is_string) && file.get("type").is_some_and(Value::is_string) =>
            {
                json!({"data": file["data"], "type": file["type"]})
            }
            _ => json!({"data": null, "type": null}),
        };
        let expect = Expect { sender_id: sender_id.map(str::to_string), master_enable, legs: Vec::new() };
        Ok(Self { request, expect, notes: Vec::new(), problems: Vec::new() })
    }

    /// Changes when the request takes effect.
    pub fn with_activation(mut self, activation: Activation) -> Self {
        self.request["activation"] = activation.to_json();
        self
    }

    /// Where a Receiver's `/active` endpoint differs from what this plan asks for; empty
    /// when it shows the change took effect.
    pub fn verify(&self, active: &Value) -> Vec<String> {
        let mut problems = Vec::new();
        let expect = &self.expect;
        let master = active.get("master_enable");
        if master.and_then(Value::as_bool) != Some(expect.master_enable) {
            problems.push(format!("master_enable is {}, not {}", shown(master), expect.master_enable));
        }
        let sender = active.get("sender_id");
        let same_sender = match (sender.and_then(Value::as_str), &expect.sender_id) {
            (Some(got), Some(want)) => got.eq_ignore_ascii_case(want),
            (None, None) => sender.is_none_or(Value::is_null),
            _ => false,
        };
        if !same_sender {
            let want = expect.sender_id.as_deref().unwrap_or("null");
            problems.push(format!("sender_id is {}, not {want}", shown(sender)));
        }
        let params = active.get("transport_params").and_then(Value::as_array);
        for (i, want) in expect.legs.iter().enumerate() {
            let n = i + 1;
            let Some(got) = params.and_then(|p| p.get(i)) else {
                problems.push(format!("it shows no leg {n}"));
                continue;
            };
            let mut differ = |name: &str, want: Value| {
                let value = got.get(name);
                if !value.is_some_and(|v| same(v, &want)) {
                    problems.push(format!("leg {n}: {name} is {}, not {}", shown(value), show(&want)));
                }
            };
            let Some(leg) = want else {
                differ("rtp_enabled", json!(false));
                continue;
            };
            differ("rtp_enabled", json!(true));
            if leg.multicast {
                differ("multicast_ip", json!(leg.destination));
            } else {
                differ("interface_ip", json!(leg.destination));
                // A unicast leg has no group; a Receiver without the parameter shows none.
                if got.get("multicast_ip").is_some_and(|v| !v.is_null()) {
                    differ("multicast_ip", Value::Null);
                }
            }
            differ("source_ip", leg.source_ip.as_deref().map_or(Value::Null, |s| json!(s)));
            differ("destination_port", json!(leg.destination_port));
        }
        problems
    }
}

/// A value from `/active` as a message shows it, `absent` when it is missing.
fn shown(value: Option<&Value>) -> String {
    value.map_or_else(|| "absent".into(), show)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUP_SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=CAM 1 video\r\nt=0 0\r\n\
        a=group:DUP primary secondary\r\n\
        m=video 5004 RTP/AVP 96\r\nc=IN IP4 239.10.10.1/32\r\n\
        a=source-filter: incl IN IP4 239.10.10.1 192.168.10.21\r\na=rtpmap:96 raw/90000\r\na=mid:primary\r\n\
        m=video 5004 RTP/AVP 96\r\nc=IN IP4 239.20.10.1/32\r\n\
        a=source-filter: incl IN IP4 239.20.10.1 192.168.20.21\r\na=rtpmap:96 raw/90000\r\na=mid:secondary\r\n";
    const SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";

    fn receiver(legs: usize) -> Constraints {
        let leg = json!({
            "source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["192.168.10.31", "192.168.20.31"]},
            "destination_port": {"minimum": 5000, "maximum": 5999}, "rtp_enabled": {}
        });
        Constraints::from_json(&Value::Array(vec![leg; legs])).unwrap()
    }

    fn one_leg(sdp: &str) -> String {
        let end = sdp.find("m=video 5004 RTP/AVP 96\r\nc=IN IP4 239.20").unwrap();
        sdp[..end].replace("a=group:DUP primary secondary\r\n", "")
    }

    #[test]
    fn connects_both_legs_of_a_pair() {
        let plan = Plan::connect(DUP_SDP, Some(SENDER), &receiver(2), Activation::Immediate).unwrap();
        assert_eq!(
            plan.request,
            json!({
                "sender_id": SENDER,
                "master_enable": true,
                "activation": {"mode": "activate_immediate", "requested_time": null},
                "transport_file": {"data": DUP_SDP, "type": "application/sdp"},
                "transport_params": [
                    {"multicast_ip": "239.10.10.1", "source_ip": "192.168.10.21", "destination_port": 5004, "rtp_enabled": true},
                    {"multicast_ip": "239.20.10.1", "source_ip": "192.168.20.21", "destination_port": 5004, "rtp_enabled": true},
                ],
            })
        );
        assert!(plan.notes.is_empty() && plan.problems.is_empty(), "{plan:#?}");
        assert_eq!(plan.expect.legs.len(), 2);
    }

    #[test]
    fn matches_legs_to_the_receiver() {
        // A pair to a Receiver with one leg: path 1 only.
        let plan = Plan::connect(DUP_SDP, Some(SENDER), &receiver(1), Activation::Immediate).unwrap();
        assert_eq!(plan.request["transport_params"].as_array().unwrap().len(), 1);
        assert_eq!(
            plan.notes,
            ["the stream has 2 legs (ST 2022-7), but the Receiver takes 1: it joins path 1 only, without the \
              protection of the others"]
        );
        // One leg to an ST 2022-7 Receiver: leg 2 off, and said so.
        let plan = Plan::connect(&one_leg(DUP_SDP), None, &receiver(2), Activation::Immediate).unwrap();
        assert_eq!(plan.request["transport_params"][1], json!({"rtp_enabled": false}));
        assert_eq!(plan.request["sender_id"], Value::Null, "a stream from outside NMOS names no Sender");
        assert_eq!(
            plan.notes,
            ["the stream has one leg, so the Receiver's leg 2 is turned off: it has no ST 2022-7 protection"]
        );
        assert_eq!(plan.expect.legs[1], None);
    }

    #[test]
    fn lists_what_the_constraints_refuse() {
        let sdp = DUP_SDP.replace("m=video 5004", "m=video 6004");
        let mut constraints = receiver(2);
        constraints.legs[1].remove("multicast_ip");
        constraints.legs[1].get_mut("rtp_enabled").unwrap().values = Some(vec![json!(false)]);
        let plan = Plan::connect(&sdp, Some(SENDER), &constraints, Activation::Immediate).unwrap();
        assert_eq!(
            plan.problems,
            [
                "leg 1: destination_port 6004 is above the maximum, 5999",
                "leg 2: the stream goes to multicast group 239.20.10.1, but the Receiver has no multicast_ip \
                 parameter, so it cannot join one",
                "leg 2: destination_port 6004 is above the maximum, 5999",
                "leg 2: rtp_enabled true is not one of false",
            ]
        );
        assert!(plan.request["transport_params"][1].get("multicast_ip").is_none());
    }

    #[test]
    fn unicast_goes_to_one_of_the_receivers_interfaces() {
        let unicast = |address: &str| {
            format!(
                "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=x\r\nt=0 0\r\nm=video 5004 RTP/AVP 96\r\n\
                 c=IN IP4 {address}\r\na=rtpmap:96 raw/90000\r\n"
            )
        };
        let plan = Plan::connect(&unicast("192.168.10.31"), None, &receiver(1), Activation::Immediate).unwrap();
        assert_eq!(
            plan.request["transport_params"][0],
            json!({"multicast_ip": null, "interface_ip": "192.168.10.31", "source_ip": null, "destination_port": 5004, "rtp_enabled": true})
        );
        assert!(plan.problems.is_empty());
        let plan = Plan::connect(&unicast("192.168.10.99"), None, &receiver(1), Activation::Immediate).unwrap();
        assert_eq!(
            plan.problems,
            ["leg 1: the stream goes to 192.168.10.99, which is not one of the Receiver's interfaces"]
        );
    }

    #[test]
    fn activations_are_written_as_nmos_does() {
        let at = PtpTime::parse("1790510439:5").unwrap();
        assert_eq!(
            Activation::At(at).to_json(),
            json!({"mode": "activate_scheduled_absolute", "requested_time": "1790510439:5"})
        );
        assert_eq!(
            Activation::After(2_500_000_000).to_json(),
            json!({"mode": "activate_scheduled_relative", "requested_time": "2:500000000"})
        );
        let plan = Plan::disconnect(Activation::Immediate).with_activation(Activation::At(at));
        assert_eq!(
            plan.request,
            json!({"sender_id": null, "master_enable": false,
                   "activation": {"mode": "activate_scheduled_absolute", "requested_time": "1790510439:5"}})
        );
        assert!(Activation::After(0).is_scheduled() && !Activation::Immediate.is_scheduled());
    }

    #[test]
    fn verifies_what_active_shows() {
        let plan = Plan::connect(DUP_SDP, Some(SENDER), &receiver(2), Activation::Immediate).unwrap();
        let mut active = json!({
            "sender_id": SENDER, "master_enable": true,
            "activation": {"mode": "activate_immediate", "requested_time": null, "activation_time": "1790510437:1"},
            "transport_file": {"data": DUP_SDP, "type": "application/sdp"},
            "transport_params": [
                {"source_ip": "192.168.10.21", "multicast_ip": "239.10.10.1", "interface_ip": "192.168.10.31",
                 "destination_port": 5004, "rtp_enabled": true},
                {"source_ip": "192.168.20.21", "multicast_ip": "239.20.10.1", "interface_ip": "192.168.20.31",
                 "destination_port": 5004, "rtp_enabled": true},
            ]
        });
        assert_eq!(plan.verify(&active), Vec::<String>::new());
        active["sender_id"] = json!(SENDER.to_uppercase());
        assert_eq!(plan.verify(&active), Vec::<String>::new(), "UUIDs match whatever their case");
        active["transport_params"][1]["multicast_ip"] = json!("239.20.10.9");
        active["transport_params"][0]["destination_port"] = json!("auto");
        active["master_enable"] = json!(false);
        assert_eq!(
            plan.verify(&active),
            [
                "master_enable is false, not true",
                "leg 1: destination_port is auto, not 5004",
                "leg 2: multicast_ip is 239.20.10.9, not 239.20.10.1",
            ]
        );
        active["transport_params"].as_array_mut().unwrap().pop();
        active["sender_id"] = Value::Null;
        let problems = plan.verify(&active);
        assert!(problems.contains(&"it shows no leg 2".to_string()), "{problems:?}");
        assert!(problems.contains(&format!("sender_id is null, not {SENDER}")), "{problems:?}");

        let off = Plan::disconnect(Activation::Immediate);
        assert_eq!(off.verify(&json!({"sender_id": null, "master_enable": false})), Vec::<String>::new());
        assert_eq!(off.verify(&json!({"master_enable": false})), Vec::<String>::new(), "no sender_id is none");
        assert_eq!(
            off.verify(&json!({"sender_id": SENDER})),
            ["master_enable is absent, not false".to_string(), format!("sender_id is {SENDER}, not null"),]
        );
    }

    #[test]
    fn restores_what_active_showed() {
        let active = json!({
            "sender_id": null, "master_enable": true,
            "activation": {"mode": null, "requested_time": null, "activation_time": null},
            "transport_file": {"data": null, "type": null},
            "transport_params": [{"source_ip": null, "multicast_ip": "239.1.1.1", "interface_ip": "auto",
                                  "destination_port": 5004, "rtp_enabled": true}]
        });
        let plan = Plan::restore(&active, Activation::Immediate).unwrap();
        // No file, so the one a failed salvo staged is taken away.
        assert_eq!(
            plan.request,
            json!({"sender_id": null, "master_enable": true,
                   "activation": {"mode": "activate_immediate", "requested_time": null},
                   "transport_file": {"data": null, "type": null},
                   "transport_params": active["transport_params"]})
        );
        let mut with_file = active.clone();
        with_file["transport_file"] = json!({"data": DUP_SDP, "type": "application/sdp"});
        let plan = Plan::restore(&with_file, Activation::Immediate).unwrap();
        assert_eq!(plan.request["transport_file"]["data"], DUP_SDP);
        assert_eq!(plan.verify(&with_file), Vec::<String>::new());
        assert!(Plan::restore(&json!({"master_enable": true}), Activation::Immediate).is_err());
    }
}
