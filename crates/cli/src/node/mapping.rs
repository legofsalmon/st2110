//! An IS-08 Channel Mapping API (v1.0.1), as a Device serves it: its Inputs and
//! Outputs (`/io`, and each one's resources under `/inputs` and `/outputs`), the map it
//! applies now (`/map/active`), and the activations that change it, at once or at a
//! time (`/map/activations`). The demo facility of `st2110 router --demo` serves one
//! for its audio Node.
//!
//! An activation is checked against the Inputs and Outputs before it is taken: each
//! Output and Input must exist, each channel be one of theirs, and the Input be one of
//! the Output's `routable_inputs`, or silence where they list `null`. Every Input here
//! reorders freely, in blocks of one channel, so neither is checked. An Output that a
//! scheduled activation is waiting to change is locked to every other activation until
//! that one takes effect or is cancelled, and a request for it is answered 423.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use st2110_ptp::PtpTime;

use super::connection::{error, tai};

/// An Input or Output's channel, by its Input or Output id and its index from 0.
type Channel = (String, usize);

/// An activation waiting for its time.
struct Pending {
    due: PtpTime,
    activation: Value,
    action: Value,
}

/// One Device's Channel Mapping API.
pub(crate) struct ChannelMap {
    /// What `/io` serves: `inputs` and `outputs`, each by id.
    io: Value,
    /// What each Output's channels carry, by Output id: an Input's channel, or `None`
    /// for silence.
    map: BTreeMap<String, Vec<Option<Channel>>>,
    /// The activation that last changed the map.
    activation: Value,
    /// The scheduled activations not yet due, by id.
    pending: BTreeMap<String, Pending>,
    /// The last activation id given.
    last_id: u64,
    /// Whether the map changed since this was last asked.
    changed: bool,
}

/// The `activation` of a map no activation has changed.
fn no_activation() -> Value {
    json!({"mode": null, "requested_time": null, "activation_time": null})
}

/// The channels of an Input or Output in `/io`, by their labels.
pub(crate) fn channels(labels: &[&str]) -> Value {
    labels.iter().map(|label| json!({"label": label})).collect()
}

impl ChannelMap {
    /// A Device with these Inputs and Outputs, as `/io` serves them, each Output
    /// silent.
    pub(crate) fn new(io: Value) -> Self {
        let map = io["outputs"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(id, output)| (id.clone(), vec![None; output["channels"].as_array().map_or(0, Vec::len)]))
            .collect();
        Self { io, map, activation: no_activation(), pending: BTreeMap::new(), last_id: 0, changed: false }
    }

    /// Routes an Output's channel to an Input's channel, to set the Device up.
    pub(crate) fn with(mut self, output: &str, channel: usize, input: &str, input_channel: usize) -> Self {
        if let Some(slot) = self.map.get_mut(output).and_then(|o| o.get_mut(channel)) {
            *slot = Some((input.to_string(), input_channel));
        }
        self
    }

    /// Whether the map changed since this was last asked.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// The map, to keep for the next run.
    pub(crate) fn export(&self) -> Value {
        self.active_map(None)
    }

    /// Puts back what [`ChannelMap::export`] kept, as far as it still fits the Inputs
    /// and Outputs.
    pub(crate) fn restore(&mut self, kept: &Value) {
        let Some(kept) = kept.as_object() else { return };
        let mut routes = Vec::new();
        for (output, channels) in kept {
            for (index, route) in channels.as_object().into_iter().flatten() {
                let Ok(index) = index.parse::<usize>() else { continue };
                if self.check_route(output, index, route).is_ok() {
                    routes.push((output.clone(), index, route.clone()));
                }
            }
        }
        for (output, index, route) in routes {
            self.set(&output, index, &route);
        }
    }

    /// Answers a request, from the path after `/x-nmos/channelmapping`.
    pub(crate) fn route(&mut self, method: &str, rest: &str, body: &Value, now: PtpTime) -> (u16, Value) {
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let get = |value: Value| if method == "GET" { (200, value) } else { error(405, "Method Not Allowed", "") };
        match parts.as_slice() {
            [] => get(json!(["v1.0/"])),
            ["v1.0"] => get(json!(["io/", "map/", "inputs/", "outputs/"])),
            ["v1.0", "io"] => get(self.io.clone()),
            ["v1.0", side @ ("inputs" | "outputs")] => {
                get(self.io[*side].as_object().into_iter().flatten().map(|(id, _)| json!(format!("{id}/"))).collect())
            }
            ["v1.0", side @ ("inputs" | "outputs"), id, resource @ ..] => {
                let Some(found) = self.io[*side].get(*id) else {
                    return error(404, "Not Found", &format!("no such {}", &side[..side.len() - 1]));
                };
                let names: &[&str] = if *side == "inputs" {
                    &["parent", "channels", "caps", "properties"]
                } else {
                    &["sourceid", "channels", "caps", "properties"]
                };
                match resource {
                    [] => get(names.iter().map(|n| json!(format!("{n}/"))).collect()),
                    // An Output's `/sourceid` is its `source_id`.
                    ["sourceid"] if *side == "outputs" => get(found["source_id"].clone()),
                    [name] if names.contains(name) => get(found[*name].clone()),
                    _ => error(404, "Not Found", rest),
                }
            }
            ["v1.0", "map"] => get(json!(["activations/", "active/"])),
            ["v1.0", "map", "active"] => get(json!({"activation": self.activation, "map": self.active_map(None)})),
            ["v1.0", "map", "active", output] => match self.map.contains_key(*output) {
                true => get(self.active_map(Some(output))),
                false => error(404, "Not Found", "no such output"),
            },
            ["v1.0", "map", "activations"] => match method {
                "GET" => (
                    200,
                    self.pending
                        .iter()
                        .map(|(id, p)| (id.clone(), json!({"activation": p.activation, "action": p.action})))
                        .collect::<Map<String, Value>>()
                        .into(),
                ),
                "POST" => self.activate(body, now),
                _ => error(405, "Method Not Allowed", ""),
            },
            ["v1.0", "map", "activations", id] => match (method, self.pending.get(*id)) {
                (_, None) => error(404, "Not Found", "no such activation: it took effect, or was never made"),
                ("GET", Some(p)) => (200, json!({*id: {"activation": p.activation, "action": p.action}})),
                ("DELETE", Some(_)) => {
                    self.pending.remove(*id);
                    (204, Value::Null)
                }
                _ => error(405, "Method Not Allowed", ""),
            },
            _ => error(404, "Not Found", rest),
        }
    }

    /// Carries out the scheduled activations that are due, oldest first.
    pub(crate) fn settle(&mut self, now: PtpTime) {
        let mut due: Vec<(PtpTime, String)> =
            self.pending.iter().filter(|(_, p)| p.due <= now).map(|(id, p)| (p.due, id.clone())).collect();
        due.sort();
        for (_, id) in due {
            if let Some(pending) = self.pending.remove(&id) {
                self.apply(&pending.action, pending.activation);
            }
        }
    }

    /// `POST /map/activations`: checks an activation, and makes it at once (200) or
    /// waits for its time (202).
    fn activate(&mut self, body: &Value, now: PtpTime) -> (u16, Value) {
        let bad = |why: &str| error(400, "Bad Request", why);
        let mode = body["activation"]["mode"].as_str().unwrap_or_default();
        let requested = body["activation"]["requested_time"].as_str();
        let due = match (mode, requested.map(PtpTime::parse)) {
            ("activate_immediate", _) => now,
            ("activate_scheduled_absolute", Some(Some(at))) => at,
            ("activate_scheduled_relative", Some(Some(after))) => {
                match now.add_nanos(i128::from(after.seconds()) * 1_000_000_000 + i128::from(after.subsec_nanos())) {
                    Some(at) => at,
                    None => return bad("the requested_time is too far ahead"),
                }
            }
            ("activate_scheduled_absolute" | "activate_scheduled_relative", _) => {
                return bad("a scheduled activation needs a requested_time, as <seconds>:<nanoseconds>");
            }
            _ => {
                return bad(
                    "the activation's mode is activate_immediate, activate_scheduled_absolute or activate_scheduled_relative",
                );
            }
        };
        let Some(action) = body["action"].as_object().filter(|a| !a.is_empty()) else {
            return bad("the action names no outputs");
        };
        for (output, channels) in action {
            let Some(channels) = channels.as_object().filter(|c| !c.is_empty()) else {
                return bad(&format!("the action names no channels of output {output}"));
            };
            if let Some((id, _)) = self.pending.iter().find(|(_, p)| p.action.get(output).is_some()) {
                return error(
                    423,
                    "Locked",
                    &format!("output {output} is locked by activation {id}, which is waiting to take effect"),
                );
            }
            for (index, route) in channels {
                let Ok(index) = index.parse::<usize>() else {
                    return bad(&format!("output {output} has no channel {index}: channels are numbered from 0"));
                };
                if let Err(why) = self.check_route(output, index, route) {
                    return bad(&why);
                }
            }
        }
        self.last_id += 1;
        let id = self.last_id.to_string();
        let action = Value::Object(action.clone());
        let activation = json!({"mode": mode, "requested_time": requested, "activation_time": tai(due)});
        let accepted = json!({&id: {"activation": activation, "action": action}});
        if mode == "activate_immediate" {
            self.apply(&action, activation);
            return (200, accepted);
        }
        self.pending.insert(id, Pending { due, activation, action });
        (202, accepted)
    }

    /// Whether an Output's channel can carry what a route names: `Err` says why not.
    fn check_route(&self, output: &str, index: usize, route: &Value) -> Result<(), String> {
        let Some(found) = self.io["outputs"].get(output) else {
            return Err(format!("the device has no output {output}"));
        };
        let count = found["channels"].as_array().map_or(0, Vec::len);
        if index >= count {
            return Err(format!("output {output} has {count} channels, numbered from 0, so no channel {index}"));
        }
        let routable = found["caps"]["routable_inputs"].as_array();
        let input = match (&route["input"], &route["channel_index"]) {
            (Value::Null, Value::Null) => None,
            (Value::String(input), Value::Number(channel)) => Some((input, channel.as_u64())),
            _ => {
                return Err(format!(
                    "output {output} channel {index} needs an input and its channel_index, or null for both to be silent"
                ));
            }
        };
        match input {
            None => {
                if routable.is_some_and(|r| !r.contains(&Value::Null)) {
                    return Err(format!("output {output} cannot be silent: its routable_inputs leave out null"));
                }
            }
            Some((input, channel)) => {
                let Some(source) = self.io["inputs"].get(input.as_str()) else {
                    return Err(format!("the device has no input {input}"));
                };
                let inputs = source["channels"].as_array().map_or(0, Vec::len);
                if channel.is_none_or(|c| c >= inputs as u64) {
                    return Err(format!("input {input} has {inputs} channels, numbered from 0"));
                }
                if routable.is_some_and(|r| !r.iter().any(|i| i.as_str() == Some(input))) {
                    return Err(format!(
                        "output {output} cannot take input {input}: it is not one of its routable_inputs"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Makes an action the map, by an activation already checked.
    fn apply(&mut self, action: &Value, activation: Value) {
        for (output, channels) in action.as_object().into_iter().flatten() {
            for (index, route) in channels.as_object().into_iter().flatten() {
                if let Ok(index) = index.parse::<usize>() {
                    self.set(output, index, route);
                }
            }
        }
        self.activation = activation;
        self.changed = true;
    }

    fn set(&mut self, output: &str, index: usize, route: &Value) {
        let to = match (route["input"].as_str(), route["channel_index"].as_u64()) {
            (Some(input), Some(channel)) => usize::try_from(channel).ok().map(|c| (input.to_string(), c)),
            _ => None,
        };
        if let Some(slot) = self.map.get_mut(output).and_then(|o| o.get_mut(index)) {
            *slot = to;
        }
    }

    /// The map as `/map/active` gives it, by Output id, of every Output or just one.
    fn active_map(&self, only: Option<&str>) -> Value {
        self.map
            .iter()
            .filter(|(id, _)| only.is_none_or(|o| o == id.as_str()))
            .map(|(id, channels)| {
                let routes: Map<String, Value> = channels
                    .iter()
                    .enumerate()
                    .map(|(i, route)| {
                        let route = match route {
                            Some((input, channel)) => json!({"input": input, "channel_index": channel}),
                            None => json!({"input": null, "channel_index": null}),
                        };
                        (i.to_string(), route)
                    })
                    .collect();
                (id.clone(), Value::Object(routes))
            })
            .collect::<Map<String, Value>>()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> ChannelMap {
        ChannelMap::new(json!({
            "inputs": {
                "mic": {"properties": {"name": "Mic"}, "parent": {"id": null, "type": null}, "channels": channels(&["1", "2"]),
                        "caps": {"reordering": true, "block_size": 1}},
                "tone": {"properties": {"name": "Tone"}, "parent": {"id": null, "type": null}, "channels": channels(&["L"]),
                         "caps": {"reordering": true, "block_size": 1}},
            },
            "outputs": {
                "main": {"properties": {"name": "Main"}, "source_id": null, "channels": channels(&["L", "R"]),
                         "caps": {"routable_inputs": ["mic"]}},
            },
        }))
        .with("main", 0, "mic", 0)
        .with("main", 1, "mic", 1)
    }

    fn at(seconds: u64) -> PtpTime {
        PtpTime::new(seconds, 0).unwrap()
    }

    fn post(map: &mut ChannelMap, mode: &str, time: Option<&str>, action: Value, now: u64) -> (u16, Value) {
        let body = json!({"activation": {"mode": mode, "requested_time": time}, "action": action});
        map.route("POST", "/v1.0/map/activations", &body, at(now))
    }

    #[test]
    fn serves_its_inputs_outputs_and_map() {
        let mut map = device();
        let (status, outputs) = map.route("GET", "/v1.0/outputs/", &Value::Null, at(1));
        assert_eq!((status, outputs), (200, json!(["main/"])));
        assert_eq!(map.route("GET", "/v1.0/outputs/main/sourceid", &Value::Null, at(1)), (200, Value::Null));
        assert_eq!(map.route("GET", "/v1.0/inputs/tone/channels", &Value::Null, at(1)).1, json!([{"label": "L"}]));
        assert_eq!(map.route("GET", "/v1.0/inputs/none", &Value::Null, at(1)).0, 404);
        let (_, active) = map.route("GET", "/v1.0/map/active/main", &Value::Null, at(1));
        assert_eq!(active["main"]["1"], json!({"input": "mic", "channel_index": 1}));
        assert_eq!(map.route("PUT", "/v1.0/io", &Value::Null, at(1)).0, 405);
    }

    #[test]
    fn takes_a_change_at_once_and_refuses_what_does_not_fit() {
        let mut map = device();
        let swap =
            json!({"main": {"0": {"input": "mic", "channel_index": 1}, "1": {"input": "mic", "channel_index": 0}}});
        let (status, accepted) = post(&mut map, "activate_immediate", None, swap, 5);
        assert_eq!(status, 200, "{accepted}");
        assert_eq!(accepted["1"]["activation"]["activation_time"], "5:0");
        assert!(map.take_changed());
        let (_, active) = map.route("GET", "/v1.0/map/active", &Value::Null, at(6));
        assert_eq!(active["map"]["main"]["0"]["channel_index"], 1);
        assert_eq!(active["activation"]["mode"], "activate_immediate");
        for action in [
            json!({"main": {"2": {"input": "mic", "channel_index": 0}}}),
            json!({"main": {"0": {"input": "mic", "channel_index": 2}}}),
            json!({"main": {"0": {"input": "tone", "channel_index": 0}}}),
            json!({"main": {"0": {"input": null, "channel_index": null}}}),
            json!({"aux": {"0": {"input": "mic", "channel_index": 0}}}),
            json!({}),
        ] {
            assert_eq!(post(&mut map, "activate_immediate", None, action.clone(), 7).0, 400, "{action}");
        }
        assert!(!map.take_changed());
    }

    #[test]
    fn a_scheduled_change_locks_its_outputs_until_it_is_due_or_cancelled() {
        let mut map = device();
        let cross = json!({"main": {"0": {"input": "mic", "channel_index": 1}}});
        let (status, accepted) = post(&mut map, "activate_scheduled_relative", Some("2:0"), cross.clone(), 10);
        assert_eq!(status, 202, "{accepted}");
        assert_eq!(accepted["1"]["activation"]["activation_time"], "12:0");
        let (status, locked) = post(&mut map, "activate_immediate", None, cross.clone(), 11);
        assert_eq!(status, 423, "{locked}");
        assert_eq!(map.route("GET", "/v1.0/map/activations", &Value::Null, at(11)).1["1"]["action"], cross);
        map.settle(at(11));
        assert!(!map.take_changed());
        map.settle(at(12));
        assert!(map.take_changed());
        assert_eq!(map.route("GET", "/v1.0/map/activations", &Value::Null, at(12)).1, json!({}));
        // Cancelled, it never happens.
        let back = json!({"main": {"0": {"input": "mic", "channel_index": 0}}});
        post(&mut map, "activate_scheduled_absolute", Some("20:0"), back, 13);
        assert_eq!(map.route("DELETE", "/v1.0/map/activations/2", &Value::Null, at(14)).0, 204);
        assert_eq!(map.route("DELETE", "/v1.0/map/activations/2", &Value::Null, at(14)).0, 404);
        map.settle(at(21));
        assert_eq!(map.export()["main"]["0"]["channel_index"], 1);
    }

    #[test]
    fn keeps_its_map_for_the_next_run() {
        let mut map = device();
        post(&mut map, "activate_immediate", None, json!({"main": {"1": {"input": "mic", "channel_index": 0}}}), 1);
        let kept = map.export();
        let mut again = device();
        again.restore(&kept);
        assert_eq!(again.export(), kept);
        // What no longer fits is left as it is.
        let mut broken = kept.clone();
        broken["main"]["0"] = json!({"input": "gone", "channel_index": 0});
        let mut again = device();
        again.restore(&broken);
        assert_eq!(again.export()["main"]["0"], json!({"input": "mic", "channel_index": 0}));
        assert_eq!(again.export()["main"]["1"], json!({"input": "mic", "channel_index": 0}));
    }
}
