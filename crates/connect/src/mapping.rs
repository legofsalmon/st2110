//! IS-08 Audio Channel Mapping, as a controller uses it: which Input channel each
//! channel of a Device's Outputs carries, changed by an activation that takes effect at
//! once or at a time (IS-08 v1.0.1).
//!
//! A change names Output channels and the Input channels they are to take, checked
//! against the Device's `/io` first: the Output and Input must exist, the channels be
//! within them, and the Input be one the Output can be routed from. It is sent to
//! `/map/activations`; one that takes effect at once is read back from `/map/active`,
//! and one scheduled for later is reported with its activation id. A Device answers 423
//! when another activation is already waiting for the same Outputs, which
//! [`Remap::Cancel`] takes away.
//!
//! ```no_run
//! use st2110_connect::client::{ConnectionClient, Options};
//! use st2110_connect::controller::Settings;
//! use st2110_connect::mapping::{Remap, Route, remap};
//! use st2110_nmos::client::{self, QueryClient};
//!
//! let read = client::Options { fetch_sdp: false, ..client::Options::default() };
//! let snapshot = QueryClient::connect("http://registry.example:8080", &read)?.snapshot()?;
//! let client = ConnectionClient::new(&Options::default());
//! // Output "main" channels 1 and 2 take channels 3 and 4 of Input "mic".
//! let routes = vec![Route::parse("main:1=mic:3")?, Route::parse("main:2=mic:4")?];
//! let report = remap(&snapshot, "Monitor 1", &Remap::Routes(routes), &client, &Settings::default())?;
//! println!("{}: {}", report.device.describe(), report.state.describe());
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value, json};
use st2110_nmos::Snapshot;
use st2110_nmos::routing::{self, DeviceEndpoint};

use crate::Activation;
use crate::client::ConnectionClient;
use crate::controller::{Settings, State, read_json};

/// One Output channel, and the Input channel it is to carry, or silence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    /// The Output, by its id or its name.
    pub output: String,
    /// The Output channel, counted from 0.
    pub channel: usize,
    /// The Input, by its id or its name, and its channel counted from 0; `None` for
    /// silence.
    pub input: Option<(String, usize)>,
}

impl Route {
    /// Reads a route written `OUTPUT:CHANNEL=INPUT:CHANNEL`, with channels counted from
    /// 1 as an operator counts them, or `OUTPUT:CHANNEL=-` for silence.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad =
            || format!("{text} is not a route: write OUTPUT:CHANNEL=INPUT:CHANNEL, or OUTPUT:CHANNEL=- for silence");
        let (to, from) = text.split_once('=').ok_or_else(bad)?;
        let place = |side: &str| -> Result<(String, usize), String> {
            let (name, channel) = side.trim().rsplit_once(':').ok_or_else(bad)?;
            let channel: usize = channel.trim().parse().map_err(|_| bad())?;
            if name.trim().is_empty() || channel == 0 {
                return Err(bad());
            }
            Ok((name.trim().to_string(), channel - 1))
        };
        let (output, channel) = place(to)?;
        let input = match from.trim() {
            "-" => None,
            from => Some(place(from)?),
        };
        Ok(Self { output, channel, input })
    }
}

/// A change to a Device's channel map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remap {
    /// These Output channels take these Input channels; every other channel stays as
    /// it is.
    Routes(Vec<Route>),
    /// The activations waiting to take effect are taken away.
    Cancel,
}

/// A change to a Device's channel map, and what became of it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Remapped {
    /// The Device.
    pub device: DeviceEndpoint,
    /// What became of the change.
    pub state: State,
    /// The activation sent to `/map/activations`; `None` when nothing could be planned,
    /// or for a cancel.
    pub request: Option<Value>,
    /// The id the Device gave a scheduled activation, by which it can be cancelled.
    pub activation_id: Option<String>,
    /// When a scheduled activation is due, as TAI `seconds:nanoseconds`.
    pub activation_time: Option<String>,
    /// What an operator should know, such as the activations a cancel took away.
    pub notes: Vec<String>,
    /// Why it was refused or failed, and the problems it was sent with when forced.
    pub problems: Vec<String>,
    /// What went wrong without changing the outcome.
    pub warnings: Vec<String>,
}

/// Changes a Device's channel map through its IS-08 Channel Mapping API, or takes away
/// the activations waiting on it.
///
/// The Device is named by its `id`, its `label`, the start of its `id`, or one of its
/// Senders or Receivers. The routes are checked against its `/io`; a change with
/// problems is refused unless [`Settings::force`] is set. [`Settings::dry_run`] plans
/// without sending. [`Settings::activation`] says when it takes effect, at once when
/// `None`; one that takes effect at once is read back from `/map/active` within
/// [`Settings::wait`].
pub fn remap(
    snapshot: &Snapshot,
    device: &str,
    change: &Remap,
    client: &ConnectionClient,
    settings: &Settings,
) -> Result<Remapped, String> {
    let device = routing::find_device(snapshot, device)?;
    let mut report = Remapped {
        device,
        state: State::Planned,
        request: None,
        activation_id: None,
        activation_time: None,
        notes: Vec::new(),
        problems: Vec::new(),
        warnings: Vec::new(),
    };
    let Some(api) = report.device.channel_mapping.as_ref().map(|api| api.href.clone()) else {
        report.problems.push(
            "it advertises no IS-08 Channel Mapping API (urn:x-nmos:control:cm-ctrl/v1.0) in its controls".into(),
        );
        report.state = State::Refused;
        return Ok(report);
    };
    let routes = match change {
        Remap::Cancel => {
            cancel(client, &api, settings, &mut report);
            return Ok(report);
        }
        Remap::Routes(routes) if routes.is_empty() => return Err("no channel routes were given".into()),
        Remap::Routes(routes) => routes,
    };
    let io = match read_json(client, &format!("{api}io")) {
        Ok(io) => io,
        Err(e) => {
            report.problems.push(format!("its /io could not be read: {e}"));
            report.state = State::Refused;
            return Ok(report);
        }
    };
    let action = plan(&io, routes, &mut report.problems);
    let activation = settings.activation.unwrap_or(Activation::Immediate);
    report.request = Some(json!({"activation": activation.to_json(), "action": action}));
    if !report.problems.is_empty() && !settings.force {
        report.state = State::Refused;
        return Ok(report);
    }
    if settings.dry_run {
        return Ok(report);
    }
    let request = report.request.clone().unwrap_or_default();
    let reply = match client.post(&format!("{api}map/activations"), &request) {
        Ok(reply) => reply,
        Err(e) => {
            report.problems.push(format!("no answer: {e}"));
            report.state = State::Failed;
            return Ok(report);
        }
    };
    let accepted = reply.body.as_object().and_then(|body| body.iter().next());
    match reply.status {
        200 => {
            if let Some((id, _)) = accepted {
                report.activation_id = Some(id.clone());
            }
            report.state = verify(client, &api, &action, settings.wait, &mut report.warnings);
        }
        202 => {
            if let Some((id, accepted)) = accepted {
                report.activation_id = Some(id.clone());
                report.activation_time = accepted
                    .get("activation")
                    .and_then(|a| a.get("activation_time"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            } else {
                report.warnings.push("the Device scheduled it, but did not say under which activation id".into());
            }
            report.state = State::Scheduled;
        }
        status => {
            let why = match status {
                400 => "; the map breaks one of the Device's constraints, such as its block size or reordering",
                423 => "; another activation is already waiting for one of these Outputs: cancel it first",
                _ => "",
            };
            report.problems.push(format!("the Channel Mapping API refused it: {}{why}", reply.error()));
            report.state = State::Failed;
        }
    }
    Ok(report)
}

/// Takes away every activation waiting on the Device.
fn cancel(client: &ConnectionClient, api: &str, settings: &Settings, report: &mut Remapped) {
    let pending = match read_json(client, &format!("{api}map/activations")) {
        Ok(pending) => pending,
        Err(e) => {
            report.problems.push(format!("its /map/activations could not be read: {e}"));
            report.state = State::Failed;
            return;
        }
    };
    let ids: Vec<String> = pending.as_object().map(|p| p.keys().cloned().collect()).unwrap_or_default();
    if ids.is_empty() {
        report.notes.push("no activations were waiting".into());
        report.state = if settings.dry_run { State::Planned } else { State::Done };
        return;
    }
    if settings.dry_run {
        report.notes.push(format!("would cancel activation {}", ids.join(", ")));
        return;
    }
    for id in &ids {
        match client.delete(&format!("{api}map/activations/{id}")) {
            Ok(reply) if reply.is_success() => report.notes.push(format!("cancelled activation {id}")),
            // Gone already: it took effect, or someone else cancelled it.
            Ok(reply) if reply.status == 404 => {
                report.warnings.push(format!("activation {id} was gone before it could be cancelled"));
            }
            Ok(reply) => report.problems.push(format!("activation {id} could not be cancelled: {}", reply.error())),
            Err(e) => report.problems.push(format!("activation {id} could not be cancelled: {e}")),
        }
    }
    report.state = if report.problems.is_empty() { State::Done } else { State::Failed };
}

/// The `action` of an activation for these routes, by Output id and channel, with the
/// problems `/io` shows in them.
fn plan(io: &Value, routes: &[Route], problems: &mut Vec<String>) -> Map<String, Value> {
    let mut action = Map::new();
    for route in routes {
        let Some((output_id, output)) = pick(io, "outputs", &route.output) else {
            problems.push(format!("the Device has no Output {}", route.output));
            continue;
        };
        let count = output.get("channels").and_then(Value::as_array).map_or(0, Vec::len);
        let name = shown(output_id, output);
        if route.channel >= count {
            problems.push(format!("Output {name} has {count} channels, so it has no channel {}", route.channel + 1));
        }
        let routable = output.get("caps").and_then(|c| c.get("routable_inputs")).and_then(Value::as_array);
        let entry = match &route.input {
            None => {
                if let Some(routable) = routable
                    && !routable.iter().any(Value::is_null)
                {
                    problems.push(format!("Output {name} cannot be left silent: its routable_inputs leave out null"));
                }
                json!({"input": null, "channel_index": null})
            }
            Some((input, channel)) => {
                let Some((input_id, found)) = pick(io, "inputs", input) else {
                    problems.push(format!("the Device has no Input {input}"));
                    continue;
                };
                let inputs = found.get("channels").and_then(Value::as_array).map_or(0, Vec::len);
                if *channel >= inputs {
                    problems.push(format!(
                        "Input {} has {inputs} channels, so it has no channel {}",
                        shown(input_id, found),
                        channel + 1
                    ));
                }
                if let Some(routable) = routable
                    && !routable.iter().any(|r| r.as_str() == Some(input_id))
                {
                    problems.push(format!(
                        "Output {name} cannot take Input {}: it is not one of the Output's routable_inputs",
                        shown(input_id, found)
                    ));
                }
                json!({"input": input_id, "channel_index": channel})
            }
        };
        let channels = action.entry(output_id.to_string()).or_insert_with(|| Value::Object(Map::new()));
        if let Some(channels) = channels.as_object_mut() {
            channels.insert(route.channel.to_string(), entry);
        }
    }
    action
}

/// An Input or Output of `/io`, by its id or its name.
fn pick<'a>(io: &'a Value, side: &str, wanted: &str) -> Option<(&'a str, &'a Value)> {
    let all = io.get(side)?.as_object()?;
    if let Some((id, value)) = all.get_key_value(wanted) {
        return Some((id.as_str(), value));
    }
    let named: Vec<(&String, &Value)> = all
        .iter()
        .filter(|(_, v)| {
            v.get("properties")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case(wanted))
        })
        .collect();
    match named.as_slice() {
        [(id, value)] => Some((id.as_str(), value)),
        _ => None,
    }
}

/// How an Input or Output is named in messages: its name and id, or its id.
fn shown(id: &str, io: &Value) -> String {
    match io.get("properties").and_then(|p| p.get("name")).and_then(Value::as_str).filter(|n| !n.is_empty() && *n != id)
    {
        Some(name) => format!("\"{name}\" ({id})"),
        None => id.to_string(),
    }
}

/// Reads `/map/active` until it shows the action, or `wait` runs out.
fn verify(
    client: &ConnectionClient,
    api: &str,
    action: &Map<String, Value>,
    wait: Duration,
    warnings: &mut Vec<String>,
) -> State {
    let deadline = Instant::now() + wait;
    loop {
        match read_json(client, &format!("{api}map/active")) {
            Ok(active) => {
                let map = active.get("map");
                let shows = action.iter().all(|(output, channels)| {
                    channels.as_object().into_iter().flatten().all(|(index, route)| {
                        map.and_then(|m| m.get(output)).and_then(|o| o.get(index)).is_some_and(|got| same(got, route))
                    })
                });
                if shows {
                    return State::Done;
                }
                if Instant::now() >= deadline {
                    warnings.push("its /map/active does not show the change".into());
                    return State::Differs;
                }
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    warnings.push(format!("its /map/active could not be read: {e}"));
                    return State::Differs;
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Whether a route in `/map/active` is the one asked for: the same Input, and the same
/// channel.
fn same(got: &Value, wanted: &Value) -> bool {
    got.get("input") == wanted.get("input")
        && got.get("channel_index").and_then(Value::as_u64) == wanted.get("channel_index").and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_read_as_operators_count_channels() {
        assert_eq!(
            Route::parse("main:1=mic:3"),
            Ok(Route { output: "main".into(), channel: 0, input: Some(("mic".into(), 2)) })
        );
        assert_eq!(
            Route::parse(" out:a:2 = - ").map(|r| (r.output, r.channel, r.input)),
            Ok(("out:a".into(), 1, None))
        );
        for bad in ["main:0=mic:1", "main=mic:1", "main:1", ":1=mic:1", "main:1=mic"] {
            assert!(Route::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn routes_are_checked_against_io() {
        let io = json!({
            "inputs": {
                "in-1": {"properties": {"name": "mic"}, "channels": [{"label": "L"}, {"label": "R"}]},
                "in-2": {"properties": {"name": "line"}, "channels": [{"label": "L"}]},
            },
            "outputs": {
                "out-1": {"properties": {"name": "main"}, "channels": [{"label": "L"}, {"label": "R"}],
                          "caps": {"routable_inputs": ["in-1"]}},
            },
        });
        let mut problems = Vec::new();
        let routes = [Route::parse("main:1=mic:2").unwrap(), Route::parse("out-1:2=mic:1").unwrap()];
        let action = plan(&io, &routes, &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(
            Value::Object(action),
            json!({"out-1": {"0": {"input": "in-1", "channel_index": 1}, "1": {"input": "in-1", "channel_index": 0}}})
        );
        let routes = ["main:3=mic:1", "main:1=mic:3", "main:1=line:1", "main:1=-", "aux:1=mic:1", "main:1=nothing:1"]
            .map(|r| Route::parse(r).unwrap());
        plan(&io, &routes, &mut problems);
        assert_eq!(problems.len(), 6, "{problems:#?}");
    }
}
