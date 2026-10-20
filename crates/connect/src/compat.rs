//! IS-11 Stream Compatibility Management, as a controller uses it: holding a Sender to
//! what the Receivers it is to feed can take, by putting their BCP-004-01 capabilities
//! to it as its active constraints, and letting it go again.
//!
//! A controller reads the Sender's `/constraints/supported` first, to know which
//! parameter constraints it can be held to, builds one list of constraint sets that
//! every chosen Receiver accepts, `PUT`s them to `/constraints/active`, and reports the
//! Sender's `status` after (IS-11 v1.0 Behaviour: Client Side). `DELETE` lets it go.
//!
//! ```no_run
//! use st2110_connect::client::{ConnectionClient, Options};
//! use st2110_connect::compat::{Hold, constrain};
//! use st2110_connect::controller::Settings;
//! use st2110_nmos::client::{self, QueryClient};
//!
//! let read = client::Options { fetch_sdp: false, ..client::Options::default() };
//! let snapshot = QueryClient::connect("http://registry.example:8080", &read)?.snapshot()?;
//! let client = ConnectionClient::new(&Options::default());
//! let wanted = Hold::For(vec!["MON 1 video".into(), "MON 2 video".into()]);
//! let report = constrain(&snapshot, "CAM 1 video", &wanted, &client, &Settings::default())?;
//! println!("{}: {}", report.sender.describe(), report.state.describe());
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::cmp::Ordering;

use serde::Serialize;
use serde_json::{Map, Value, json};
use st2110_nmos::routing::{self, Endpoint};
use st2110_nmos::{Kind, Snapshot};

use crate::client::{ConnectionClient, Reply};
use crate::controller::{Settings, State, read_json};

/// The most constraint sets a consensus keeps: each Receiver's sets multiply the others'.
const MOST_SETS: usize = 64;

/// What a Sender is to be held to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// What every one of these Receivers can take: each named by its `id`, its `label`
    /// or the start of its `id`.
    For(Vec<String>),
    /// Nothing: its active constraints are taken away.
    Nothing,
}

/// A change to a Sender's IS-11 active constraints, and what became of it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Constrained {
    /// The Sender.
    pub sender: Endpoint,
    /// What became of the change.
    pub state: State,
    /// The constraint sets put to `/constraints/active`; `None` when they are taken away,
    /// or none could be planned.
    pub request: Option<Value>,
    /// The Sender's IS-11 `status` `state` afterwards, such as `constrained`.
    pub status: Option<String>,
    /// What an operator should know, such as a constraint the Sender cannot be held to.
    pub notes: Vec<String>,
    /// Why it was refused or failed, and the problems it was sent with when forced.
    pub problems: Vec<String>,
    /// What went wrong without changing the outcome, such as a status that could not
    /// be read.
    pub warnings: Vec<String>,
}

/// Holds a Sender to what the named Receivers can all take, or lets it go, through its
/// Device's IS-11 API, and reads its `status` after.
///
/// For [`Hold::For`], each Receiver's enabled BCP-004-01 constraint sets, from
/// the registry, are combined into the sets every one of them accepts, and those into
/// what the Sender's own BCP-004-02 capabilities allow. Constraints the Sender's
/// `/constraints/supported` does not list are left out, and noted. When nothing is
/// left that all of them accept, the change is refused, unless [`Settings::force`]
/// is set and something is left to send. [`Settings::dry_run`] plans without sending.
///
/// A Device may refuse a change while its Sender is sending (HTTP 423); turn the
/// Sender off first.
///
/// Fails, sending nothing, when a name finds no Sender or Receiver, or more than one.
pub fn constrain(
    snapshot: &Snapshot,
    sender: &str,
    wanted: &Hold,
    client: &ConnectionClient,
    settings: &Settings,
) -> Result<Constrained, String> {
    let sender = routing::find(snapshot, Kind::Sender, sender)?;
    let receivers = match wanted {
        Hold::For(names) => {
            names.iter().map(|name| routing::find(snapshot, Kind::Receiver, name)).collect::<Result<Vec<_>, _>>()?
        }
        Hold::Nothing => Vec::new(),
    };
    let mut report = Constrained {
        sender,
        state: State::Planned,
        request: None,
        status: None,
        notes: Vec::new(),
        problems: Vec::new(),
        warnings: Vec::new(),
    };
    let Some(api) = report.sender.stream_compat.as_ref().map(|api| api.href.clone()) else {
        report.problems.push(
            "its Device advertises no IS-11 Stream Compatibility Management API \
             (urn:x-nmos:control:stream-compat/v1.0) in its controls"
                .into(),
        );
        report.state = State::Refused;
        return Ok(report);
    };
    let base = format!("{api}senders/{}/", report.sender.id);
    let active = format!("{base}constraints/active");

    if *wanted == Hold::Nothing {
        if !settings.dry_run {
            let reply = client.delete(&active).map_err(|e| e.to_string());
            if let Some(problem) = refused(reply) {
                report.problems.push(problem);
                report.state = State::Failed;
                return Ok(report);
            }
            report.state = State::Done;
            read_status(client, &base, &mut report);
        }
        return Ok(report);
    }

    let supported = match read_json(client, &format!("{base}constraints/supported")) {
        Ok(supported) => supported,
        Err(e) => {
            report.problems.push(format!("its /constraints/supported could not be read: {e}"));
            report.state = State::Refused;
            return Ok(report);
        }
    };
    let supported: Vec<&str> = supported
        .get("parameter_constraints")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let plan = plan(snapshot, &report.sender, &receivers, &supported);
    report.notes = plan.notes;
    report.problems = plan.problems;
    if let Some(sets) = plan.sets {
        report.request = Some(json!({"constraint_sets": sets}));
    }
    let Some(request) = report.request.clone().filter(|_| report.problems.is_empty() || settings.force) else {
        report.state = State::Refused;
        return Ok(report);
    };
    if settings.dry_run {
        return Ok(report);
    }
    if let Some(problem) = refused(client.put(&active, &request).map_err(|e| e.to_string())) {
        report.problems.push(problem);
        report.state = State::Failed;
        return Ok(report);
    }
    report.state = State::Done;
    read_status(client, &base, &mut report);
    Ok(report)
}

/// Why a Device refused a change to a Sender's active constraints, or `None` when it
/// took it (IS-11 v1.0 StreamCompatibilityManagementAPI.raml).
fn refused(reply: Result<Reply, String>) -> Option<String> {
    let reply = match reply {
        Ok(reply) if reply.is_success() => return None,
        Ok(reply) => reply,
        Err(e) => return Some(format!("no answer: {e}")),
    };
    let why = match reply.status {
        400 => "; it does not take one of the parameter constraints, or the request is malformed",
        422 => "; the Sender cannot send anything that meets them",
        423 => "; the Device cannot change them now, as while the Sender is sending: turn it off first",
        _ => "",
    };
    Some(format!("the IS-11 API refused it: {}{why}", reply.error()))
}

/// Reads the Sender's IS-11 `status` into the report, and warns of one that is not
/// what a controller wants to see after a change.
fn read_status(client: &ConnectionClient, base: &str, report: &mut Constrained) {
    match read_json(client, &format!("{base}status")) {
        Ok(status) => {
            let state = status.get("state").and_then(Value::as_str).map(str::to_string);
            let debug = status.get("debug").and_then(Value::as_str).filter(|d| !d.trim().is_empty());
            if let Some(state @ ("active_constraints_violation" | "no_essence")) = state.as_deref() {
                let mut warning = format!("its status is {state}");
                if let Some(debug) = debug {
                    warning.push_str(&format!(": {debug}"));
                }
                report.warnings.push(warning);
            }
            report.status = state;
        }
        Err(e) => report.warnings.push(format!("its status could not be read: {e}")),
    }
}

/// The constraint sets planned for a Sender, what to know of them, and why they cannot
/// be sent.
struct Planned {
    sets: Option<Vec<Value>>,
    notes: Vec<String>,
    problems: Vec<String>,
}

/// Combines the Receivers' capabilities with each other and the Sender's, keeping only
/// the constraints the Sender supports.
fn plan(snapshot: &Snapshot, sender: &Endpoint, receivers: &[Endpoint], supported: &[&str]) -> Planned {
    let mut notes = Vec::new();
    let mut problems = Vec::new();
    let caps = |kind: Kind, id: &str| -> Option<Vec<Map<String, Value>>> {
        let list = match kind {
            Kind::Sender => &snapshot.senders,
            _ => &snapshot.receivers,
        };
        let resource = list.iter().find(|r| r.get("id").and_then(Value::as_str) == Some(id))?;
        let sets = resource.get("caps")?.get("constraint_sets")?.as_array()?;
        Some(sets.iter().filter_map(enabled).collect())
    };
    let mut consensus: Option<Vec<Map<String, Value>>> = None;
    for receiver in receivers {
        let Some(sets) = caps(Kind::Receiver, &receiver.id).filter(|sets| !sets.is_empty()) else {
            notes.push(format!("{} lists no enabled constraint sets, so it adds nothing", receiver.describe()));
            continue;
        };
        consensus = Some(match consensus {
            None => sets,
            Some(so_far) => {
                let both = combine(&so_far, &sets);
                if both.is_empty() {
                    problems.push(format!(
                        "no stream is one that {} and the Receivers before it all take",
                        receiver.describe()
                    ));
                }
                both
            }
        });
    }
    let Some(mut sets) = consensus else {
        problems.push("none of the Receivers lists capabilities to hold the Sender to".into());
        return Planned { sets: None, notes, problems };
    };
    if let Some(own) = caps(Kind::Sender, &sender.id).filter(|own| !own.is_empty()) {
        let both = combine(&sets, &own);
        if both.is_empty() && !sets.is_empty() {
            problems.push(format!(
                "{} can send nothing the Receivers all take, as its own capabilities (BCP-004-02) say",
                sender.describe()
            ));
        } else {
            sets = both;
        }
    }
    // Only what the Sender can be held to is sent.
    let mut dropped: Vec<String> = Vec::new();
    for set in &mut sets {
        set.retain(|urn, _| {
            let keep = supported.contains(&urn.as_str());
            if !keep && !dropped.contains(urn) {
                dropped.push(urn.clone());
            }
            keep
        });
    }
    if !dropped.is_empty() {
        dropped.sort();
        let short: Vec<&str> = dropped.iter().map(|u| u.strip_prefix("urn:x-nmos:cap:").unwrap_or(u)).collect();
        notes.push(format!(
            "the Sender cannot be held to {}, which its /constraints/supported does not list, so the Receivers may \
             still be sent what they cannot take there",
            short.join(", ")
        ));
    }
    sets.retain(|set| !set.is_empty());
    sets.dedup();
    if sets.is_empty() && problems.is_empty() {
        problems.push("nothing is left to hold the Sender to that it supports".into());
    }
    let sets = (!sets.is_empty()).then(|| sets.into_iter().map(Value::Object).collect());
    Planned { sets, notes, problems }
}

/// A constraint set without its metadata, unless it is disabled (BCP-004-01: a
/// controller ignores a disabled set, and does not pass a Receiver's preferences on as
/// the Sender's).
fn enabled(set: &Value) -> Option<Map<String, Value>> {
    let set = set.as_object()?;
    if set.get("urn:x-nmos:cap:meta:enabled") == Some(&Value::Bool(false)) {
        return None;
    }
    let constraints: Map<String, Value> = set
        .iter()
        .filter(|(urn, _)| !urn.starts_with("urn:x-nmos:cap:meta:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (!constraints.is_empty()).then_some(constraints)
}

/// Every set that one of `a` and one of `b` both allow, up to [`MOST_SETS`].
fn combine(a: &[Map<String, Value>], b: &[Map<String, Value>]) -> Vec<Map<String, Value>> {
    let mut out: Vec<Map<String, Value>> = Vec::new();
    for x in a {
        for y in b {
            if let Some(both) = intersect(x, y)
                && !out.contains(&both)
                && out.len() < MOST_SETS
            {
                out.push(both);
            }
        }
    }
    out
}

/// The constraint set that allows only what both `a` and `b` do, or `None` when
/// nothing is allowed by both.
pub(crate) fn intersect(a: &Map<String, Value>, b: &Map<String, Value>) -> Option<Map<String, Value>> {
    let mut out = a.clone();
    for (urn, constraint) in b {
        let merged = match a.get(urn) {
            None => constraint.clone(),
            Some(mine) => merge(mine, constraint)?,
        };
        out.insert(urn.clone(), merged);
    }
    Some(out)
}

/// One parameter constraint that allows only what both do: the values both list, the
/// higher minimum and the lower maximum.
fn merge(a: &Value, b: &Value) -> Option<Value> {
    let (a, b) = (a.as_object()?, b.as_object()?);
    let bound = |name: &str, pick: Ordering| -> Option<Value> {
        match (a.get(name), b.get(name)) {
            (Some(x), Some(y)) => Some(if order(x, y) == Some(pick) { x.clone() } else { y.clone() }),
            (x, y) => x.or(y).cloned(),
        }
    };
    let minimum = bound("minimum", Ordering::Greater);
    let maximum = bound("maximum", Ordering::Less);
    if let (Some(low), Some(high)) = (&minimum, &maximum)
        && order(low, high) == Some(Ordering::Greater)
    {
        return None;
    }
    let within = |v: &Value| {
        minimum.as_ref().is_none_or(|low| order(v, low) != Some(Ordering::Less))
            && maximum.as_ref().is_none_or(|high| order(v, high) != Some(Ordering::Greater))
    };
    let values: Option<Vec<Value>> =
        match (a.get("enum").and_then(Value::as_array), b.get("enum").and_then(Value::as_array)) {
            (Some(x), Some(y)) => Some(x.iter().filter(|v| y.iter().any(|w| same(v, w))).cloned().collect()),
            (Some(x), None) | (None, Some(x)) => Some(x.clone()),
            (None, None) => None,
        };
    let mut out = Map::new();
    if let Some(values) = values {
        let values: Vec<Value> = values.into_iter().filter(|v| within(v)).collect();
        if values.is_empty() {
            return None;
        }
        out.insert("enum".into(), Value::Array(values));
    }
    if let Some(minimum) = minimum {
        out.insert("minimum".into(), minimum);
    }
    if let Some(maximum) = maximum {
        out.insert("maximum".into(), maximum);
    }
    Some(Value::Object(out))
}

/// A number, or a rational as a fraction with a positive denominator.
fn fraction(value: &Value) -> Option<(f64, f64)> {
    if let Some(n) = value.as_f64() {
        return Some((n, 1.0));
    }
    let o = value.as_object()?;
    let n = o.get("numerator")?.as_f64()?;
    let d = o.get("denominator").map_or(Some(1.0), Value::as_f64)?;
    match d.partial_cmp(&0.0)? {
        Ordering::Equal => None,
        Ordering::Less => Some((-n, -d)),
        Ordering::Greater => Some((n, d)),
    }
}

/// Orders two numbers or rationals, cross-multiplied (BCP-004-01).
fn order(a: &Value, b: &Value) -> Option<Ordering> {
    let ((n1, d1), (n2, d2)) = (fraction(a)?, fraction(b)?);
    (n1 * d2).partial_cmp(&(n2 * d1))
}

/// Whether two constraint values are the same: numbers and rationals by value.
fn same(a: &Value, b: &Value) -> bool {
    match order(a, b) {
        Some(ordering) => ordering == Ordering::Equal,
        None => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn intersections_keep_what_both_allow() {
        let rate = "urn:x-nmos:cap:format:grain_rate";
        let width = "urn:x-nmos:cap:format:frame_width";
        let a = set(json!({rate: {"enum": [{"numerator": 25}, {"numerator": 50}]}, width: {"maximum": 1920}}));
        let b = set(json!({rate: {"enum": [{"numerator": 100, "denominator": 2}]}, width: {"minimum": 1280}}));
        assert_eq!(
            Value::Object(intersect(&a, &b).unwrap()),
            json!({rate: {"enum": [{"numerator": 50}]}, width: {"minimum": 1280, "maximum": 1920}})
        );
        let c = set(json!({width: {"enum": [3840]}}));
        assert_eq!(intersect(&a, &c), None, "3840 is above 1920");
        let d = set(json!({width: {"minimum": 2000}}));
        assert_eq!(intersect(&a, &d), None, "the range is empty");
        // A constraint only one has is kept as it is.
        let e = set(json!({"urn:x-nmos:cap:format:interlace_mode": {"enum": ["progressive"]}}));
        assert_eq!(intersect(&a, &e).unwrap().len(), 3);
        assert_eq!(combine(&[a, c], &[b, d]).len(), 3, "a with b, c with b, c with d");
    }

    #[test]
    fn disabled_sets_and_metadata_are_left_out() {
        assert_eq!(
            enabled(&json!({"urn:x-nmos:cap:meta:enabled": false, "urn:x-nmos:cap:format:frame_width": {}})),
            None
        );
        assert_eq!(
            enabled(
                &json!({"urn:x-nmos:cap:meta:preference": 10, "urn:x-nmos:cap:format:frame_width": {"enum": [1920]}})
            ),
            Some(set(json!({"urn:x-nmos:cap:format:frame_width": {"enum": [1920]}})))
        );
        assert_eq!(enabled(&json!({"urn:x-nmos:cap:meta:label": "nothing"})), None);
    }
}
