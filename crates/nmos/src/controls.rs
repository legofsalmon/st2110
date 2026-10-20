//! Checks of what a Device's other control APIs say, beside the registry: BCP-004-02
//! Sender capabilities, IS-11 stream compatibility, IS-08 channel maps and the IS-09
//! System API, and the views of them a report lists.

use std::collections::BTreeSet;

use serde_json::Value;
use st2110_sdp::{RefClock, Stream};

use crate::Snapshot;
use crate::caps::{self, SdpFacts, StreamFacts};
use crate::check::list;
use crate::model::{Model, Sender};
use crate::report::{
    ChannelMapView, ChannelRoute, Findings, InterfaceView, NodeView, OutputMap, ReceiverView, SenderView, SystemView,
};
use crate::rules::*;

/// What a Sender's SDP file told the check, where it had one.
pub(crate) struct SenderSdp<'s> {
    pub facts: &'s SdpFacts,
    pub streams: &'s [Stream],
}

/// Why a list of BCP-004 constraint sets says too little: no `caps.version`, or a set
/// with no parameter constraint. `whose` names the resource, such as `Receiver`.
pub(crate) fn set_problems(sets: &[Value], version: Option<&str>, whose: &str) -> Vec<String> {
    let mut problems = Vec::new();
    if version.is_none() {
        problems.push(
            "it has caps.constraint_sets but no caps.version, so a controller cannot tell when they change".into(),
        );
    }
    for (i, set) in sets.iter().enumerate() {
        let constraints =
            set.as_object().map_or(0, |set| set.keys().filter(|k| !k.starts_with("urn:x-nmos:cap:meta:")).count());
        if constraints == 0 {
            problems.push(format!(
                "constraint set {i} holds no parameter constraint, so it says nothing about what the {whose} {}",
                if whose == "Sender" { "sends" } else { "takes" }
            ));
        }
    }
    problems
}

/// Checks each Sender's BCP-004-02 capabilities: that they say something, and that the
/// stream it sends is one of them.
pub(crate) fn sender_caps(model: &Model<'_>, sdps: &[Option<SenderSdp<'_>>], findings: &mut Findings) {
    for (sender, sdp) in model.senders.iter().zip(sdps) {
        let Some(sets) = sender.constraint_sets else { continue };
        for problem in set_problems(sets, sender.caps_version, "Sender") {
            findings.add(&SENDER_CAPS, &sender.core, problem);
        }
        if sets.is_empty() || sender.active() == Some(false) {
            continue;
        }
        let (Some(flow), source) = model.flow_of(sender) else { continue };
        let facts = StreamFacts { flow, source, sender, sdp: sdp.as_ref().map(|s| s.facts) };
        if let Err(reasons) = caps::evaluate(sets, &facts) {
            findings.add(
                &SENDER_CAPS,
                &sender.core,
                format!("it sends a stream none of its own constraint sets allows: {}", reasons.join("; ")),
            );
        }
    }
}

/// A resource's IS-11 `status`: its `state`, and its `debug` text when it has one.
fn status(entry: Option<&Value>) -> Option<(&str, Option<&str>)> {
    let status = entry?.get("status")?;
    let state = status.get("state")?.as_str()?;
    let debug = status.get("debug").and_then(Value::as_str).map(str::trim).filter(|d| !d.is_empty());
    Some((state, debug))
}

fn with_debug(text: String, debug: Option<&str>) -> String {
    match debug {
        Some(debug) => format!("{text} ({debug})"),
        None => text,
    }
}

/// Checks what each Sender's and Receiver's IS-11 API says of it.
pub(crate) fn stream_compat(
    model: &Model<'_>,
    snapshot: &Snapshot,
    sdps: &[Option<SenderSdp<'_>>],
    findings: &mut Findings,
) {
    for (sender, sdp) in model.senders.iter().zip(sdps) {
        let Some(entry) = sender.core.id.and_then(|id| snapshot.stream_compat.get(id)) else { continue };
        let core = &sender.core;
        let state = status(Some(entry));
        match state {
            Some(("active_constraints_violation", debug)) => {
                findings.add(
                    &STREAM_COMPAT,
                    core,
                    with_debug(
                        "its IS-11 status is active_constraints_violation: what it would send breaks the constraints \
                         a controller set"
                            .into(),
                        debug,
                    ),
                );
                if sender.active() == Some(true) {
                    findings.add(
                        &ACTIVE_CONSTRAINTS,
                        core,
                        "it is still sending while it violates its active constraints; it must stop until they are \
                         met or changed",
                    );
                }
            }
            Some(("no_essence", debug)) => findings.add(
                &STREAM_COMPAT,
                core,
                with_debug("its IS-11 status is no_essence: it has no signal to send".into(), debug),
            ),
            _ => {}
        }
        let sets = entry.get("active").and_then(|a| a.get("constraint_sets")).and_then(Value::as_array);
        let Some(sets) = sets.filter(|sets| !sets.is_empty()) else { continue };
        if let Some(supported) =
            entry.get("supported").and_then(|s| s.get("parameter_constraints")).and_then(Value::as_array)
        {
            let supported: BTreeSet<&str> = supported.iter().filter_map(Value::as_str).collect();
            let unsupported: BTreeSet<&str> = sets
                .iter()
                .filter_map(Value::as_object)
                .flat_map(|set| set.keys())
                .map(String::as_str)
                .filter(|urn| !urn.starts_with("urn:x-nmos:cap:meta:") && !supported.contains(urn))
                .collect();
            if !unsupported.is_empty() {
                findings.add(
                    &ACTIVE_CONSTRAINTS,
                    core,
                    format!(
                        "its active constraints use {}, which its /constraints/supported does not list",
                        list(unsupported.iter().copied())
                    ),
                );
            }
        }
        if sender.active() != Some(true) || matches!(state, Some(("active_constraints_violation", _))) {
            continue;
        }
        let (Some(flow), source) = model.flow_of(sender) else { continue };
        let facts = StreamFacts { flow, source, sender, sdp: sdp.as_ref().map(|s| s.facts) };
        if let Err(reasons) = caps::evaluate(sets, &facts) {
            findings.add(
                &ACTIVE_CONSTRAINTS,
                core,
                format!(
                    "it sends a stream none of its active constraint sets allows, without saying so in its status: {}",
                    reasons.join("; ")
                ),
            );
        }
    }
    for receiver in model.receivers.iter().filter(|r| r.active()) {
        let entry = receiver.core.id.and_then(|id| snapshot.stream_compat.get(id));
        if let Some(("non_compliant_stream", debug)) = status(entry) {
            findings.add(
                &STREAM_COMPAT,
                &receiver.core,
                with_debug(
                    "its IS-11 status is non_compliant_stream: the stream it takes is not one it can use".into(),
                    debug,
                ),
            );
        }
    }
}

/// Adds the IS-11 state of each Sender and Receiver to its view.
pub(crate) fn compat_views(snapshot: &Snapshot, senders: &mut [SenderView], receivers: &mut [ReceiverView]) {
    let entry = |id: &Option<String>| id.as_deref().and_then(|id| snapshot.stream_compat.get(id));
    for view in senders {
        let entry = entry(&view.id);
        view.compat = status(entry).map(|(state, _)| state.to_string());
        view.active_constraints = entry.and_then(|e| e.get("active")?.get("constraint_sets")?.as_array().map(Vec::len));
    }
    for view in receivers {
        view.compat = status(entry(&view.id)).map(|(state, _)| state.to_string());
    }
}

/// The channel count of an IS-08 Input or Output in `io`, from its `channels`.
fn channels(io: Option<&Value>, side: &str, id: &str) -> Option<usize> {
    io?.get(side)?.get(id)?.get("channels")?.as_array().map(Vec::len)
}

/// Checks each Device's IS-08 active map against its Inputs and Outputs, and lists the
/// maps.
pub(crate) fn channel_maps(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) -> Vec<ChannelMapView> {
    let mut views = Vec::new();
    for device in &model.devices {
        let Some(id) = device.core.id else { continue };
        let Some(entry) = snapshot.channel_mapping.get(id) else { continue };
        let io = entry.get("io");
        let Some(map) = entry.get("active").and_then(|a| a.get("map")).and_then(Value::as_object) else { continue };
        let core = &device.core;
        let mut outputs = Vec::new();
        for (output, routes) in map {
            let known = io.and_then(|io| io.get("outputs")).map(|o| o.get(output).is_some());
            if known == Some(false) {
                findings.add(
                    &CHANNEL_MAP,
                    core,
                    format!("its active map has Output {output}, which its io does not list"),
                );
            }
            let count = channels(io, "outputs", output);
            let routable = io
                .and_then(|io| io.get("outputs")?.get(output)?.get("caps")?.get("routable_inputs"))
                .and_then(Value::as_array);
            let mut channels_routed: Vec<(usize, ChannelRoute)> = Vec::new();
            for (index, route) in routes.as_object().into_iter().flatten() {
                let Ok(index) = index.parse::<usize>() else {
                    findings.add(
                        &CHANNEL_MAP,
                        core,
                        format!("Output {output} has channel {index}, which is not an index"),
                    );
                    continue;
                };
                if let Some(count) = count
                    && index >= count
                {
                    findings.add(
                        &CHANNEL_MAP,
                        core,
                        format!("Output {output} has a channel {index} in the map, but only {count} channels"),
                    );
                }
                let input = route.get("input").and_then(Value::as_str);
                let channel_index = route.get("channel_index").and_then(Value::as_u64);
                if let Some(input) = input {
                    match (channels(io, "inputs", input), channel_index, io.map(|io| io.get("inputs"))) {
                        (None, _, Some(Some(_))) => findings.add(
                            &CHANNEL_MAP,
                            core,
                            format!("Output {output} channel {index} takes Input {input}, which its io does not list"),
                        ),
                        (Some(count), Some(channel), _) if channel as usize >= count => findings.add(
                            &CHANNEL_MAP,
                            core,
                            format!(
                                "Output {output} channel {index} takes channel {channel} of Input {input}, which has \
                                 {count}"
                            ),
                        ),
                        _ => {}
                    }
                    if let Some(routable) = routable
                        && !routable.iter().any(|r| r.as_str() == Some(input))
                    {
                        findings.add(
                            &CHANNEL_MAP,
                            core,
                            format!(
                                "Output {output} channel {index} takes Input {input}, which is not one of the Output's \
                                 routable_inputs"
                            ),
                        );
                    }
                }
                channels_routed.push((index, ChannelRoute { input: input.map(str::to_string), channel_index }));
            }
            channels_routed.sort_by_key(|(index, _)| *index);
            let name = io
                .and_then(|io| io.get("outputs")?.get(output)?.get("properties")?.get("name")?.as_str())
                .map(str::to_string);
            outputs.push(OutputMap {
                id: output.clone(),
                name,
                channels: channels_routed.into_iter().map(|(_, route)| route).collect(),
            });
        }
        views.push(ChannelMapView { device_id: id.to_string(), device: core.label.to_string(), outputs });
    }
    views.sort_by_cached_key(|v| (v.device.to_lowercase(), v.device_id.clone()));
    views
}

/// An integer in `/global`, at `path`, and whether it is from `low` to `high`.
fn global_number(global: &Value, path: &[&str], low: u64, high: u64, problems: &mut Vec<String>) -> Option<u64> {
    let mut value = global;
    for key in path {
        match value.get(key) {
            Some(next) => value = next,
            None => {
                problems.push(format!("it has no {}", path.join(".")));
                return None;
            }
        }
    }
    match value.as_u64() {
        Some(n) if (low..=high).contains(&n) => Some(n),
        _ => {
            problems.push(format!("its {} is {value}, not a whole number from {low} to {high}", path.join(".")));
            None
        }
    }
}

/// Checks what the System API gives, and the PTP domain each Sender's SDP file names
/// against it.
pub(crate) fn system(
    model: &Model<'_>,
    snapshot: &Snapshot,
    sdps: &[Option<SenderSdp<'_>>],
    findings: &mut Findings,
) -> Option<SystemView> {
    let system = snapshot.system.as_ref()?;
    let mut view = SystemView { url: system.url.clone(), ..SystemView::default() };
    let Some(global) = &system.global else {
        let why = system.error.as_deref().unwrap_or("nothing was read");
        findings.system(&SYSTEM_GLOBAL, format!("the System API at {} could not be read: {why}", system.url));
        return Some(view);
    };
    let mut problems = Vec::new();
    view.heartbeat_interval = global_number(global, &["is04", "heartbeat_interval"], 1, 1000, &mut problems);
    view.ptp_domain = global_number(global, &["ptp", "domain_number"], 0, 127, &mut problems);
    view.announce_receipt_timeout = global_number(global, &["ptp", "announce_receipt_timeout"], 2, 10, &mut problems);
    for problem in problems {
        findings.system(&SYSTEM_GLOBAL, format!("the System API's /global: {problem}"));
    }
    if let Some(domain) = view.ptp_domain {
        for (sender, sdp) in model.senders.iter().zip(sdps) {
            let Some(sdp) = sdp else { continue };
            ptp_domain(sender, sdp.streams, domain, findings);
        }
    }
    Some(view)
}

fn ptp_domain(sender: &Sender<'_>, streams: &[Stream], domain: u64, findings: &mut Findings) {
    let named = streams.iter().find_map(|s| match &s.reference_clock {
        Some(RefClock::Ptp { domain: Some(d), .. }) if u64::from(*d) != domain => Some(*d),
        _ => None,
    });
    if let Some(named) = named {
        findings.add(
            &SYSTEM_PTP_DOMAIN,
            &sender.core,
            format!(
                "its SDP file names PTP domain {named}, but the System API gives the system domain {domain}, so its \
                 timestamps may follow another clock"
            ),
        );
    }
}

/// Every Node, with what it says of each interface.
pub(crate) fn node_views(model: &Model<'_>) -> Vec<NodeView> {
    let mut views: Vec<NodeView> = model
        .nodes
        .iter()
        .map(|node| NodeView {
            id: node.core.id.map(str::to_string),
            label: node.core.label.to_string(),
            interfaces: node
                .interfaces
                .iter()
                .flatten()
                .map(|i| InterfaceView {
                    name: i.name.to_string(),
                    chassis_id: i.chassis_id.flatten().map(str::to_string),
                    port_id: i.port_id.map(str::to_string),
                    switch: i.attached.map(|(chassis, _)| chassis.to_string()),
                    switch_port: i.attached.map(|(_, port)| port.to_string()),
                })
                .collect(),
        })
        .collect();
    views.sort_by_cached_key(|n| (n.label.to_lowercase(), n.id.clone()));
    views
}
