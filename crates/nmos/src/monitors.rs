//! What each Device's IS-12 status monitors say (BCP-008-01 for Receivers, BCP-008-02
//! for Senders), as a controller shows it, and the checks a registry read and one read
//! of each monitor can make.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::Snapshot;
use crate::model::{Core, Kind, Model};
use crate::ncp::{self, class};
use crate::report::{DomainStatus, Findings, MonitorCounter, MonitorView, ReceiverView, SenderView};
use crate::routing::{is_ws, ncp_href};
use crate::rules::{MONITOR_ACTIVITY, MONITOR_STATUS, MONITOR_TOUCHPOINT, NCP_CONTROL};

/// The domain statuses a monitor of each kind has, as `(property prefix, domain)`, in
/// the order BCP-008 lists them.
const RECEIVER_DOMAINS: [(&str, &str); 4] = [
    ("link", "link"),
    ("connection", "connection"),
    ("externalSynchronization", "synchronization"),
    ("stream", "stream"),
];
const SENDER_DOMAINS: [(&str, &str); 4] = [
    ("link", "link"),
    ("transmission", "transmission"),
    ("externalSynchronization", "synchronization"),
    ("essence", "essence"),
];

/// Which kind of resource a monitor of this class watches.
fn watches(class_id: &[i64]) -> Option<Kind> {
    if ncp::derives(class_id, class::RECEIVER_MONITOR) {
        Some(Kind::Receiver)
    } else if ncp::derives(class_id, class::SENDER_MONITOR) {
        Some(Kind::Sender)
    } else {
        None
    }
}

/// The name of a status property's value, such as `Unhealthy`.
fn status_name(monitor: &Value, class_id: &[i64], property: &str) -> Option<String> {
    let value = monitor["properties"][property].as_u64()?;
    let kind = ncp::known_class(class_id)?.property_named(property)?.type_name?;
    Some(ncp::enum_name(kind, value).map_or_else(|| value.to_string(), str::to_string))
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string)
}

/// A monitor as a controller lists it, from what [`crate::ncp::client::Connection::read_monitor`]
/// read of it at `href`: whether it watches a Sender or a Receiver, and its statuses.
pub fn view(href: &str, monitor: &Value) -> Option<(Kind, MonitorView)> {
    let class_id = ncp::class_id(&monitor["classId"])?;
    let kind = watches(&class_id)?;
    let domains = if kind == Kind::Receiver { RECEIVER_DOMAINS } else { SENDER_DOMAINS };
    let properties = &monitor["properties"];
    let domains = domains
        .iter()
        .filter_map(|(prefix, domain)| {
            Some(DomainStatus {
                domain: (*domain).to_string(),
                status: status_name(monitor, &class_id, &format!("{prefix}Status"))?,
                message: text(&properties[format!("{prefix}StatusMessage")]),
                transitions: properties[format!("{prefix}StatusTransitionCounter")].as_u64(),
            })
        })
        .collect();
    let counters = monitor["counters"]
        .as_object()
        .into_iter()
        .flatten()
        .flat_map(|(kind, list)| {
            list.as_array().into_iter().flatten().filter_map(move |c| {
                Some(MonitorCounter {
                    kind: kind.clone(),
                    name: c["name"].as_str()?.to_string(),
                    value: c["value"].as_u64()?,
                })
            })
        })
        .collect();
    Some((
        kind,
        MonitorView {
            href: href.to_string(),
            role: monitor["role"].as_str().unwrap_or_default().to_string(),
            overall: status_name(monitor, &class_id, "overallStatus"),
            overall_message: text(&properties["overallStatusMessage"]),
            domains,
            synchronization_source: text(&properties["synchronizationSourceId"]),
            counters,
        },
    ))
}

/// The monitors read, each with the Device it is on and the resource its touchpoint
/// names.
struct Read<'s> {
    device: String,
    href: &'s str,
    monitor: &'s Value,
    kind: Option<Kind>,
    /// The resources its `x-nmos` touchpoints name, as `(resourceType, id)`.
    named: Vec<(&'s str, &'s str)>,
}

fn reads(snapshot: &Snapshot) -> Vec<Read<'_>> {
    let mut found = Vec::new();
    for (device, entry) in &snapshot.ncp {
        let href = entry["href"].as_str().unwrap_or_default();
        for monitor in entry["monitors"].as_array().into_iter().flatten() {
            let kind = ncp::class_id(&monitor["classId"]).and_then(|c| watches(&c));
            let named = ncp::touchpoint_resources(&monitor["touchpoints"]);
            found.push(Read { device: device.clone(), href, monitor, kind, named });
        }
    }
    found
}

/// Gives each Sender and Receiver the status of the monitor that watches it.
pub(crate) fn views(snapshot: &Snapshot, senders: &mut [SenderView], receivers: &mut [ReceiverView]) {
    let mut by_id: BTreeMap<(Kind, &str), MonitorView> = BTreeMap::new();
    for read in reads(snapshot) {
        let Some((kind, view)) = view(read.href, read.monitor) else { continue };
        let wanted = kind.as_str();
        if let Some((_, id)) = read.named.iter().find(|(t, _)| *t == wanted) {
            by_id.entry((kind, id)).or_insert(view);
        }
    }
    for sender in senders {
        sender.monitor = sender.id.as_deref().and_then(|id| by_id.get(&(Kind::Sender, id)).cloned());
    }
    for receiver in receivers {
        receiver.monitor = receiver.id.as_deref().and_then(|id| by_id.get(&(Kind::Receiver, id)).cloned());
    }
}

/// Checks each Device's IS-12 endpoint and the monitors read from it.
pub(crate) fn check(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    let prefix = format!("{}/", ncp::CONTROL_PREFIX);
    for device in &model.devices {
        let controls: Vec<_> =
            device.controls.iter().flatten().filter(|c| c.kind.starts_with(ncp::CONTROL_PREFIX)).collect();
        for control in &controls {
            if !control.kind.starts_with(&prefix) {
                findings.add(
                    &NCP_CONTROL,
                    &device.core,
                    format!(
                        "its IS-12 control is typed {}, with no version: IS-12 v1.0 is {}",
                        control.kind,
                        ncp::CONTROL_TYPE
                    ),
                );
            } else if !is_ws(control.href) {
                findings.add(
                    &NCP_CONTROL,
                    &device.core,
                    format!(
                        "its IS-12 control is at {}, which is not a ws:// or wss:// URL: IS-12 runs over WebSocket",
                        control.href
                    ),
                );
            }
        }
        if ncp_href(device).is_none() {
            continue;
        }
        let Some(entry) = device.core.id.and_then(|id| snapshot.ncp.get(id)) else { continue };
        if let Some(error) = entry["error"].as_str() {
            findings.add(
                &NCP_CONTROL,
                &device.core,
                format!("its IS-12 control at {} cannot be read: {error}", entry["href"].as_str().unwrap_or("?")),
            );
            continue;
        }
        let root = &entry["root"];
        if root["role"] != "root" {
            findings.add(&NCP_CONTROL, &device.core, format!("its root block's role is {}, not root", root["role"]));
        }
        let members = root["members"].as_array().map(Vec::as_slice).unwrap_or_default();
        for (role, wanted) in [("DeviceManager", class::DEVICE_MANAGER), ("ClassManager", class::CLASS_MANAGER)] {
            let held = members
                .iter()
                .any(|m| m["role"] == role && ncp::class_id(&m["classId"]).is_some_and(|c| ncp::derives(&c, wanted)));
            if !held {
                findings.add(
                    &NCP_CONTROL,
                    &device.core,
                    format!("its root block holds no {role}, which every MS-05-02 Device has"),
                );
            }
        }
    }
    touchpoints(model, snapshot, findings);
    statuses(model, snapshot, findings);
}

/// Each monitor names one Sender or Receiver of its own Device, and no two the same.
fn touchpoints(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    let mut watched: BTreeMap<(Kind, &str), Vec<String>> = BTreeMap::new();
    for read in reads(snapshot) {
        let Some(kind) = read.kind else { continue };
        let Some(device) = model.device(&read.device) else { continue };
        let role = read.monitor["role"].as_str().unwrap_or("?");
        let wanted = kind.as_str();
        let what = if kind == Kind::Receiver { "Receiver monitor" } else { "Sender monitor" };
        let named: Vec<&str> = read.named.iter().filter(|(t, _)| *t == wanted).map(|(_, id)| *id).collect();
        let [id] = named.as_slice() else {
            findings.add(
                &MONITOR_TOUCHPOINT,
                &device.core,
                format!(
                    "its {what} {role} names {} {wanted}s in its touchpoints, where it names exactly one",
                    named.len()
                ),
            );
            continue;
        };
        let device_of = match kind {
            Kind::Receiver => model.receiver(id).map(|r| r.device_id),
            _ => model.sender(id).map(|s| s.device_id),
        };
        match device_of {
            None => findings.add(
                &MONITOR_TOUCHPOINT,
                &device.core,
                format!("its {what} {role} watches {wanted} {id}, which is not registered"),
            ),
            Some(of) if of != Some(read.device.as_str()) => findings.add(
                &MONITOR_TOUCHPOINT,
                &device.core,
                format!("its {what} {role} watches {wanted} {id}, which belongs to another Device"),
            ),
            Some(_) => watched.entry((kind, id)).or_default().push(role.to_string()),
        }
    }
    for ((kind, id), roles) in watched {
        if roles.len() > 1
            && let Some(core) = model.first(kind, id)
        {
            findings.add(
                &MONITOR_TOUCHPOINT,
                core,
                format!("{} monitors watch it ({}), where each has its own", roles.len(), roles.join(", ")),
            );
        }
    }
}

/// What each monitor says of the Sender or Receiver it watches.
fn statuses(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    for read in reads(snapshot) {
        let Some((kind, view)) = view(read.href, read.monitor) else { continue };
        let Some((_, id)) = read.named.iter().find(|(t, _)| *t == kind.as_str()) else { continue };
        let (core, active): (&Core<'_>, Option<bool>) = match kind {
            Kind::Receiver => match model.receiver(id) {
                Some(r) => (&r.core, Some(r.active())),
                None => continue,
            },
            _ => match model.sender(id) {
                Some(s) => (&s.core, s.active()),
                None => continue,
            },
        };
        let Some(overall) = view.overall.as_deref() else { continue };
        if matches!(overall, "Unhealthy" | "PartiallyHealthy") {
            let causes: Vec<String> = view
                .domains
                .iter()
                .filter(|d| matches!(d.status.as_str(), "Unhealthy" | "PartiallyHealthy" | "SomeDown" | "AllDown"))
                .map(|d| match &d.message {
                    Some(message) => format!("{} {}: {message}", d.domain, d.status),
                    None => format!("{} {}", d.domain, d.status),
                })
                .collect();
            let mut message = format!("its monitor {} says {overall}", view.role);
            if let Some(said) = &view.overall_message {
                message.push_str(&format!(": {said}"));
            }
            if !causes.is_empty() {
                message.push_str(&format!(" ({})", causes.join("; ")));
            }
            findings.add(&MONITOR_STATUS, core, message);
        }
        let Some(active) = active else { continue };
        let neutral = |domain: &str| view.domains.iter().find(|d| d.domain == domain).map(|d| d.status == "Inactive");
        let (moving, content) =
            if kind == Kind::Receiver { ("connection", "stream") } else { ("transmission", "essence") };
        let inactive = overall == "Inactive";
        if active == inactive {
            findings.add(
                &MONITOR_ACTIVITY,
                core,
                format!(
                    "the registry has it {}, and its monitor {} says {overall}",
                    if active { "active" } else { "inactive" },
                    view.role
                ),
            );
        } else if !active {
            let still: Vec<&str> = [moving, content].into_iter().filter(|d| neutral(d) == Some(false)).collect();
            if !still.is_empty() {
                findings.add(
                    &MONITOR_ACTIVITY,
                    core,
                    format!(
                        "it is inactive, and its monitor {} still gives a {} status other than Inactive",
                        view.role,
                        still.join(" and ")
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::check;

    const DEVICE: &str = "58f6b536-ca4c-43fd-880a-9df2501fc125";
    const RECEIVER: &str = "82fdc03f-76c7-4989-9d05-3ea2cc98875e";
    const SENDER: &str = "9bfe1101-5513-45fa-ae3b-7e668e317bd5";
    const NODE: &str = "d1713110-7343-4d9e-b3f4-456c8f6ce765";

    fn monitor(class_id: Value, role: &str, kind: &str, id: &str, properties: Value) -> Value {
        json!({"role": role, "oid": 4, "classId": class_id, "touchpoints": [ncp::touchpoint(kind, id)],
               "properties": properties, "counters": {"lost": [{"name": "lost", "value": 12, "description": null}]}})
    }

    fn snapshot(controls: Value, ncp: Option<Value>, active: bool) -> Snapshot {
        let core =
            |id: &str, label: &str| json!({"id": id, "version": "1:0", "label": label, "description": "", "tags": {}});
        let mut device = core(DEVICE, "box");
        device["node_id"] = json!(NODE);
        device["type"] = json!("urn:x-nmos:device:generic");
        device["senders"] = json!([]);
        device["receivers"] = json!([]);
        device["controls"] = controls;
        let mut receiver = core(RECEIVER, "MON 1");
        for (k, v) in [
            ("device_id", json!(DEVICE)),
            ("transport", json!("urn:x-nmos:transport:rtp")),
            ("format", json!("urn:x-nmos:format:audio")),
            ("caps", json!({})),
            ("interface_bindings", json!([])),
            ("subscription", json!({"sender_id": null, "active": active})),
        ] {
            receiver[k] = v;
        }
        Snapshot {
            devices: vec![device],
            receivers: vec![receiver],
            ncp: ncp.map(|n| [(DEVICE.to_string(), n)].into()).unwrap_or_default(),
            ..Snapshot::default()
        }
    }

    fn rules(snapshot: &Snapshot) -> Vec<(&'static str, String)> {
        check(snapshot)
            .findings
            .into_iter()
            .filter(|f| f.rule.starts_with("ncp") || f.rule.starts_with("monitor"))
            .map(|f| (f.rule, f.message))
            .collect()
    }

    const HREF: &str = "ws://192.168.10.21/x-nmos/ncp/v1.0/";

    fn root() -> Value {
        json!({"role": "root", "members": [
            {"role": "DeviceManager", "oid": 2, "classId": [1, 3, 1]},
            {"role": "ClassManager", "oid": 3, "classId": [1, 3, 2]},
        ]})
    }

    #[test]
    fn shows_a_receivers_monitor_and_what_it_says() {
        let properties = json!({
            "overallStatus": 3, "overallStatusMessage": "No packets arrive",
            "linkStatus": 1, "connectionStatus": 3, "connectionStatusMessage": "No packets arrive",
            "connectionStatusTransitionCounter": 2, "externalSynchronizationStatus": 0, "streamStatus": 1,
            "synchronizationSourceId": "internal",
        });
        let read = json!({"href": HREF, "root": root(), "monitors": [
            monitor(json!([1, 2, 2, 1]), "receiver-monitor", "receiver", RECEIVER, properties),
        ]});
        let snapshot = snapshot(json!([{"type": ncp::CONTROL_TYPE, "href": HREF}]), Some(read), true);
        let report = check(&snapshot);
        let view = report.receivers[0].monitor.as_ref().expect("a monitor");
        assert_eq!(view.overall.as_deref(), Some("Unhealthy"));
        assert_eq!(view.domains[1].domain, "connection");
        assert_eq!((view.domains[1].status.as_str(), view.domains[1].transitions), ("Unhealthy", Some(2)));
        assert_eq!(view.domains[2].status, "NotUsed");
        assert_eq!(view.counters[0].value, 12);
        let found = rules(&snapshot);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "monitor-status");
        assert!(found[0].1.contains("says Unhealthy: No packets arrive (connection Unhealthy: No packets arrive)"));
    }

    #[test]
    fn finds_monitors_that_say_otherwise_than_the_registry() {
        let inactive = json!({"overallStatus": 0, "linkStatus": 1, "connectionStatus": 1, "streamStatus": 0});
        let read = json!({"href": HREF, "root": root(), "monitors": [
            monitor(json!([1, 2, 2, 1]), "m", "receiver", RECEIVER, inactive.clone()),
        ]});
        let found = rules(&snapshot(json!([{"type": ncp::CONTROL_TYPE, "href": HREF}]), Some(read.clone()), true));
        assert_eq!(found, [("monitor-activity", "the registry has it active, and its monitor m says Inactive".into())]);
        let found = rules(&snapshot(json!([{"type": ncp::CONTROL_TYPE, "href": HREF}]), Some(read), false));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].1.contains("still gives a connection status other than Inactive"), "{found:?}");
    }

    #[test]
    fn finds_touchpoints_that_name_nothing_known_and_endpoints_that_are_not_websockets() {
        let ok = json!({"overallStatus": 1, "linkStatus": 1, "connectionStatus": 1, "streamStatus": 1});
        let read = json!({"href": HREF, "root": {"role": "root", "members": []}, "monitors": [
            monitor(json!([1, 2, 2, 1]), "a", "receiver", SENDER, ok.clone()),
            monitor(json!([1, 2, 2, 1, 0, 1]), "b", "receiver", RECEIVER, ok.clone()),
            monitor(json!([1, 2, 2, 1]), "c", "receiver", RECEIVER, ok.clone()),
            monitor(json!([1, 2, 2, 2]), "d", "receiver", RECEIVER, ok),
        ]});
        let controls =
            json!([{"type": ncp::CONTROL_TYPE, "href": HREF}, {"type": "urn:x-nmos:control:ncp", "href": HREF}]);
        let found = rules(&snapshot(controls, Some(read), true));
        let messages: Vec<&str> = found.iter().map(|(_, m)| m.as_str()).collect();
        assert!(messages.contains(&"its IS-12 control is typed urn:x-nmos:control:ncp, with no version: IS-12 v1.0 is urn:x-nmos:control:ncp/v1.0"), "{messages:#?}");
        assert!(
            messages.contains(&"its root block holds no DeviceManager, which every MS-05-02 Device has"),
            "{messages:#?}"
        );
        assert!(
            messages.contains(
                &format!("its Receiver monitor a watches receiver {SENDER}, which is not registered").as_str()
            ),
            "{messages:#?}"
        );
        assert!(
            messages.contains(&"its Sender monitor d names 0 senders in its touchpoints, where it names exactly one"),
            "{messages:#?}"
        );
        assert!(messages.contains(&"2 monitors watch it (b, c), where each has its own"), "{messages:#?}");

        let found = rules(&snapshot(json!([{"type": ncp::CONTROL_TYPE, "href": "http://x/"}]), None, false));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].1.contains("not a ws:// or wss:// URL"));
        let unread = json!({"href": HREF, "error": "connection refused"});
        let found = rules(&snapshot(json!([{"type": ncp::CONTROL_TYPE, "href": HREF}]), Some(unread), false));
        assert_eq!(found, [("ncp-control", format!("its IS-12 control at {HREF} cannot be read: connection refused"))]);
    }
}
