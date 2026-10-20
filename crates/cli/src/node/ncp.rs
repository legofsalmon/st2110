//! The Node's IS-12 v1.0.1 control endpoint: a WebSocket at `/x-nmos/ncp/v1.0/` on the
//! Node's port, which its Device lists in `controls` as `urn:x-nmos:control:ncp/v1.0`.
//!
//! The Device model is the MS-05-02 minimum and one monitor: the root block (oid 1,
//! role `root`), the `DeviceManager` (2), the `ClassManager` (3) and an
//! `NcReceiverMonitor` or `NcSenderMonitor` (4, role `receiver-monitor` or
//! `sender-monitor`) whose touchpoint names the Receiver or Sender ([`super::monitor`]).
//! The oids are the same on every run.
//!
//! Every object answers `Get`, `Set` (the user label, the DeviceManager's names, and the
//! monitor's `statusReportingDelay` and `autoResetCountersAndMessages`) and the sequence
//! methods; the root block its searches; the ClassManager every class and datatype
//! descriptor; the monitor its counters and `ResetCountersAndMessages`. A controller
//! subscribes to any of them and hears each property change as a notification.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_nmos::ncp::{self, Class, ElementId, class, message, method, property};
use st2110_nmos::ws::{self, Frame};

use super::connection::Side;
use super::monitor::{MOST_DELAY, Monitor, Sync};
use crate::http::{self, Request, Response};

/// Where the endpoint is, on the Node's port.
pub(crate) const PATH: &str = "/x-nmos/ncp/v1.0";

const ROOT: u64 = 1;
const DEVICE_MANAGER: u64 = 2;
const CLASS_MANAGER: u64 = 3;
const MONITOR: u64 = 4;

/// The most controllers connected at once.
const MOST_SESSIONS: usize = 16;

/// The largest message a controller may send.
const MESSAGE_LIMIT: usize = 1 << 20;

/// How long a controller may be silent before it is pinged, and then before it is let go.
const QUIET: Duration = Duration::from_secs(15);

/// Who the Device is.
pub(crate) struct Identity<'a> {
    pub side: Side,
    /// The Device's label.
    pub label: &'a str,
    pub device_id: &'a str,
    /// The Sender's or Receiver's id.
    pub endpoint_id: &'a str,
    pub hostname: &'a str,
}

/// The Device model, and what changed in it.
pub(crate) struct Model {
    /// Every object but the monitor: its class and property values.
    objects: BTreeMap<u64, (&'static Class, BTreeMap<ElementId, Value>)>,
    pub monitor: Monitor,
    monitor_class: &'static Class,
    /// Properties of objects other than the monitor that changed.
    changes: Vec<(u64, ElementId, Value)>,
}

fn ok(value: Value) -> Value {
    json!({"status": 200, "value": value})
}

fn failed(status: u16, message: impl Into<String>) -> Value {
    json!({"status": status, "errorMessage": message.into()})
}

/// The NcObject properties of an object.
fn object(
    class: &Class,
    oid: u64,
    owner: Option<u64>,
    role: &str,
    label: Value,
    touchpoints: Value,
) -> BTreeMap<ElementId, Value> {
    BTreeMap::from([
        (property::CLASS_ID, json!(class.id)),
        (property::OID, json!(oid)),
        (property::CONSTANT_OID, json!(true)),
        (property::OWNER, json!(owner)),
        (property::ROLE, json!(role)),
        (property::USER_LABEL, label),
        (property::TOUCHPOINTS, touchpoints),
        (property::RUNTIME_PROPERTY_CONSTRAINTS, Value::Null),
    ])
}

impl Model {
    pub(crate) fn new(identity: &Identity<'_>, sync: &Sync, active: bool, now: Instant) -> Self {
        let class_of = |id| ncp::class(id).expect("a class of the model");
        let root_class = class_of(class::BLOCK);
        let mut root = object(
            root_class,
            ROOT,
            None,
            "root",
            json!(identity.label),
            json!([ncp::touchpoint("device", identity.device_id)]),
        );
        root.insert(property::ENABLED, json!(true));
        let devices_class = class_of(class::DEVICE_MANAGER);
        let mut device =
            object(devices_class, DEVICE_MANAGER, Some(ROOT), "DeviceManager", json!("Device manager"), Value::Null);
        let product = match identity.side {
            Side::Sender => "st2110 send",
            Side::Receiver => "st2110 receive",
        };
        for (id, value) in [
            ((3, 1), json!(ncp::NC_VERSION)),
            ((3, 2), json!({"name": "st2110", "organizationId": null, "website": env!("CARGO_PKG_REPOSITORY")})),
            (
                (3, 3),
                json!({"name": product, "key": "st2110", "revisionLevel": env!("CARGO_PKG_VERSION"), "brandName": null,
                       "uuid": null, "description": "A software ST 2110 sender or receiver, run as an NMOS Node"}),
            ),
            ((3, 4), json!(identity.hostname)),
            ((3, 5), Value::Null),
            ((3, 6), Value::Null),
            ((3, 7), Value::Null),
            ((3, 8), json!({"generic": 1, "deviceSpecificDetails": null})),
            ((3, 9), json!(1)),
            ((3, 10), Value::Null),
        ] {
            device.insert(ElementId::new(id.0, id.1), value);
        }
        let classes_class = class_of(class::CLASS_MANAGER);
        let mut classes =
            object(classes_class, CLASS_MANAGER, Some(ROOT), "ClassManager", json!("Class manager"), Value::Null);
        classes.insert(ElementId::new(3, 1), json!(ncp::control_classes()));
        classes.insert(ElementId::new(3, 2), json!(ncp::datatypes()));
        let (monitor_class, role, kind) = match identity.side {
            Side::Receiver => (class_of(class::RECEIVER_MONITOR), "receiver-monitor", "receiver"),
            Side::Sender => (class_of(class::SENDER_MONITOR), "sender-monitor", "sender"),
        };
        let watched = object(
            monitor_class,
            MONITOR,
            Some(ROOT),
            role,
            json!(format!("{} monitor", identity.side.name())),
            json!([ncp::touchpoint(kind, identity.endpoint_id)]),
        );
        let monitor = Monitor::new(identity.side, watched, sync, active, now);
        Self {
            objects: BTreeMap::from([
                (ROOT, (root_class, root)),
                (DEVICE_MANAGER, (devices_class, device)),
                (CLASS_MANAGER, (classes_class, classes)),
            ]),
            monitor,
            monitor_class,
            changes: Vec::new(),
        }
    }

    fn class_of(&self, oid: u64) -> Option<&'static Class> {
        if oid == MONITOR { Some(self.monitor_class) } else { self.objects.get(&oid).map(|(c, _)| *c) }
    }

    fn value(&self, oid: u64, id: ElementId) -> Option<Value> {
        if oid == ROOT && id == property::MEMBERS {
            return Some(json!(self.members()));
        }
        if oid == MONITOR { self.monitor.get(id).cloned() } else { self.objects.get(&oid)?.1.get(&id).cloned() }
    }

    /// The root block's members' descriptors.
    fn members(&self) -> Vec<Value> {
        [DEVICE_MANAGER, CLASS_MANAGER, MONITOR]
            .into_iter()
            .filter_map(|oid| {
                let class = self.class_of(oid)?;
                let get = |id| self.value(oid, id).unwrap_or(Value::Null);
                Some(json!({
                    "description": class.description, "role": get(property::ROLE), "oid": oid, "constantOid": true,
                    "classId": class.id, "userLabel": get(property::USER_LABEL), "owner": ROOT,
                }))
            })
            .collect()
    }

    /// Every object's oid, for subscriptions.
    fn oids(&self) -> BTreeSet<u64> {
        self.objects.keys().copied().chain([MONITOR]).collect()
    }

    /// Calls a method of an object, and gives its `NcMethodResult`.
    pub(crate) fn command(&mut self, oid: u64, method: ElementId, arguments: &Value, now: Instant) -> Value {
        let Some(class) = self.class_of(oid) else {
            return failed(404, format!("there is no object {oid}"));
        };
        if !class.has_method(method) {
            return failed(501, format!("{} has no method {}m{}", class.name, method.level, method.index));
        }
        let property = |name: &str| -> Result<ncp::Property, Value> {
            let id = ElementId::from_json(&arguments[name])
                .ok_or_else(|| failed(417, format!("{name} is not a property id: {{\"level\": …, \"index\": …}}")))?;
            class
                .property(id)
                .ok_or_else(|| failed(502, format!("{} has no property {}p{}", class.name, id.level, id.index)))
        };
        let flag = |name: &str| arguments[name].as_bool();
        match method {
            method::GET => match property("id") {
                Ok(p) => ok(self.value(oid, p.id).unwrap_or(Value::Null)),
                Err(e) => e,
            },
            method::SET => match property("id") {
                Ok(p) if p.read_only => failed(405, format!("{} is read only", p.name)),
                Ok(p) => self.set(oid, p, arguments["value"].clone(), now),
                Err(e) => e,
            },
            method::GET_SEQUENCE_ITEM | method::GET_SEQUENCE_LENGTH => {
                let p = match property("id") {
                    Ok(p) if p.sequence => p,
                    Ok(p) => return failed(417, format!("{} is not a sequence", p.name)),
                    Err(e) => return e,
                };
                let value = self.value(oid, p.id).unwrap_or(Value::Null);
                if method == method::GET_SEQUENCE_LENGTH {
                    return ok(json!(value.as_array().map(Vec::len)));
                }
                let index = arguments["index"].as_u64().and_then(|i| usize::try_from(i).ok());
                match index.and_then(|i| value.as_array()?.get(i)) {
                    Some(item) => ok(item.clone()),
                    None => failed(414, format!("{} has no item {}", p.name, arguments["index"])),
                }
            }
            method::SET_SEQUENCE_ITEM | method::ADD_SEQUENCE_ITEM | method::REMOVE_SEQUENCE_ITEM => {
                match property("id") {
                    Ok(p) if p.read_only => failed(405, format!("{} is read only", p.name)),
                    Ok(p) => failed(417, format!("{} is not a sequence that can change", p.name)),
                    Err(e) => e,
                }
            }
            method::GET_MEMBER_DESCRIPTORS => ok(json!(self.members())),
            method::FIND_MEMBERS_BY_PATH => {
                let path: Option<Vec<&str>> =
                    arguments["path"].as_array().and_then(|p| p.iter().map(Value::as_str).collect());
                match path.as_deref() {
                    Some([role]) => {
                        ok(json!(self.members().into_iter().filter(|m| m["role"] == *role).collect::<Vec<_>>()))
                    }
                    Some(_) => ok(json!([])),
                    None => failed(417, "path is not a sequence of roles"),
                }
            }
            method::FIND_MEMBERS_BY_ROLE => {
                let (Some(role), Some(case), Some(whole)) =
                    (arguments["role"].as_str(), flag("caseSensitive"), flag("matchWholeString"))
                else {
                    return failed(417, "give role, caseSensitive, matchWholeString and recurse");
                };
                let fold = |s: &str| if case { s.to_string() } else { s.to_lowercase() };
                let wanted = fold(role);
                let found: Vec<Value> = self
                    .members()
                    .into_iter()
                    .filter(|m| {
                        let have = fold(m["role"].as_str().unwrap_or_default());
                        if whole { have == wanted } else { have.contains(&wanted) }
                    })
                    .collect();
                ok(json!(found))
            }
            method::FIND_MEMBERS_BY_CLASS_ID => {
                let (Some(wanted), Some(derived)) = (ncp::class_id(&arguments["classId"]), flag("includeDerived"))
                else {
                    return failed(417, "give classId, includeDerived and recurse");
                };
                let found: Vec<Value> = self
                    .members()
                    .into_iter()
                    .filter(|m| {
                        let id = ncp::class_id(&m["classId"]).unwrap_or_default();
                        if derived { ncp::derives(&id, &wanted) } else { id == wanted }
                    })
                    .collect();
                ok(json!(found))
            }
            method::GET_CONTROL_CLASS => {
                let found = ncp::class_id(&arguments["classId"]).and_then(|id| ncp::class(&id));
                match found {
                    Some(c) => ok(c.descriptor(flag("includeInherited").unwrap_or(false))),
                    None => failed(404, format!("this Device has no class {}", arguments["classId"])),
                }
            }
            method::GET_DATATYPE => {
                let found = arguments["name"]
                    .as_str()
                    .and_then(|name| ncp::datatype(name, flag("includeInherited").unwrap_or(false)));
                match found {
                    Some(d) => ok(d),
                    None => failed(404, format!("this Device has no datatype {}", arguments["name"])),
                }
            }
            _ => self.monitor_method(method, now),
        }
    }

    /// The methods of a Receiver or Sender monitor.
    fn monitor_method(&mut self, method: ElementId, now: Instant) -> Value {
        let receiver = ncp::derives(self.monitor_class.id, class::RECEIVER_MONITOR);
        let counters = |kind| ok(json!(self.monitor.counters(kind)));
        match (receiver, method) {
            (true, method::GET_LOST_PACKET_COUNTERS) => counters("lost"),
            (true, method::GET_LATE_PACKET_COUNTERS) => counters("late"),
            (false, method::GET_TRANSMISSION_ERROR_COUNTERS) => counters("errors"),
            (true, method::RESET_RECEIVER_COUNTERS) | (false, method::RESET_SENDER_COUNTERS) => {
                self.monitor.reset();
                self.monitor.update(now);
                json!({"status": 200})
            }
            _ => failed(501, format!("method {}m{} is not implemented", method.level, method.index)),
        }
    }

    /// Sets a property that is not read only.
    fn set(&mut self, oid: u64, p: ncp::Property, value: Value, now: Instant) -> Value {
        let text = value.is_null() || value.is_string();
        match (oid, p.id) {
            (_, property::USER_LABEL) if !text => return failed(417, "userLabel is a string or null"),
            (MONITOR, property::USER_LABEL) => self.monitor.set_label(value),
            (MONITOR, property::ENABLED) => {
                return failed(406, "a monitor's enabled has no meaning (BCP-008), so it stays true");
            }
            (MONITOR, property::STATUS_REPORTING_DELAY) => match value.as_u64().filter(|s| *s <= MOST_DELAY) {
                Some(seconds) => self.monitor.set_delay(seconds, now),
                None => return failed(417, format!("statusReportingDelay is 0 to {MOST_DELAY} seconds")),
            },
            (MONITOR, property::AUTO_RESET) => match value.as_bool() {
                Some(on) => self.monitor.set_auto_reset(on),
                None => return failed(417, "autoResetCountersAndMessages is true or false"),
            },
            (MONITOR, _) => return failed(405, format!("{} cannot be set", p.name)),
            (DEVICE_MANAGER, id) if id.level == 3 && !text => {
                return failed(417, format!("{} is a string or null", p.name));
            }
            (_, id) => {
                let Some((_, values)) = self.objects.get_mut(&oid) else { return failed(404, "no such object") };
                if values.get(&id) != Some(&value) {
                    values.insert(id, value.clone());
                    self.changes.push((oid, id, value));
                }
            }
        }
        json!({"status": 200})
    }

    /// Every property that changed since this was last asked, by object.
    pub(crate) fn take_changes(&mut self) -> Vec<(u64, ElementId, Value)> {
        let mut changes = std::mem::take(&mut self.changes);
        changes.extend(self.monitor.take_changes().into_iter().map(|(id, value)| (MONITOR, id, value)));
        changes
    }

    pub(crate) fn has_changes(&self) -> bool {
        !self.changes.is_empty() || self.monitor.has_changes()
    }

    /// Answers one message from a controller, keeping its subscriptions.
    pub(crate) fn message(&mut self, text: &str, subscribed: &mut BTreeSet<u64>, now: Instant) -> Value {
        let error = |status: u16, message: String| json!({"messageType": message::ERROR, "status": status, "errorMessage": message});
        let message: Value = match serde_json::from_str(text) {
            Ok(message) => message,
            Err(e) => return error(400, format!("not JSON: {e}")),
        };
        match message["messageType"].as_u64() {
            Some(message::COMMAND) => {
                let Some(commands) = message["commands"].as_array() else {
                    return error(400, "a Command message has commands".into());
                };
                let mut responses = Vec::new();
                for command in commands {
                    let (Some(handle), Some(oid), Some(method)) = (
                        command["handle"].as_u64(),
                        command["oid"].as_u64(),
                        ElementId::from_json(&command["methodId"]),
                    ) else {
                        return error(400, "each command has a numeric handle and oid, and a methodId".into());
                    };
                    let arguments = command.get("arguments").cloned().unwrap_or_else(|| json!({}));
                    responses.push(json!({"handle": handle, "result": self.command(oid, method, &arguments, now)}));
                }
                json!({"messageType": message::COMMAND_RESPONSE, "responses": responses})
            }
            Some(message::SUBSCRIPTION) => {
                let Some(wanted) = message["subscriptions"].as_array() else {
                    return error(400, "a Subscription message has subscriptions".into());
                };
                let known = self.oids();
                *subscribed = wanted.iter().filter_map(Value::as_u64).filter(|oid| known.contains(oid)).collect();
                json!({"messageType": message::SUBSCRIPTION_RESPONSE, "subscriptions": subscribed.iter().collect::<Vec<_>>()})
            }
            Some(other) => error(400, format!("messageType {other} is not one a controller sends")),
            None => error(400, "no messageType".into()),
        }
    }
}

/// A controller connected to the endpoint.
pub(crate) struct Session {
    id: u64,
    stream: Mutex<TcpStream>,
    subscribed: Mutex<BTreeSet<u64>>,
}

impl Session {
    fn send(&self, frame: &Frame) -> io::Result<()> {
        let mut stream = self.stream.lock().map_err(|_| io::Error::other("the connection failed"))?;
        ws::write_frame(&mut *stream, frame, None)
    }
}

/// The controllers connected.
#[derive(Default)]
pub(crate) struct Sessions {
    next: AtomicU64,
    list: Mutex<Vec<Arc<Session>>>,
}

impl Sessions {
    fn add(&self, stream: &TcpStream) -> Option<Arc<Session>> {
        let mut list = self.list.lock().ok()?;
        if list.len() >= MOST_SESSIONS {
            return None;
        }
        let stream = stream.try_clone().ok()?;
        // A controller that stops reading is let go rather than holding up the rest.
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
        let session = Arc::new(Session {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            stream: stream.into(),
            subscribed: Mutex::default(),
        });
        list.push(session.clone());
        Some(session)
    }

    fn remove(&self, id: u64) {
        if let Ok(mut list) = self.list.lock() {
            list.retain(|s| s.id != id);
        }
    }

    /// Tells each controller of the changes to the objects it subscribed to.
    pub(crate) fn notify(&self, changes: &[(u64, ElementId, Value)]) {
        if changes.is_empty() {
            return;
        }
        let list: Vec<Arc<Session>> = self.list.lock().map(|l| l.clone()).unwrap_or_default();
        for session in list {
            let subscribed = session.subscribed.lock().map(|s| s.clone()).unwrap_or_default();
            let notifications: Vec<Value> = changes
                .iter()
                .filter(|(oid, _, _)| subscribed.contains(oid))
                .map(|(oid, id, value)| {
                    json!({"oid": oid, "eventId": ncp::PROPERTY_CHANGED.json(), "eventData": {
                        "propertyId": id.json(), "changeType": 0, "value": value, "sequenceItemIndex": null,
                    }})
                })
                .collect();
            if notifications.is_empty() {
                continue;
            }
            let text = json!({"messageType": message::NOTIFICATION, "notifications": notifications}).to_string();
            if session.send(&Frame::Text(text)).is_err() {
                self.remove(session.id);
            }
        }
    }
}

/// A request to the endpoint: becomes a WebSocket, and answers the controller until it
/// goes.
pub(crate) fn serve(shared: &super::Shared, stream: &TcpStream, request: &Request) {
    if let Err((status, why)) = http::accept(stream, request) {
        let message = format!("{why}: the IS-12 control endpoint is a WebSocket");
        let _ = http::write(stream, &Response::json(status, &super::connection::error(status, "", &message).1));
        return;
    }
    let Some(session) = shared.sessions.add(stream) else {
        let _ = ws::write_frame(&mut &*stream, &Frame::Close(Some(1013)), None);
        return;
    };
    let _ = stream.set_read_timeout(Some(QUIET));
    let mut reader = stream;
    let mut pinged = false;
    loop {
        match ws::read_frame(&mut reader, MESSAGE_LIMIT) {
            Ok(Frame::Text(text)) => {
                pinged = false;
                let reply = {
                    let mut subscribed = session.subscribed.lock().map(|s| s.clone()).unwrap_or_default();
                    let reply = shared.lock().ncp.message(&text, &mut subscribed, Instant::now());
                    if let Ok(mut held) = session.subscribed.lock() {
                        *held = subscribed;
                    }
                    reply
                };
                if session.send(&Frame::Text(reply.to_string())).is_err() {
                    break;
                }
                shared.notify();
            }
            Ok(Frame::Ping(payload)) => {
                if session.send(&Frame::Pong(payload)).is_err() {
                    break;
                }
            }
            Ok(Frame::Close(code)) => {
                let _ = session.send(&Frame::Close(code.or(Some(1000))));
                break;
            }
            Ok(Frame::Binary(_)) => {
                let error = json!({"messageType": message::ERROR, "status": 400, "errorMessage": "IS-12 messages are JSON text"});
                if session.send(&Frame::Text(error.to_string())).is_err() {
                    break;
                }
            }
            Ok(Frame::Pong(_)) => pinged = false,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) && !pinged => {
                pinged = true;
                if session.send(&Frame::Ping(Vec::new())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    shared.sessions.remove(session.id);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Model {
        let identity = Identity {
            side: Side::Receiver,
            label: "st2110 receive on test",
            device_id: "58f6b536-ca4c-43fd-880a-9df2501fc125",
            endpoint_id: "82fdc03f-76c7-4989-9d05-3ea2cc98875e",
            hostname: "test",
        };
        Model::new(&identity, &Sync::internal(), false, Instant::now())
    }

    fn call(model: &mut Model, oid: u64, method: ElementId, arguments: Value) -> Value {
        model.command(oid, method, &arguments, Instant::now())
    }

    #[test]
    fn answers_as_ms_05_02_has_it() {
        let mut m = model();
        let get = |m: &mut Model, oid, id: ElementId| call(m, oid, method::GET, json!({"id": id.json()}));
        assert_eq!(get(&mut m, 1, property::ROLE), json!({"status": 200, "value": "root"}));
        assert_eq!(get(&mut m, 1, property::OWNER)["value"], Value::Null);
        let members = get(&mut m, 1, property::MEMBERS)["value"].clone();
        let roles: Vec<&str> = members.as_array().unwrap().iter().map(|d| d["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["DeviceManager", "ClassManager", "receiver-monitor"]);
        assert_eq!(get(&mut m, 4, property::CLASS_ID)["value"], json!([1, 2, 2, 1]));
        assert_eq!(get(&mut m, 4, property::TOUCHPOINTS)["value"][0]["resource"]["resourceType"], "receiver");
        assert_eq!(get(&mut m, 4, property::OVERALL_STATUS)["value"], 0);
        assert_eq!(get(&mut m, 2, ElementId::new(3, 1))["value"], "v1.0.0");
        assert_eq!(get(&mut m, 9, property::ROLE)["status"], 404);
        assert_eq!(get(&mut m, 2, ElementId::new(4, 1))["status"], 502);
        assert_eq!(call(&mut m, 2, method::GET_MEMBER_DESCRIPTORS, json!({"recurse": true}))["status"], 501);

        let set = |m: &mut Model, oid, id: ElementId, value| {
            call(m, oid, method::SET, json!({"id": id.json(), "value": value}))
        };
        assert_eq!(set(&mut m, 4, property::ROLE, json!("x"))["status"], 405);
        assert_eq!(set(&mut m, 4, property::ENABLED, json!(false))["status"], 406);
        assert_eq!(set(&mut m, 4, property::STATUS_REPORTING_DELAY, json!(-1))["status"], 417);
        assert_eq!(set(&mut m, 4, property::STATUS_REPORTING_DELAY, json!(0))["status"], 200);
        assert_eq!(set(&mut m, 1, property::USER_LABEL, json!("Booth"))["status"], 200);
        assert_eq!(set(&mut m, 2, ElementId::new(3, 6), json!(7))["status"], 417);
        let changes = m.take_changes();
        assert!(changes.contains(&(1, property::USER_LABEL, json!("Booth"))), "{changes:?}");
        assert!(changes.contains(&(4, property::STATUS_REPORTING_DELAY, json!(0))), "{changes:?}");

        let found = call(
            &mut m,
            1,
            method::FIND_MEMBERS_BY_CLASS_ID,
            json!({"classId": [1, 2, 2], "includeDerived": true, "recurse": true}),
        );
        assert_eq!(found["value"].as_array().unwrap().len(), 1);
        let exact = call(
            &mut m,
            1,
            method::FIND_MEMBERS_BY_CLASS_ID,
            json!({"classId": [1, 2, 2], "includeDerived": false, "recurse": true}),
        );
        assert_eq!(exact["value"], json!([]));
        let by_role = call(
            &mut m,
            1,
            method::FIND_MEMBERS_BY_ROLE,
            json!({"role": "MANAGER", "caseSensitive": false, "matchWholeString": false, "recurse": true}),
        );
        assert_eq!(by_role["value"].as_array().unwrap().len(), 2);
        let by_path = call(&mut m, 1, method::FIND_MEMBERS_BY_PATH, json!({"path": ["receiver-monitor"]}));
        assert_eq!(by_path["value"][0]["oid"], 4);
        assert_eq!(call(&mut m, 1, method::GET_SEQUENCE_LENGTH, json!({"id": property::MEMBERS.json()}))["value"], 3);
        assert_eq!(
            call(&mut m, 1, method::GET_SEQUENCE_ITEM, json!({"id": property::MEMBERS.json(), "index": 5}))["status"],
            414
        );
        assert_eq!(
            call(&mut m, 1, method::ADD_SEQUENCE_ITEM, json!({"id": property::MEMBERS.json(), "value": {}}))["status"],
            405
        );

        let class =
            call(&mut m, 3, method::GET_CONTROL_CLASS, json!({"classId": [1, 2, 2, 1], "includeInherited": true}));
        assert_eq!(class["value"]["name"], "NcReceiverMonitor");
        let datatype = call(&mut m, 3, method::GET_DATATYPE, json!({"name": "NcCounter", "includeInherited": false}));
        assert_eq!(datatype["value"]["fields"].as_array().unwrap().len(), 3);
        assert_eq!(call(&mut m, 4, method::GET_LOST_PACKET_COUNTERS, json!({}))["value"][0]["name"], "lost");
        assert_eq!(call(&mut m, 4, method::RESET_RECEIVER_COUNTERS, json!({}))["status"], 200);
    }

    #[test]
    fn keeps_subscriptions_and_refuses_what_it_cannot_read() {
        let mut m = model();
        let mut subscribed = BTreeSet::new();
        let now = Instant::now();
        let reply = m.message(r#"{"messageType": 3, "subscriptions": [1, 4, 111]}"#, &mut subscribed, now);
        assert_eq!(reply, json!({"messageType": 4, "subscriptions": [1, 4]}));
        assert_eq!(subscribed, BTreeSet::from([1, 4]));
        let reply = m.message(
            r#"{"messageType": 0, "commands": [{"handle": 2, "oid": 4, "methodId": {"level": 1, "index": 1},
                "arguments": {"id": {"level": 3, "index": 3}}}]}"#,
            &mut subscribed,
            now,
        );
        assert_eq!(
            reply,
            json!({"messageType": 1, "responses": [{"handle": 2, "result": {"status": 200, "value": 3}}]})
        );
        assert_eq!(m.message("{", &mut subscribed, now)["messageType"], 5);
        assert_eq!(m.message(r#"{"messageType": 1}"#, &mut subscribed, now)["status"], 400);
        let missing = m.message(r#"{"messageType": 0, "commands": [{"oid": 1}]}"#, &mut subscribed, now);
        assert_eq!(missing["messageType"], 5);
    }
}
