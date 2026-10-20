//! A controller's side of IS-12: commands to a Device's control endpoint, and the
//! notifications it subscribes to.
//!
//! [`Connection::monitors`] finds every status monitor in the Device model by its class
//! (BCP-008-01 and -02 Controllers: "All blocks inside an MS-05-02 device allow
//! searching for members by their class id") and reads each one's statuses, messages,
//! touchpoints and counters. A controller that follows them then subscribes and reads
//! [`Connection::next_change`], rather than reading them again: BCP-008 forbids polling.
//!
//! ```no_run
//! use std::time::Duration;
//! use st2110_nmos::ncp::client::Connection;
//!
//! let mut device = Connection::open("ws://192.168.10.21:8080/x-nmos/ncp/v1.0/", &[], Duration::from_secs(5))?;
//! let monitors = device.monitors()?;
//! let oids: Vec<u64> = monitors.iter().filter_map(|m| m["oid"].as_u64()).collect();
//! device.subscribe(&oids)?;
//! device.set_read_timeout(None)?;
//! while let Some(change) = device.next_change()? {
//!     println!("{} {:?} is now {}", change.oid, change.property, change.value);
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::{ElementId, class, message, method, property};
use crate::ws::{self, Frame};

/// A property that changed, from a `PropertyChanged` notification.
#[derive(Clone, Debug, PartialEq)]
pub struct Notification {
    /// The object it changed on.
    pub oid: u64,
    /// The property.
    pub property: ElementId,
    /// Its value now; for a sequence item change, the item.
    pub value: Value,
}

/// A connection to a Device's IS-12 endpoint.
#[derive(Debug)]
pub struct Connection {
    socket: ws::Socket,
    url: String,
    next_handle: u64,
    /// Notifications that arrived while an answer was awaited.
    queued: VecDeque<Notification>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl Connection {
    /// Connects to the endpoint at `url`, a `ws://` or `wss://` URL from a Device's
    /// `controls`, sending `headers` with the handshake (an IS-10 token, where one is
    /// needed) and waiting `timeout` at most for each answer.
    pub fn open(url: &str, headers: &[(&str, &str)], timeout: Duration) -> io::Result<Self> {
        let socket = ws::connect(url, headers, timeout)?;
        Ok(Self { socket, url: url.to_string(), next_handle: 1, queued: VecDeque::new() })
    }

    /// The endpoint's URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// How long a read waits; `None` waits as long as it takes.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Calls methods, each `(oid, method, arguments)`, in one `Command` message, and
    /// gives each one's result in order: an `NcMethodResult`, with its `status` and,
    /// for most, a `value`, or an `errorMessage` where it failed.
    pub fn call_all(&mut self, calls: &[(u64, ElementId, Value)]) -> io::Result<Vec<Value>> {
        let first = self.next_handle;
        self.next_handle += calls.len() as u64;
        let commands: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, (oid, method, arguments))| {
                json!({"handle": first + i as u64, "oid": oid, "methodId": method.json(), "arguments": arguments})
            })
            .collect();
        let text = json!({"messageType": message::COMMAND, "commands": commands}).to_string();
        self.socket.send(&Frame::Text(text))?;
        let mut results: Vec<Option<Value>> = vec![None; calls.len()];
        while results.iter().any(Option::is_none) {
            let reply = self.read_message()?;
            if reply["messageType"] != message::COMMAND_RESPONSE {
                continue;
            }
            for response in reply["responses"].as_array().into_iter().flatten() {
                let Some(handle) = response["handle"].as_u64() else { continue };
                if let Some(slot) = handle.checked_sub(first).and_then(|i| results.get_mut(i as usize)) {
                    *slot = Some(response["result"].clone());
                }
            }
        }
        Ok(results.into_iter().flatten().collect())
    }

    /// Calls one method, and gives its result, or fails with the Device's status and
    /// message where the result is an error.
    pub fn call(&mut self, oid: u64, method: ElementId, arguments: Value) -> io::Result<Value> {
        let result = self.call_all(&[(oid, method, arguments)])?.pop().unwrap_or(Value::Null);
        succeeded(&result).map(|()| result)
    }

    /// The value of one property.
    pub fn get(&mut self, oid: u64, property: ElementId) -> io::Result<Value> {
        let mut result = self.call(oid, method::GET, json!({"id": property.json()}))?;
        Ok(result["value"].take())
    }

    /// Subscribes to the events of these objects, and gives those the Device took.
    /// Each `Subscription` replaces the last, so it names every object wanted.
    pub fn subscribe(&mut self, oids: &[u64]) -> io::Result<Vec<u64>> {
        self.socket.send(&Frame::Text(super::subscription(oids).to_string()))?;
        loop {
            let reply = self.read_message()?;
            if reply["messageType"] == message::SUBSCRIPTION_RESPONSE {
                return Ok(reply["subscriptions"].as_array().into_iter().flatten().filter_map(Value::as_u64).collect());
            }
        }
    }

    /// The next property change: one that arrived already, or the next to arrive.
    /// `None` once the Device closes the connection. A read that times out fails with
    /// `WouldBlock` or `TimedOut`, and can be tried again.
    pub fn next_change(&mut self) -> io::Result<Option<Notification>> {
        loop {
            if let Some(change) = self.queued.pop_front() {
                return Ok(Some(change));
            }
            match self.read_message() {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    /// Pings the Device, to keep a quiet connection open and find out it is still there.
    pub fn ping(&mut self) -> io::Result<()> {
        self.socket.send(&Frame::Ping(Vec::new()))
    }

    /// Closes the connection.
    pub fn close(self) {
        self.socket.close();
    }

    /// Reads one IS-12 message, queuing the notifications it carries. An `Error`
    /// message fails.
    fn read_message(&mut self) -> io::Result<Value> {
        let text = loop {
            match self.socket.read_any()? {
                Frame::Text(text) => break text,
                Frame::Close(_) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the Device closed it")),
                _ => {}
            }
        };
        let message: Value = serde_json::from_str(&text).map_err(|e| invalid(format!("not an IS-12 message: {e}")))?;
        match message["messageType"].as_u64() {
            Some(message::NOTIFICATION) => {
                for n in message["notifications"].as_array().into_iter().flatten() {
                    let (Some(oid), Some(property)) =
                        (n["oid"].as_u64(), ElementId::from_json(&n["eventData"]["propertyId"]))
                    else {
                        continue;
                    };
                    self.queued.push_back(Notification { oid, property, value: n["eventData"]["value"].clone() });
                }
            }
            Some(message::ERROR) => {
                return Err(io::Error::other(format!(
                    "the Device answered with an error, status {}: {}",
                    message["status"],
                    message["errorMessage"].as_str().unwrap_or("no message")
                )));
            }
            _ => {}
        }
        Ok(message)
    }

    /// The descriptors of the root block's members.
    pub fn members(&mut self) -> io::Result<Vec<Value>> {
        Ok(self.get(1, property::MEMBERS)?.as_array().cloned().unwrap_or_default())
    }

    /// Every status monitor in the Device model, each read whole ([`Connection::read_monitor`]).
    pub fn monitors(&mut self) -> io::Result<Vec<Value>> {
        let found = self.call(
            1,
            method::FIND_MEMBERS_BY_CLASS_ID,
            json!({"classId": class::STATUS_MONITOR, "includeDerived": true, "recurse": true}),
        )?;
        let descriptors = found["value"].as_array().cloned().unwrap_or_default();
        descriptors.iter().map(|d| self.read_monitor(d)).collect()
    }

    /// One monitor, by its block member descriptor: its role, oid, class, label,
    /// touchpoints, every property of its class by name, and its counters.
    pub fn read_monitor(&mut self, descriptor: &Value) -> io::Result<Value> {
        let oid = descriptor["oid"].as_u64().ok_or_else(|| invalid("a member descriptor with no oid"))?;
        let class_id = super::class_id(&descriptor["classId"]).unwrap_or_default();
        let known = super::known_class(&class_id);
        let properties: Vec<super::Property> = known
            .map(|c| c.properties())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.id.level >= 2 || p.id == property::TOUCHPOINTS)
            .collect();
        let mut calls: Vec<(u64, ElementId, Value)> =
            properties.iter().map(|p| (oid, method::GET, json!({"id": p.id.json()}))).collect();
        let counters: &[(&str, ElementId)] = if super::derives(&class_id, class::RECEIVER_MONITOR) {
            &[("lost", method::GET_LOST_PACKET_COUNTERS), ("late", method::GET_LATE_PACKET_COUNTERS)]
        } else if super::derives(&class_id, class::SENDER_MONITOR) {
            &[("transmission_errors", method::GET_TRANSMISSION_ERROR_COUNTERS)]
        } else {
            &[]
        };
        calls.extend(counters.iter().map(|(_, m)| (oid, *m, json!({}))));
        let results = self.call_all(&calls)?;
        let mut read = Map::new();
        let mut failed = Map::new();
        for (p, result) in properties.iter().zip(&results) {
            match succeeded(result) {
                Ok(()) => read.insert(p.name.to_string(), result["value"].clone()),
                Err(e) => failed.insert(p.name.to_string(), json!(e.to_string())),
            };
        }
        let mut counted = Map::new();
        for ((name, _), result) in counters.iter().zip(&results[properties.len()..]) {
            match succeeded(result) {
                Ok(()) => counted.insert(name.to_string(), result["value"].clone()),
                Err(e) => failed.insert(name.to_string(), json!(e.to_string())),
            };
        }
        let touchpoints = read.remove("touchpoints").unwrap_or(Value::Null);
        let mut monitor = json!({
            "role": descriptor["role"], "oid": oid, "classId": descriptor["classId"],
            "userLabel": descriptor["userLabel"], "touchpoints": touchpoints,
            "properties": read, "counters": counted,
        });
        if !failed.is_empty() {
            monitor["failed"] = Value::Object(failed);
        }
        Ok(monitor)
    }
}

/// `Ok` where an `NcMethodResult` says the call succeeded (2xx), otherwise the status
/// and the Device's message.
pub fn succeeded(result: &Value) -> io::Result<()> {
    match result["status"].as_u64() {
        Some(status) if (200..300).contains(&status) => Ok(()),
        status => Err(io::Error::other(format!(
            "status {}: {}",
            status.map_or("none".into(), |s| s.to_string()),
            result["errorMessage"].as_str().unwrap_or("no message")
        ))),
    }
}

/// Reads what a controller lists of a Device's control endpoint at `href`: the root
/// block's role and members, and every status monitor. What could not be read is
/// recorded in `error`, not returned.
pub fn read_device(href: &str, headers: &[(&str, &str)], timeout: Duration) -> Value {
    let read = || -> io::Result<Value> {
        let mut device = Connection::open(href, headers, timeout)?;
        let role = device.get(1, property::ROLE)?;
        let members = device.members()?;
        let monitors = device.monitors()?;
        device.close();
        Ok(json!({"href": href, "root": {"role": role, "members": members}, "monitors": monitors}))
    };
    read().unwrap_or_else(|e| json!({"href": href, "error": e.to_string()}))
}

/// Applies a property-changed notification to a monitor as [`Connection::read_monitor`]
/// read it, so that a controller keeps it current without asking again. Gives whether
/// the notification was for one of its properties.
pub fn apply(monitor: &mut Value, notification: &Notification) -> bool {
    if monitor["oid"].as_u64() != Some(notification.oid) {
        return false;
    }
    let Some(class) = super::class_id(&monitor["classId"]).and_then(|id| super::known_class(&id)) else {
        return false;
    };
    let Some(changed) = class.properties().into_iter().find(|p| p.id == notification.property) else {
        return false;
    };
    if changed.id == property::TOUCHPOINTS {
        monitor["touchpoints"] = notification.value.clone();
    } else if changed.id.level >= 2 {
        monitor["properties"][changed.name] = notification.value.clone();
    }
    true
}
