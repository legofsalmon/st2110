//! The Receiver of `st2110 receive --nmos`: what an IS-05 activation does to what it
//! receives. The stream's format comes from the transport file, the SDP file a
//! controller stages with the Sender's id, and the transport parameters say which
//! groups, sources and ports to join it on, as they override the file's.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use st2110_media::describe::Description;

use super::Role;
use super::connection::Side;

/// What to receive now.
#[derive(Clone, Debug)]
pub(crate) struct Tuned {
    pub description: Description,
    /// How the SDP file's legs were read.
    pub notes: Vec<String>,
    /// The Sender it comes from, when the controller said.
    pub sender_id: Option<String>,
    /// The interface to receive each leg on, as IS-05 has it.
    pub interfaces: Vec<Option<Ipv4Addr>>,
}

/// What the Receiver is told to receive, shared with the loop that receives it.
#[derive(Default)]
pub(crate) struct Tuning {
    current: Mutex<Option<Tuned>>,
    /// Raised when it changes, for the receiving to stop and start again.
    pub changed: AtomicBool,
}

impl Tuning {
    /// What to receive now, lowering [`Tuning::changed`].
    pub(crate) fn take(&self) -> Option<Tuned> {
        self.changed.store(false, Ordering::SeqCst);
        self.current.lock().ok()?.clone()
    }

    fn set(&self, tuned: Option<Tuned>) {
        if let Ok(mut current) = self.current.lock() {
            *current = tuned;
        }
        self.changed.store(true, Ordering::SeqCst);
    }
}

/// What an IS-05 activation does to `st2110 receive`.
pub(crate) struct Receiving {
    tuning: Arc<Tuning>,
    /// Whether the interfaces were given, to receive on them; the system picks
    /// otherwise.
    given: bool,
}

impl Receiving {
    pub(crate) fn new(tuning: Arc<Tuning>, given: bool) -> Self {
        Self { tuning, given }
    }
}

/// The stream that active or staged parameters describe: the transport file's, joined
/// as the transport parameters say. `None` when there is no file.
fn read(params: &Value, given: bool) -> Result<Option<Tuned>, String> {
    let file = &params["transport_file"];
    let Some(sdp) = file["data"].as_str() else {
        return Ok(None);
    };
    if let Some(kind) = file["type"].as_str()
        && !kind.eq_ignore_ascii_case("application/sdp")
    {
        return Err(format!("the transport_file is {kind}, and this Receiver takes application/sdp"));
    }
    let (mut description, notes) =
        Description::parse(sdp).map_err(|e| format!("the transport_file is not a stream this Receiver takes: {e}"))?;
    let ip = |value: &Value| value.as_str().and_then(|ip| ip.parse::<Ipv4Addr>().ok());
    let all = params["transport_params"].as_array().cloned().unwrap_or_default();
    let mut legs = Vec::new();
    let mut interfaces = Vec::new();
    for (leg, params) in description.legs.iter().zip(&all) {
        if params["rtp_enabled"] == false {
            continue;
        }
        let mut leg = *leg;
        if let Some(group) = ip(&params["multicast_ip"]) {
            leg.destination.set_ip(group);
        }
        if let Some(port) = params["destination_port"].as_u64().and_then(|p| u16::try_from(p).ok()) {
            leg.destination.set_port(port);
        }
        if let Some(source) = ip(&params["source_ip"]) {
            leg.source = Some(source);
        }
        legs.push(leg);
        interfaces.push(ip(&params["interface_ip"]).filter(|_| given));
    }
    if legs.is_empty() {
        return Err("the transport_params turn off every leg the transport_file has".into());
    }
    description.legs = legs;
    let sender_id = params["sender_id"].as_str().map(str::to_string);
    Ok(Some(Tuned { description, notes, sender_id, interfaces }))
}

impl Role for Receiving {
    fn side(&self) -> Side {
        Side::Receiver
    }

    fn check(&self, staged: &Value) -> Result<(), String> {
        let tuned = read(staged, self.given)?;
        if staged["master_enable"] == true && tuned.is_none() {
            return Err("this Receiver learns the stream's format from its SDP file: give a transport_file".into());
        }
        Ok(())
    }

    fn activate(&mut self, active: &mut Value) {
        let tuned = if active["master_enable"] == true { read(active, self.given).ok().flatten() } else { None };
        self.tuning.set(tuned);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=CAM 1\r\nt=0 0\r\n\
        m=audio 5004 RTP/AVP 97\r\nc=IN IP4 239.1.1.1/32\r\na=source-filter: incl IN IP4 239.1.1.1 192.168.10.21\r\n\
        a=rtpmap:97 L24/48000/2\r\na=ptime:1\r\na=ts-refclk:localmac=02-00-00-00-00-01\r\na=mediaclk:direct=0\r\n";

    #[test]
    fn joins_where_the_transport_params_say() {
        let tuning = Arc::new(Tuning::default());
        let mut receiving = Receiving::new(tuning.clone(), true);
        let mut active = json!({
            "sender_id": "5e0d", "master_enable": true,
            "transport_file": {"data": SDP, "type": "application/sdp"},
            "transport_params": [
                {"source_ip": "192.168.10.22", "multicast_ip": "239.1.1.2", "interface_ip": "127.0.0.1",
                 "destination_port": 5006, "rtp_enabled": true},
                {"rtp_enabled": false},
            ],
        });
        assert!(receiving.check(&active).is_ok());
        receiving.activate(&mut active);
        assert!(tuning.changed.load(Ordering::SeqCst));
        let tuned = tuning.take().expect("a stream");
        assert!(!tuning.changed.load(Ordering::SeqCst));
        assert_eq!(tuned.description.legs.len(), 1);
        assert_eq!(tuned.description.legs[0].destination.to_string(), "239.1.1.2:5006");
        assert_eq!(tuned.description.legs[0].source, Some(Ipv4Addr::new(192, 168, 10, 22)));
        assert_eq!(tuned.interfaces, [Some(Ipv4Addr::LOCALHOST)]);
        assert_eq!(tuned.sender_id.as_deref(), Some("5e0d"));
        // Off, it receives nothing; on with no file, it cannot be.
        active["master_enable"] = json!(false);
        receiving.activate(&mut active);
        assert!(tuning.take().is_none());
        let bare = json!({"master_enable": true, "transport_file": {"data": null, "type": null}});
        assert!(receiving.check(&bare).unwrap_err().contains("give a transport_file"));
        let wrong = json!({"transport_file": {"data": "v=0", "type": "application/sdp"}});
        assert!(receiving.check(&wrong).is_err());
    }
}
