//! The Sender of `st2110 send --nmos`: what an IS-05 activation does to the stream as
//! it is sent. A change of destination opens new sockets and the stream goes on there
//! from the next packet; `master_enable` false keeps the stream's time and sends
//! nothing; and the transport file follows.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use st2110_media::describe::{Description, Leg};
use st2110_media::net::{TransmitCounts, Transmitter, tai_now};
use st2110_media::send::Output;

use super::Role;
use super::connection::{Endpoint, Side};

/// Packets due sooner than this are let go at once while the Sender is off, rather
/// than each waited for.
const IDLE_NS: i128 = 1_000_000;

/// The sockets a Sender sends on now, which an activation swaps, or none while it is
/// off.
pub(crate) struct Switch {
    tai_utc: i32,
    transmitter: Mutex<Option<Transmitter>>,
    /// What the sockets swapped out did.
    retired: Mutex<TransmitCounts>,
    /// Packets not sent while the Sender was off.
    held: AtomicU64,
}

impl Switch {
    pub(crate) fn new(transmitter: Transmitter, tai_utc: i32) -> Arc<Self> {
        Arc::new(Self {
            tai_utc,
            transmitter: Mutex::new(Some(transmitter)),
            retired: Mutex::default(),
            held: AtomicU64::new(0),
        })
    }

    /// How every socket kept time so far.
    pub(crate) fn counts(&self) -> TransmitCounts {
        let mut counts = self.retired.lock().map(|c| *c).unwrap_or_default();
        if let Some(now) = self.transmitter.lock().ok().as_ref().and_then(|t| t.as_ref()).map(Transmitter::counts) {
            add(&mut counts, now);
        }
        counts
    }

    /// Packets not sent while the Sender was off.
    pub(crate) fn held(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    fn swap(&self, transmitter: Option<Transmitter>) {
        let Ok(mut held) = self.transmitter.lock() else { return };
        if let Some(old) = std::mem::replace(&mut *held, transmitter)
            && let Ok(mut retired) = self.retired.lock()
        {
            add(&mut retired, old.counts());
        }
    }
}

fn add(counts: &mut TransmitCounts, more: TransmitCounts) {
    counts.sent += more.sent;
    counts.late += more.late;
    counts.latest_ns = counts.latest_ns.max(more.latest_ns);
    counts.refused += more.refused;
}

/// Sends through a [`Switch`].
pub(crate) struct Switched(pub Arc<Switch>);

impl Output for Switched {
    fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()> {
        let mut held = self.0.transmitter.lock().map_err(|_| io::Error::other("the Sender's sockets were lost"))?;
        if let Some(transmitter) = held.as_mut() {
            return transmitter.send(packet, at);
        }
        drop(held);
        self.0.held.fetch_add(1, Ordering::Relaxed);
        // Off: keep the stream's time without sending.
        let wait = at - tai_now(self.0.tai_utc);
        if wait > IDLE_NS {
            thread::sleep(Duration::from_nanos(wait as u64));
        }
        Ok(())
    }

    fn now(&self) -> Option<i128> {
        Some(tai_now(self.0.tai_utc))
    }
}

/// What an IS-05 activation does to `st2110 send`'s stream.
pub(crate) struct Sending {
    /// The stream as it was started: each leg's source is the interface it goes from.
    made: Description,
    /// The interface to send each leg from, when one was given.
    interfaces: Vec<Option<Ipv4Addr>>,
    ttl: u8,
    dscp: u8,
    tai_utc: i32,
    switch: Arc<Switch>,
    /// Whether it sends to multicast groups, as its IS-04 transport says.
    multicast: bool,
    /// The SDP file's session id, and how many times the file has changed.
    session: u64,
    edits: u64,
    sdp: String,
    /// The port each leg went from last.
    ports: Vec<u16>,
    /// Told of each new SDP file.
    on_change: Box<dyn FnMut(&str) + Send>,
}

impl Sending {
    /// The stream `made`, sent through `switch`, its SDP file `sdp` with session id
    /// `session`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        made: Description,
        interfaces: Vec<Option<Ipv4Addr>>,
        ttl: u8,
        dscp: u8,
        tai_utc: i32,
        switch: Arc<Switch>,
        session: u64,
        sdp: String,
        on_change: Box<dyn FnMut(&str) + Send>,
    ) -> Self {
        let multicast = made.legs.first().is_some_and(|l| l.destination.ip().is_multicast());
        let ports = switch.transmitter.lock().ok().and_then(|t| t.as_ref().map(Transmitter::ports)).unwrap_or_default();
        Self { made, interfaces, ttl, dscp, tai_utc, switch, multicast, session, edits: 0, sdp, ports, on_change }
    }

    /// The Sender's IS-05 resources, as it sends now.
    pub(crate) fn endpoint(&self) -> Endpoint {
        let source = |leg: &Leg| leg.source.unwrap_or(Ipv4Addr::UNSPECIFIED).to_string();
        let constraints = self
            .made
            .legs
            .iter()
            .map(|leg| {
                json!({"source_ip": {"enum": ["auto", source(leg)]}, "destination_ip": {}, "source_port": {},
                       "destination_port": {"minimum": 1, "maximum": 65535}, "rtp_enabled": {}})
            })
            .collect();
        let params = self
            .made
            .legs
            .iter()
            .enumerate()
            .map(|(i, leg)| {
                json!({"source_ip": source(leg), "destination_ip": leg.destination.ip().to_string(),
                       "source_port": self.ports.get(i).copied().unwrap_or(0),
                       "destination_port": leg.destination.port(), "rtp_enabled": true})
            })
            .collect();
        let mut endpoint = Endpoint::sender(constraints, params, true);
        // The system picks the port, which only the active parameters say.
        for params in endpoint.staged["transport_params"].as_array_mut().into_iter().flatten() {
            params["source_port"] = json!("auto");
        }
        endpoint
    }
}

impl Role for Sending {
    fn side(&self) -> Side {
        Side::Sender
    }

    fn check(&self, staged: &Value) -> Result<(), String> {
        let legs = staged["transport_params"].as_array().into_iter().flatten();
        for (i, params) in legs.enumerate() {
            if let Some(ip) = params["destination_ip"].as_str().and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                && ip.is_multicast() != self.multicast
            {
                let (transport, sends) =
                    if self.multicast { ("rtp.mcast", "multicast groups") } else { ("rtp.ucast", "unicast addresses") };
                return Err(format!("leg {i}: this Sender is {transport}, so it sends to {sends}, not {ip}"));
            }
            let port = &params["source_port"];
            if port != "auto" && port.as_u64().and_then(|p| u16::try_from(p).ok()) != self.ports.get(i).copied() {
                return Err(format!(
                    "leg {i}: this Sender sends from a port the system picks, so source_port is auto, not {port}"
                ));
            }
        }
        Ok(())
    }

    fn activate(&mut self, active: &mut Value) {
        let enabled = active["master_enable"] == true;
        let mut legs = Vec::new();
        let mut interfaces = Vec::new();
        let mut at = Vec::new();
        for (i, (params, made)) in
            active["transport_params"].as_array().into_iter().flatten().zip(&self.made.legs).enumerate()
        {
            if params["rtp_enabled"] == false {
                continue;
            }
            let ip = params["destination_ip"].as_str().and_then(|ip| ip.parse::<Ipv4Addr>().ok());
            let port = params["destination_port"].as_u64().and_then(|p| u16::try_from(p).ok());
            let (Some(ip), Some(port)) = (ip, port) else { continue };
            legs.push(Leg { destination: SocketAddrV4::new(ip, port), ..*made });
            interfaces.push(self.interfaces.get(i).copied().flatten());
            at.push(i);
        }
        // The old sockets go first, so that the new ones can keep their ports.
        self.switch.swap(None);
        let ports: Vec<u16> = at.iter().map(|&i| self.ports.get(i).copied().unwrap_or(0)).collect();
        let transmitter = if enabled && !legs.is_empty() {
            match Transmitter::from_ports(&legs, &interfaces, &ports, self.ttl, self.dscp, self.tai_utc) {
                Ok(transmitter) => Some(transmitter),
                Err(e) => {
                    eprintln!("st2110: the stream cannot be sent where IS-05 asked, so it stops: {e}");
                    None
                }
            }
        } else {
            None
        };
        if let Some(transmitter) = &transmitter {
            for ((&i, source), port) in at.iter().zip(transmitter.sources()).zip(transmitter.ports()) {
                if let Some(slot) = self.ports.get_mut(i) {
                    *slot = port;
                }
                active["transport_params"][i]["source_ip"] = json!(source.to_string());
            }
        }
        for (i, params) in active["transport_params"].as_array_mut().into_iter().flatten().enumerate() {
            params["source_port"] = json!(self.ports.get(i).copied().unwrap_or(0));
        }
        self.switch.swap(transmitter);
        // The file says where it sends when on, and still does while it is off; with
        // every leg off it keeps the last.
        if !legs.is_empty() {
            self.edits += 1;
            self.sdp = Description { legs, ..self.made.clone() }.sdp(self.session + self.edits);
            (self.on_change)(&self.sdp);
        }
    }

    fn transport_file(&self) -> Option<String> {
        Some(self.sdp.clone())
    }
}
