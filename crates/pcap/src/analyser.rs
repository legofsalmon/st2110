//! Reading a capture frame by frame, and sending each packet to its flow or to the PTP
//! monitor once the capture's clock is known.

use std::collections::HashMap;
use std::io::Read;

use st2110_ptp::Message;

use crate::capture::{CaptureError, Format, Frame, Reader};
use crate::flow::{Flow, Key, RtpPacket, SdpStream};
use crate::net::{self, Packet};
use crate::ptp::Monitor;
use crate::report::{Capture, Finding, Report, TimescaleReport};
use crate::stats::NANOS;
use crate::timescale::{Decision, Detector};
use crate::{FLOW_LIMIT, Options, Timeline, plural, rules};

/// Packets are held while the capture's clock is worked out, for this long at most.
const DECIDE_WITHIN: i128 = 2 * NANOS;

/// Or until this many are held.
const DECIDE_EVENTS: usize = 200_000;

/// UDP ports of PTP event and general messages.
const PTP_PORTS: [u16; 2] = [319, 320];

enum Event {
    Rtp { t: i128, key: Key, packet: RtpPacket },
    Ptp { t: i128, from: String, message: Box<Message> },
}

impl Event {
    fn time(&self) -> i128 {
        match self {
            Self::Rtp { t, .. } | Self::Ptp { t, .. } => *t,
        }
    }
}

/// The flows and the PTP monitor, once the capture's clock is known.
struct Running {
    decision: Decision,
    sdp: Vec<SdpStream>,
    flows: Vec<Flow>,
    index: HashMap<Key, usize>,
    /// RTP packets in flows past the first [`FLOW_LIMIT`].
    untracked: u64,
    ptp: Monitor,
}

impl Running {
    fn new(decision: Decision, sdp: Vec<SdpStream>) -> Self {
        let ptp = Monitor::new(decision.absolute());
        Self { decision, sdp, flows: Vec::new(), index: HashMap::new(), untracked: 0, ptp }
    }

    fn event(&mut self, event: Event) {
        let shift = self.decision.shift;
        match event {
            Event::Rtp { t, key, packet } => {
                let i = match self.index.get(&key) {
                    Some(&i) => i,
                    None if self.flows.len() >= FLOW_LIMIT => {
                        self.untracked += 1;
                        return;
                    }
                    None => {
                        let stream = SdpStream::find(&self.sdp, key).map(|i| {
                            self.sdp[i].matched = true;
                            self.sdp[i].clone()
                        });
                        self.flows.push(Flow::new(self.flows.len() + 1, key, stream, self.decision.absolute()));
                        self.index.insert(key, self.flows.len() - 1);
                        self.flows.len() - 1
                    }
                };
                self.flows[i].push(t + shift, packet);
            }
            Event::Ptp { t, from, message } => self.ptp.push(t + shift, &from, &message),
        }
    }
}

/// Analyses a capture one frame at a time; [`analyse`] reads a whole file with it.
pub struct Analyser {
    capture: Capture,
    first: Option<i128>,
    last: i128,
    undecodable: u64,
    /// Until the capture's clock is known: the evidence, and the packets held.
    detector: Option<(Detector, Vec<Event>, Vec<SdpStream>)>,
    running: Option<Running>,
}

impl Analyser {
    /// Starts an analysis of a capture in `format`.
    pub fn new(format: Format, options: &Options) -> Self {
        let sdp = SdpStream::read(&options.sdp);
        let (detector, running) = match Decision::forced(options) {
            Some(decision) => (None, Some(Running::new(decision, sdp))),
            None => (Some((Detector::new(options.tai_utc), Vec::new(), sdp)), None),
        };
        let capture = Capture {
            format: format.to_string(),
            frames: 0,
            start: None,
            duration: 0.0,
            bytes: 0,
            udp: 0,
            rtp: 0,
            rtp_untracked: 0,
            ptp: 0,
            fragments: 0,
            other: 0,
            error: None,
        };
        Self { capture, first: None, last: 0, undecodable: 0, detector, running }
    }

    /// Takes the next frame of the capture.
    pub fn push(&mut self, frame: &Frame<'_>) {
        let t = frame.time;
        let c = &mut self.capture;
        c.frames += 1;
        c.bytes += u64::from(frame.length);
        self.first.get_or_insert(t);
        self.last = self.last.max(t);
        let event = match net::parse(frame.link, frame.data) {
            Packet::Udp(d) => {
                c.udp += 1;
                if PTP_PORTS.contains(&d.destination.port()) {
                    c.ptp += 1;
                    match st2110_ptp::decode(d.payload) {
                        Ok(message) => Event::Ptp { t, from: d.source.ip().to_string(), message: Box::new(message) },
                        Err(_) => {
                            self.undecodable += 1;
                            return;
                        }
                    }
                } else if let Some(packet) = RtpPacket::read(&d) {
                    c.rtp += 1;
                    Event::Rtp { t, key: (d.source, d.destination), packet }
                } else {
                    return;
                }
            }
            Packet::Ptp { source, payload } => {
                c.ptp += 1;
                match st2110_ptp::decode(payload) {
                    Ok(message) => Event::Ptp { t, from: mac(source), message: Box::new(message) },
                    Err(_) => {
                        self.undecodable += 1;
                        return;
                    }
                }
            }
            Packet::Fragment { .. } => {
                c.fragments += 1;
                return;
            }
            Packet::Other => {
                c.other += 1;
                return;
            }
        };
        self.dispatch(event);
    }

    fn dispatch(&mut self, event: Event) {
        if let Some(running) = &mut self.running {
            running.event(event);
            return;
        }
        let (detector, events, sdp) = self.detector.as_mut().expect("deciding until running");
        match &event {
            Event::Rtp { t, key, packet } => {
                let rate = SdpStream::find(sdp, *key).and_then(|i| sdp[i].clock_rate());
                detector.rtp(*t, *key, packet.header.timestamp, rate);
            }
            Event::Ptp { t, message, .. } => detector.ptp(*t, message),
        }
        let since = events.first().map_or(event.time(), Event::time);
        let elapsed = event.time() - since;
        events.push(event);
        if elapsed >= DECIDE_WITHIN || events.len() >= DECIDE_EVENTS {
            self.decide();
        }
    }

    /// Decides what the capture's clock is, then measures the packets held until now.
    fn decide(&mut self) {
        let Some((detector, events, sdp)) = self.detector.take() else { return };
        let mut running = Running::new(detector.decide(), sdp);
        for event in events {
            running.event(event);
        }
        self.running = Some(running);
    }

    /// Finishes the analysis. `error` is why the capture could not be read to the end,
    /// if it could not.
    pub fn finish(mut self, error: Option<CaptureError>) -> Report {
        self.decide();
        let running = self.running.take().expect("decided above");
        let start = self.first.unwrap_or_default();
        let timeline = Timeline { start, shift: running.decision.shift };
        let mut capture = self.capture;
        capture.start = self.first.map(|t| format!("{}.{:09}", t.div_euclid(NANOS), t.rem_euclid(NANOS)));
        capture.duration = (self.last - start) as f64 / 1e9;
        capture.error = error.map(|e| e.to_string());
        capture.rtp_untracked = running.untracked;
        let mut findings = Vec::new();
        let mut flows = Vec::new();
        let mut fragmented_flows = false;
        for flow in running.flows {
            let (report, more) = flow.finish(&timeline);
            fragmented_flows |= more.iter().any(|f| f.rule == rules::IP_FRAGMENT.id);
            flows.push(report);
            findings.extend(more);
        }
        if capture.fragments > 0 && !fragmented_flows {
            // Later fragments whose first fragment the capture missed.
            findings.insert(
                0,
                Finding::new(
                    &rules::IP_FRAGMENT,
                    format!("{} were later fragments of fragmented IP packets", plural(capture.fragments, "frame")),
                    None,
                    None,
                    None,
                    capture.fragments,
                ),
            );
        }
        let end = self.last + running.decision.shift;
        let (ptp, more) = running.ptp.finish(end, self.undecodable, &timeline);
        findings.extend(more);
        let missing =
            running.sdp.iter().filter(|s| !s.matched).map(|s| format!("{}, to {}", s.label, s.destination())).collect();
        let decision = running.decision;
        Report {
            capture,
            timescale: TimescaleReport {
                clock: decision.clock,
                basis: decision.basis,
                shift: i64::try_from(decision.shift).unwrap_or_default(),
                note: decision.note,
            },
            flows,
            ptp,
            missing,
            findings,
        }
    }
}

/// Analyses a whole capture: a pcap or pcapng file.
///
/// Fails only when `input` is not a capture. A file that ends partway through, or
/// breaks off, is analysed as far as it goes, and [`Capture::error`] says why it
/// stopped.
pub fn analyse(input: impl Read, options: &Options) -> Result<Report, CaptureError> {
    let mut reader = Reader::new(input)?;
    let mut analyser = Analyser::new(reader.format(), options);
    let mut error = None;
    while let Some(frame) = reader.next_frame() {
        match frame {
            Ok(frame) => analyser.push(&frame),
            Err(e) => error = Some(e),
        }
    }
    Ok(analyser.finish(error))
}

/// A MAC address, as `02:00:00:00:00:01`.
fn mac(octets: [u8; 6]) -> String {
    octets.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}
