//! Reading a capture frame by frame, and sending each packet to its flow or to the PTP
//! monitor once the capture's clock is known.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use st2110_ptp::Message;
use st2110_sdp::Essence;

use crate::capture::{CaptureError, Format, Frame, Reader};
use crate::dup::Pair;
use crate::flow::{Flow, Key, RtpPacket, SdpStream, compare_constituents};
use crate::net::{self, Packet};
use crate::ptp::Monitor;
use crate::report::{Capture, Finding, FlowReport, RelativeReport, Report, TimescaleReport};
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
    Rtp {
        t: i128,
        key: Key,
        packet: RtpPacket,
        /// The whole RTP packet, for a stream whose payloads are read.
        bytes: Option<Box<[u8]>>,
    },
    /// `to` is the destination address, or `None` when the message came over Ethernet
    /// rather than UDP.
    Ptp {
        t: i128,
        from: String,
        to: Option<IpAddr>,
        message: Box<Message>,
    },
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
    /// The SDP files' `DUP` groups, each with its index by file and group, and the
    /// pair and leg each flow is, by flow.
    pairs: Vec<((usize, usize), Pair)>,
    legs: Vec<Option<(usize, usize)>>,
}

impl Running {
    fn new(decision: Decision, sdp: Vec<SdpStream>) -> Self {
        let ptp = Monitor::new(decision.absolute());
        let mut pairs: Vec<((usize, usize), Vec<&SdpStream>)> = Vec::new();
        for stream in &sdp {
            let Some((group, _)) = stream.dup else { continue };
            match pairs.iter_mut().find(|(g, _)| *g == group) {
                Some((_, streams)) => streams.push(stream),
                None => pairs.push((group, vec![stream])),
            }
        }
        let pairs = pairs
            .into_iter()
            .filter(|(_, streams)| streams.len() > 1)
            .map(|(group, streams)| {
                let label = streams.iter().map(|s| s.label.as_str()).collect::<Vec<_>>().join(" and ");
                (group, Pair::new(label, streams.len(), streams[0].wide_sequence()))
            })
            .collect();
        Self { decision, sdp, flows: Vec::new(), index: HashMap::new(), untracked: 0, ptp, pairs, legs: Vec::new() }
    }

    fn event(&mut self, event: Event) {
        let shift = self.decision.shift;
        match event {
            Event::Rtp { t, key, packet, bytes } => {
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
                        let leg = stream.as_ref().and_then(|s| s.dup).and_then(|(group, leg)| {
                            let pair = self.pairs.iter().position(|(g, _)| *g == group)?;
                            self.pairs[pair].1.set_flow(leg, self.flows.len() + 1);
                            Some((pair, leg))
                        });
                        self.legs.push(leg);
                        self.flows.push(Flow::new(self.flows.len() + 1, key, stream, self.decision.absolute()));
                        self.index.insert(key, self.flows.len() - 1);
                        self.flows.len() - 1
                    }
                };
                if let Some((pair, leg)) = self.legs[i] {
                    let pair = &mut self.pairs[pair].1;
                    let sequence = if pair.wide() {
                        packet.extended_sequence().map(|high| u32::from(high) << 16 | u32::from(packet.header.sequence))
                    } else {
                        Some(u32::from(packet.header.sequence))
                    };
                    if let Some(sequence) = sequence {
                        pair.push(leg, t + shift, sequence, packet.ip_length);
                    }
                }
                self.flows[i].push(t + shift, packet, bytes.as_deref());
            }
            Event::Ptp { t, from, to, message } => self.ptp.push(t + shift, &from, to, &message),
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
                        Ok(message) => Event::Ptp {
                            t,
                            from: d.source.ip().to_string(),
                            to: Some(d.destination.ip()),
                            message: Box::new(message),
                        },
                        Err(_) => {
                            self.undecodable += 1;
                            return;
                        }
                    }
                } else if let Some(packet) = RtpPacket::read(&d) {
                    c.rtp += 1;
                    let key = (d.source, d.destination);
                    let streams = match (&self.running, &self.detector) {
                        (Some(running), _) => &running.sdp[..],
                        (None, Some((_, _, sdp))) => &sdp[..],
                        (None, None) => &[][..],
                    };
                    let reads = SdpStream::find(streams, key).is_some_and(|i| streams[i].reads_payloads());
                    let bytes = (reads && d.complete()).then(|| d.payload.into());
                    Event::Rtp { t, key, packet, bytes }
                } else {
                    return;
                }
            }
            Packet::Ptp { source, payload } => {
                c.ptp += 1;
                match st2110_ptp::decode(payload) {
                    Ok(message) => Event::Ptp { t, from: mac(source), to: None, message: Box::new(message) },
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
            Event::Rtp { t, key, packet, .. } => {
                let stream = SdpStream::find(sdp, *key).map(|i| &sdp[i]);
                let rate = stream.and_then(SdpStream::clock_rate);
                let offset = stream.map_or(0, SdpStream::audio_offset);
                detector.rtp(*t, *key, packet.header.timestamp.wrapping_sub(offset), rate);
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
        let constituents: Vec<_> = running.flows.iter().filter_map(Flow::constituent).collect();
        for flow in running.flows {
            let (report, more) = flow.finish(&timeline);
            fragmented_flows |= more.iter().any(|f| f.rule == rules::IP_FRAGMENT.id);
            flows.push(report);
            findings.extend(more);
        }
        relate(&mut flows);
        findings.extend(compare_constituents(&constituents, &timeline));
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
        let pairs = running.pairs.into_iter().map(|(_, pair)| pair.finish(&timeline)).collect();
        let refclks: Vec<_> =
            running.sdp.iter().filter_map(|s| Some((s.label.clone(), s.reference_clock.clone()?))).collect();
        let (ptp, more) = running.ptp.finish(end, self.undecodable, &timeline, &refclks);
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
            pairs,
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

/// Lines each audio and ancillary data flow up with a video flow, as RP 2110-25:2023
/// §4.11.4, §4.12.4 and §4.12.5 measure them: against the video from the same sender,
/// or else the first video in the capture.
fn relate(flows: &mut [FlowReport]) {
    /// A video flow, as the others are lined up with it.
    struct Video {
        index: usize,
        sender: Option<IpAddr>,
        latency: Option<f64>,
        rtp_offset: Option<f64>,
        /// A frame, in ticks of the 90 kHz clock.
        frame: Option<f64>,
    }
    let sender = |flow: &FlowReport| flow.source.parse::<SocketAddr>().ok().map(|a| a.ip());
    let videos: Vec<Video> = flows
        .iter()
        .filter(|f| matches!(f.essence, Essence::Video | Essence::CompressedVideo))
        .filter_map(|f| {
            let v = f.video.as_ref()?;
            let frame = v
                .frame_rate
                .as_deref()
                .and_then(|r| st2110_sdp::parse_frame_rate(r).ok())
                .map(|(r, _)| 90_000.0 * r.denominator() as f64 / r.numerator() as f64);
            Some(Video {
                index: f.index,
                sender: sender(f),
                latency: v.latency.map(|s| s.mean),
                rtp_offset: v.rtp_offset.map(|s| s.mean),
                frame,
            })
        })
        .collect();
    let Some(first) = videos.first() else { return };
    for flow in flows.iter_mut() {
        let (latency, offset) = match (flow.essence, &flow.video, &flow.audio) {
            (Essence::Ancillary, Some(anc), _) => (anc.latency.map(|s| s.mean), anc.rtp_offset.map(|s| s.mean)),
            (Essence::Audio | Essence::Aes3, _, Some(audio)) => (audio.latency.map(|s| s.mean), None),
            _ => continue,
        };
        let from = sender(flow);
        let video = videos.iter().find(|v| v.sender.is_some() && v.sender == from).unwrap_or(first);
        // RP 2110-25 NOTE 1: brought within half a frame.
        let rtp_offset = offset.zip(video.rtp_offset).map(|(anc, video_offset)| {
            let difference = video_offset - anc;
            match video.frame.filter(|&frame| frame > 0.0) {
                Some(frame) => difference - frame * (difference / frame).round(),
                None => difference,
            }
        });
        flow.relative = Some(RelativeReport {
            video: video.index,
            differential_latency_us: latency.zip(video.latency).map(|(own, video)| own - video),
            rtp_offset,
        });
    }
}

/// A MAC address, as `02:00:00:00:00:01`.
fn mac(octets: [u8; 6]) -> String {
    octets.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}
