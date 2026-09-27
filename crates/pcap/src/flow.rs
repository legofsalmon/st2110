//! RTP flows: matching each to a stream in the SDP files, working out what it carries
//! when none matches, and following its sequence numbers.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use st2110_sdp::{Essence, Param, Rule};

use crate::audio::{AudioConfig, AudioEngine};
use crate::net::Datagram;
use crate::report::{Finding, FlowReport};
use crate::rtp::{self, AncField};
use crate::stats::Tally;
use crate::timescale::estimate_rate;
use crate::video::{Arrival, SenderType, VideoConfig, VideoEngine, VideoKind};
use crate::{SdpFile, Timeline, plural, rules};

/// A flow's source and destination.
pub(crate) type Key = (SocketAddr, SocketAddr);

/// An RTP packet, as much of it as the measurements need.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RtpPacket {
    pub header: rtp::Header,
    /// The first octets of the payload, which hold the payload header of ST 2110-20
    /// video and ST 2110-40 ancillary data.
    head: [u8; 8],
    head_len: u8,
    /// Octets of payload, by the UDP length: the RTP header and padding left out.
    pub payload_len: u32,
    /// The UDP length field.
    pub udp_length: u16,
    /// Octets of the IP packet.
    pub ip_length: u32,
    /// Whether it was the first fragment of a fragmented IP packet.
    pub fragmented: bool,
}

impl RtpPacket {
    /// Reads the RTP packet in a datagram, if it holds one.
    pub(crate) fn read(d: &Datagram<'_>) -> Option<Self> {
        let header = rtp::header(d.payload, d.complete())?;
        let payload = d.payload.get(header.length..).unwrap_or_default();
        let mut head = [0; 8];
        let n = payload.len().min(8);
        head[..n].copy_from_slice(&payload[..n]);
        let overhead = 8 + header.length + header.padding;
        Some(Self {
            header,
            head,
            head_len: n as u8,
            payload_len: u32::try_from(usize::from(d.length).saturating_sub(overhead)).unwrap_or(0),
            udp_length: d.length,
            ip_length: d.ip_length,
            fragmented: d.fragmented,
        })
    }

    fn head(&self) -> &[u8] {
        &self.head[..usize::from(self.head_len)]
    }

    /// The payload header's high 16 bits of the sequence number.
    fn extended_sequence(&self) -> Option<u16> {
        let head = self.head();
        (head.len() >= 2).then(|| u16::from_be_bytes([head[0], head[1]]))
    }
}

/// A stream from an SDP file, as flows are matched against it.
#[derive(Clone, Debug)]
pub(crate) struct SdpStream {
    /// Such as `camera1.sdp stream 0`.
    pub label: String,
    destination: Option<IpAddr>,
    port: Option<u16>,
    source: Option<IpAddr>,
    essence: Essence,
    payload_type: Option<u8>,
    encoding: Option<String>,
    clock_rate: Option<u32>,
    channels: Option<u16>,
    ptime_ms: Option<f64>,
    video: VideoConfig,
    maxudp: Option<u32>,
    /// Whether a flow has matched it.
    pub matched: bool,
}

impl SdpStream {
    /// Every stream in the files.
    pub(crate) fn read(files: &[SdpFile]) -> Vec<Self> {
        let mut streams = Vec::new();
        for file in files {
            let report = st2110_sdp::lint(&file.text);
            let (sdp, _) = st2110_sdp::parse(&file.text);
            for stream in &report.streams {
                let params = &stream.parameters;
                let ptime = sdp
                    .media
                    .get(stream.index)
                    .and_then(|m| m.attribute("ptime"))
                    .or_else(|| sdp.session.attribute("ptime"))
                    .and_then(|a| a.text().parse::<f64>().ok())
                    .filter(|ms| ms.is_finite() && *ms > 0.0);
                let number = |name: &str| value(params, name).and_then(|v| v.trim().parse::<u32>().ok());
                let video = VideoConfig {
                    frame_rate: value(params, "exactframerate")
                        .and_then(|v| st2110_sdp::parse_frame_rate(v).ok())
                        .map(|(rate, _)| rate),
                    interlaced: match stream.essence {
                        Essence::Video | Essence::CompressedVideo => Some(param(params, "interlace").is_some()),
                        _ => None,
                    },
                    segmented: param(params, "segmented").is_some(),
                    height: number("height"),
                    sender: value(params, "TP").and_then(SenderType::parse),
                    troff_us: number("TROFF"),
                    cmax: number("CMAX"),
                    maxudp: number("MAXUDP"),
                };
                streams.push(Self {
                    label: format!("{} stream {}", file.name, stream.index),
                    destination: stream.destination.as_deref().and_then(|d| d.parse().ok()),
                    port: stream.port,
                    source: stream.source.as_deref().and_then(|s| s.parse().ok()),
                    essence: stream.essence,
                    payload_type: stream.payload_type,
                    encoding: stream.encoding.clone(),
                    clock_rate: stream.clock_rate,
                    channels: stream.channels,
                    ptime_ms: ptime,
                    maxudp: video.maxudp,
                    video,
                    matched: false,
                });
            }
        }
        streams
    }

    /// Where the stream goes, as `239.1.1.1:5004`.
    pub(crate) fn destination(&self) -> String {
        match (self.destination, self.port) {
            (Some(ip), Some(port)) => SocketAddr::new(ip, port).to_string(),
            (Some(ip), None) => ip.to_string(),
            _ => "an address that is not an IP address".into(),
        }
    }

    /// The stream a flow belongs to: the first whose destination matches and whose
    /// source filter, if it has one, names the flow's sender, preferring one that does.
    pub(crate) fn find(streams: &[Self], key: Key) -> Option<usize> {
        let (source, destination) = key;
        let goes = |s: &&Self| s.destination == Some(destination.ip()) && s.port == Some(destination.port());
        let candidates: Vec<usize> = (0..streams.len()).filter(|&i| goes(&&streams[i])).collect();
        candidates
            .iter()
            .copied()
            .find(|&i| streams[i].source == Some(source.ip()))
            .or_else(|| candidates.into_iter().find(|&i| streams[i].source.is_none()))
    }

    /// The RTP clock rate the stream declares.
    pub(crate) fn clock_rate(&self) -> Option<u32> {
        self.clock_rate
    }
}

fn param<'a>(params: &'a [Param], name: &str) -> Option<&'a Param> {
    params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

fn value<'a>(params: &'a [Param], name: &str) -> Option<&'a str> {
    param(params, name)?.value.as_deref()
}

/// What a flow carries, as the measurements treat it.
#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Video(VideoKind),
    Audio(AudioConfig),
    /// Only the RTP-level checks apply.
    Other(Essence),
}

impl Kind {
    fn essence(&self) -> Essence {
        match self {
            Self::Video(VideoKind::Uncompressed) => Essence::Video,
            Self::Video(VideoKind::Compressed) => Essence::CompressedVideo,
            Self::Video(VideoKind::Ancillary) => Essence::Ancillary,
            Self::Audio(config) if config.encoding.eq_ignore_ascii_case("AM824") => Essence::Aes3,
            Self::Audio(_) => Essence::Audio,
            Self::Other(essence) => *essence,
        }
    }

    /// Whether the payload header carries the sequence number's high 16 bits.
    fn wide_sequence(&self) -> bool {
        matches!(self, Self::Video(VideoKind::Uncompressed | VideoKind::Ancillary))
    }
}

/// A flow without an SDP stream is held until this many packets have arrived, at most,
/// for its packets to show what it carries.
const PENDING_LIMIT: usize = 50_000;

/// One flow.
pub(crate) struct Flow {
    index: usize,
    key: Key,
    sdp: Option<SdpStream>,
    absolute: bool,
    kind: Option<Kind>,
    pending: Vec<(i128, RtpPacket)>,
    pending_timestamps: usize,
    payload_type: Option<u8>,
    ssrc: Option<u32>,
    first_ssrc: Option<u32>,
    packets: u64,
    bytes: u64,
    /// Octets of the first packet, which arrived at the start of the flow's time.
    first_bytes: u64,
    first: Option<i128>,
    last: i128,
    seq: SeqTracker,
    ssrc_changes: Tally,
    other_payload_types: Vec<u8>,
    payload_type_wrong: Tally,
    fragments: Tally,
    oversize: Tally,
    video: Option<Box<VideoEngine>>,
    audio: Option<Box<AudioEngine>>,
}

impl Flow {
    pub(crate) fn new(index: usize, key: Key, sdp: Option<SdpStream>, absolute: bool) -> Self {
        Self {
            index,
            key,
            sdp,
            absolute,
            kind: None,
            pending: Vec::new(),
            pending_timestamps: 0,
            payload_type: None,
            ssrc: None,
            first_ssrc: None,
            packets: 0,
            bytes: 0,
            first_bytes: 0,
            first: None,
            last: 0,
            seq: SeqTracker::default(),
            ssrc_changes: Tally::default(),
            other_payload_types: Vec::new(),
            payload_type_wrong: Tally::default(),
            fragments: Tally::default(),
            oversize: Tally::default(),
            video: None,
            audio: None,
        }
    }

    /// Takes the next packet, which arrived at `t` on the analysis timeline.
    pub(crate) fn push(&mut self, t: i128, p: RtpPacket) {
        self.packets += 1;
        self.bytes += u64::from(p.ip_length);
        if self.first.is_none() {
            (self.first, self.first_bytes) = (Some(t), u64::from(p.ip_length));
        }
        self.last = self.last.max(t);
        self.payload_type.get_or_insert(p.header.payload_type);
        if self.kind.is_some() {
            self.process(t, p);
            return;
        }
        if self.sdp.is_some() {
            self.classify();
            self.process(t, p);
            return;
        }
        if self.pending.last().is_none_or(|(_, last)| last.header.timestamp != p.header.timestamp) {
            self.pending_timestamps += 1;
        }
        self.pending.push((t, p));
        let elapsed = t - self.pending[0].0;
        if (self.pending_timestamps >= 4 && elapsed >= 50_000_000)
            || elapsed >= 500_000_000
            || self.pending.len() >= PENDING_LIMIT
        {
            self.classify();
        }
    }

    /// Decides what the flow carries and starts measuring it, then measures the packets
    /// held so far.
    fn classify(&mut self) {
        let kind = match &self.sdp {
            Some(sdp) => from_sdp(sdp),
            None => guess(&self.pending),
        };
        match &kind {
            Kind::Video(video) => {
                let config = self.sdp.as_ref().map(|s| s.video.clone()).unwrap_or_default();
                self.video = Some(Box::new(VideoEngine::new(*video, config, self.absolute)));
            }
            Kind::Audio(config) => self.audio = Some(Box::new(AudioEngine::new(config.clone(), self.absolute))),
            Kind::Other(_) => {}
        }
        self.seq.wide = kind.wide_sequence();
        self.kind = Some(kind);
        for (t, p) in std::mem::take(&mut self.pending) {
            self.process(t, p);
        }
    }

    fn process(&mut self, t: i128, p: RtpPacket) {
        if p.fragmented {
            self.fragments.hit(t);
        }
        let limit = self.udp_limit();
        if u32::from(p.udp_length) > limit {
            self.oversize.hit_max(t, f64::from(p.udp_length));
        }
        let h = p.header;
        if let Some(expected) = self.sdp.as_ref().and_then(|s| s.payload_type)
            && h.payload_type != expected
        {
            self.payload_type_wrong.hit(t);
            if !self.other_payload_types.contains(&h.payload_type) {
                self.other_payload_types.push(h.payload_type);
            }
        }
        match self.ssrc {
            Some(ssrc) if ssrc != h.ssrc => {
                self.ssrc_changes.hit(t);
                self.seq.restart();
            }
            _ => {}
        }
        self.ssrc = Some(h.ssrc);
        self.first_ssrc.get_or_insert(h.ssrc);
        let extended = if self.seq.wide { p.extended_sequence() } else { None };
        let seq = match extended {
            Some(high) => self.seq.push(t, u32::from(high) << 16 | u32::from(h.sequence), 32),
            None => self.seq.push(t, u32::from(h.sequence), 16),
        };
        let Some(seq) = seq else { return };
        if let Some(video) = &mut self.video {
            let kind = match &self.kind {
                Some(Kind::Video(kind)) => *kind,
                _ => unreachable!("a video engine runs only for video"),
            };
            let head = p.head();
            video.push(Arrival {
                t,
                seq,
                timestamp: h.timestamp,
                marker: h.marker,
                video: (kind == VideoKind::Uncompressed).then(|| rtp::video_header(head)).flatten(),
                anc: (kind == VideoKind::Ancillary).then(|| rtp::anc_header(head).map(|a| a.field)).flatten(),
            });
        }
        if let Some(audio) = &mut self.audio {
            audio.push(t, seq, h.timestamp, p.payload_len);
        }
    }

    /// ST 2110-10's limit on UDP datagrams, in octets.
    fn udp_limit(&self) -> u32 {
        self.sdp.as_ref().and_then(|s| s.maxudp).map_or(1460, |m| m.min(8960))
    }

    pub(crate) fn finish(mut self, timeline: &Timeline) -> (FlowReport, Vec<Finding>) {
        if self.kind.is_none() {
            self.classify();
        }
        let flow = Some(self.index);
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, first: Option<i128>, count: u64, message: String| {
            if count > 0 {
                findings.push(Finding::new(rule, message, flow, None, timeline.at(first), count));
            }
        };
        let seq = &self.seq;
        let received = self.packets.saturating_sub(seq.duplicates.count);
        add(
            &rules::PACKET_LOSS,
            seq.first_loss,
            seq.lost,
            format!(
                "{} of {} never arrived ({:.3}%), in {}",
                plural(seq.lost, "packet"),
                received + seq.lost,
                seq.lost as f64 * 100.0 / (received + seq.lost).max(1) as f64,
                plural(seq.gaps, "gap")
            ),
        );
        let mut disorder = Vec::new();
        if seq.out_of_order.count > 0 {
            disorder.push(format!("{} arrived after a later one", plural(seq.out_of_order.count, "packet")));
        }
        if seq.duplicates.count > 0 {
            disorder.push(format!("{} arrived more than once", plural(seq.duplicates.count, "packet")));
        }
        if seq.restarts.count > 0 {
            disorder.push(format!(
                "the sequence numbers jumped {}, as if the sender restarted",
                plural(seq.restarts.count, "time")
            ));
        }
        let firsts = [seq.out_of_order.first, seq.duplicates.first, seq.restarts.first];
        add(
            &rules::PACKET_ORDER,
            firsts.into_iter().flatten().min(),
            seq.out_of_order.count + seq.duplicates.count + seq.restarts.count,
            disorder.join("; "),
        );
        add(
            &rules::SSRC_CHANGE,
            self.ssrc_changes.first,
            self.ssrc_changes.count,
            format!(
                "the SSRC changed {}, from {:08X} to {:08X} by the end",
                plural(self.ssrc_changes.count, "time"),
                self.first_ssrc.unwrap_or_default(),
                self.ssrc.unwrap_or_default()
            ),
        );
        if let Some(expected) = self.sdp.as_ref().and_then(|s| s.payload_type) {
            let seen: Vec<String> = self.other_payload_types.iter().map(u8::to_string).collect();
            add(
                &rules::PAYLOAD_TYPE_MISMATCH,
                self.payload_type_wrong.first,
                self.payload_type_wrong.count,
                format!(
                    "{} carried payload type {}, not the {expected} of the SDP file's m= line",
                    plural(self.payload_type_wrong.count, "packet"),
                    seen.join(" or ")
                ),
            );
        }
        add(
            &rules::IP_FRAGMENT,
            self.fragments.first,
            self.fragments.count,
            format!("{} arrived in IP fragments", plural(self.fragments.count, "packet")),
        );
        add(
            &rules::UDP_SIZE,
            self.oversize.first,
            self.oversize.count,
            format!(
                "{} exceeded {} octets, the largest being {}",
                plural(self.oversize.count, "datagram"),
                self.udp_limit(),
                self.oversize.worst.unwrap_or_default()
            ),
        );
        let video = self.video.take().map(|engine| {
            let (report, more) = engine.finish(self.index, timeline);
            findings.extend(more);
            report
        });
        let audio = self.audio.take().map(|engine| {
            let (report, more) = engine.finish(self.index, timeline);
            findings.extend(more);
            report
        });
        let first = self.first.unwrap_or_default();
        let seconds = (self.last - first) as f64 / 1e9;
        let kind = self.kind.as_ref().expect("classified above");
        let report = FlowReport {
            index: self.index,
            source: self.key.0.to_string(),
            destination: self.key.1.to_string(),
            essence: kind.essence(),
            sdp: self.sdp.as_ref().map(|s| s.label.clone()),
            guessed: self.sdp.is_none(),
            payload_type: self.payload_type.unwrap_or_default(),
            ssrc: format!("{:08X}", self.first_ssrc.unwrap_or_default()),
            packets: self.packets,
            bytes: self.bytes,
            first: timeline.at(Some(first)).unwrap_or_default(),
            last: timeline.at(Some(self.last)).unwrap_or_default(),
            mbps: (seconds > 0.0).then(|| (self.bytes - self.first_bytes) as f64 * 8.0 / seconds / 1e6),
            lost: self.seq.lost,
            out_of_order: self.seq.out_of_order.count,
            duplicates: self.seq.duplicates.count,
            video,
            audio,
        };
        (report, findings)
    }
}

/// What an SDP stream says the flow carries.
fn from_sdp(sdp: &SdpStream) -> Kind {
    match sdp.essence {
        Essence::Video => Kind::Video(VideoKind::Uncompressed),
        Essence::CompressedVideo => Kind::Video(VideoKind::Compressed),
        Essence::Ancillary => Kind::Video(VideoKind::Ancillary),
        essence @ (Essence::Audio | Essence::Aes3) => {
            let encoding = sdp.encoding.clone().unwrap_or_default();
            match (octets(&encoding), sdp.clock_rate) {
                (Some(octets), Some(sample_rate)) => Kind::Audio(AudioConfig {
                    encoding,
                    octets,
                    sample_rate,
                    channels: sdp.channels,
                    ptime_ms: sdp.ptime_ms,
                }),
                _ => Kind::Other(essence),
            }
        }
        essence => Kind::Other(essence),
    }
}

/// Octets per sample of one channel.
fn octets(encoding: &str) -> Option<u32> {
    match encoding.to_ascii_uppercase().as_str() {
        "L16" => Some(2),
        "L24" => Some(3),
        "AM824" => Some(4),
        _ => None,
    }
}

/// What a flow without an SDP stream most likely carries, from its first packets.
fn guess(packets: &[(i128, RtpPacket)]) -> Kind {
    let mut starts: Vec<(i128, u32)> = Vec::new();
    for &(t, p) in packets {
        if starts.last().is_none_or(|(_, ts)| *ts != p.header.timestamp) {
            starts.push((t, p.header.timestamp));
        }
    }
    let Some(rate) = estimate_rate(&starts) else { return Kind::Other(Essence::Unknown) };
    if rate == 90_000 {
        let per_timestamp = packets.len() as f64 / starts.len() as f64;
        return if per_timestamp >= 8.0 {
            Kind::Video(if plausible(packets, video_header_fits) {
                VideoKind::Uncompressed
            } else {
                VideoKind::Compressed
            })
        } else if plausible(packets, anc_header_fits) {
            Kind::Video(VideoKind::Ancillary)
        } else {
            Kind::Other(Essence::Unknown)
        };
    }
    // Audio: every packet holds the same number of samples, so its payload is a whole
    // number of samples of every channel.
    // Only steps the audio engine takes too, so that a sample frame's size fits in a u32.
    let mut steps: Vec<u32> =
        starts.windows(2).map(|w| w[1].1.wrapping_sub(w[0].1)).filter(|&s| s > 0 && s < 1 << 20).collect();
    if steps.is_empty() {
        return Kind::Other(Essence::Unknown);
    }
    steps.sort_unstable();
    let step = steps[steps.len() / 2];
    let fits = |octets: u32| packets.iter().all(|(_, p)| p.payload_len > 0 && p.payload_len % (octets * step) == 0);
    let encoding = if fits(3) {
        "L24"
    } else if fits(2) {
        "L16"
    } else {
        return Kind::Other(Essence::Unknown);
    };
    Kind::Audio(AudioConfig {
        encoding: encoding.into(),
        octets: octets(encoding).expect("a PCM encoding"),
        sample_rate: rate,
        channels: None,
        ptime_ms: None,
    })
}

/// Whether nine in ten packets have payload headers that `fits` accepts, and their
/// extended sequence numbers carry over as a 32-bit count would.
fn plausible(packets: &[(i128, RtpPacket)], fits: fn(&RtpPacket) -> bool) -> bool {
    let good = packets.iter().filter(|(_, p)| fits(p)).count();
    let mut carried = 0;
    let mut pairs = 0;
    for pair in packets.windows(2) {
        let (a, b) = (pair[0].1, pair[1].1);
        let (Some(high_a), Some(high_b)) = (a.extended_sequence(), b.extended_sequence()) else { continue };
        if b.header.sequence != a.header.sequence.wrapping_add(1) {
            continue;
        }
        pairs += 1;
        let expected = if b.header.sequence == 0 { high_a.wrapping_add(1) } else { high_a };
        if high_b == expected {
            carried += 1;
        }
    }
    good * 10 >= packets.len() * 9 && (pairs == 0 || carried * 10 >= pairs * 9)
}

/// An ST 2110-20 payload header: its first row segment fits the payload and names a
/// row and offset a real image has.
fn video_header_fits(p: &RtpPacket) -> bool {
    rtp::video_header(p.head())
        .is_some_and(|v| v.length > 0 && u32::from(v.length) + 8 <= p.payload_len && v.row < 8192 && v.offset < 16384)
}

/// An RFC 8331 payload header: its length counts the rest of the payload, and its field
/// is one RFC 8331 allows.
fn anc_header_fits(p: &RtpPacket) -> bool {
    rtp::anc_header(p.head()).is_some_and(|a| {
        u32::from(a.length) + 8 == p.payload_len && a.field != AncField::Invalid && (a.count > 0 || a.length == 0)
    })
}

/// Sequence numbers, extended past their wrap, and what they show of loss and order.
#[derive(Debug, Default)]
struct SeqTracker {
    /// Whether the payload header carries the high 16 bits.
    wide: bool,
    highest: Option<i64>,
    /// The first sequence number: one below it arrived late from before the capture.
    lowest: i64,
    /// Runs of sequence numbers that have not arrived, each from its first to one past
    /// its last, within reordering distance of the highest.
    missing: BTreeMap<i64, i64>,
    lost: u64,
    gaps: u64,
    first_loss: Option<i128>,
    out_of_order: Tally,
    duplicates: Tally,
    restarts: Tally,
}

/// A jump back further than this is a restart, not reordering, so sequence numbers that
/// go missing are remembered this far back to count them found if they turn up late.
const REORDER_LIMIT: i64 = 3_000;

/// A jump forward further than this, in a 32-bit sequence, is a restart, not loss.
const LOSS_LIMIT: i64 = 1 << 24;

impl SeqTracker {
    /// Takes a sequence number of `bits` bits and returns it extended, or `None` for a
    /// packet that arrived before.
    fn push(&mut self, t: i128, value: u32, bits: u32) -> Option<u32> {
        let Some(highest) = self.highest else {
            self.highest = Some(i64::from(value));
            self.lowest = i64::from(value);
            return Some(value);
        };
        let modulus = 1_i64 << bits;
        let mut delta = (i64::from(value) - highest).rem_euclid(modulus);
        if delta >= modulus / 2 {
            delta -= modulus;
        }
        let extended = highest + delta;
        if delta > 0 && (bits == 16 || delta <= LOSS_LIMIT) {
            if delta > 1 {
                self.lost += (delta - 1) as u64;
                self.gaps += 1;
                self.first_loss.get_or_insert(t);
                self.missing.insert(highest + 1, extended);
            }
            self.highest = Some(extended);
            self.forget_below(extended - REORDER_LIMIT);
        } else if self.found(extended) {
            self.lost -= 1;
            self.out_of_order.hit(t);
        } else if (-REORDER_LIMIT..0).contains(&delta) && extended < self.lowest {
            // Sent before the first packet the capture holds, and overtaken by it.
            self.lowest = extended;
        } else if !(-REORDER_LIMIT..=0).contains(&delta) {
            self.restarts.hit(t);
            self.missing.clear();
            self.highest = Some(extended);
        } else {
            self.duplicates.hit(t);
            return None;
        }
        Some(extended as u32)
    }

    /// Takes a missing sequence number off the runs, if it is on one.
    fn found(&mut self, n: i64) -> bool {
        let Some((&start, &end)) = self.missing.range(..=n).next_back() else { return false };
        if n >= end {
            return false;
        }
        self.missing.remove(&start);
        let (before, after) = (start < n, n + 1 < end);
        if before {
            self.missing.insert(start, n);
        }
        if after {
            self.missing.insert(n + 1, end);
        }
        // A gap it closes counts no more; one it splits counts twice.
        match (before, after) {
            (false, false) => self.gaps -= 1,
            (true, true) => self.gaps += 1,
            _ => {}
        }
        true
    }

    /// Forgets the missing sequence numbers below `cutoff`, too far back to arrive late.
    fn forget_below(&mut self, cutoff: i64) {
        while let Some((&start, &end)) = self.missing.first_key_value() {
            if start >= cutoff {
                break;
            }
            self.missing.remove(&start);
            if end > cutoff {
                self.missing.insert(cutoff, end);
                break;
            }
        }
    }

    /// Starts again, for a new sender.
    fn restart(&mut self) {
        self.highest = None;
        self.missing.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_loss_and_disorder() {
        let mut s = SeqTracker::default();
        let pushed: Vec<Option<u32>> =
            [65_533, 65_534, 1, 65_535, 2, 2, 3, 65_532].into_iter().map(|v| s.push(0, v, 16)).collect();
        // Wrapping past 65 535 to 65 536, with 0 lost and 65 535 late; 65 532 was sent
        // before the capture began.
        let expected = [65_533, 65_534, 65_537, 65_535, 65_538, 0, 65_539, 65_532].map(|v| (v > 0).then_some(v));
        assert_eq!(pushed, expected);
        assert_eq!((s.lost, s.gaps, s.out_of_order.count, s.duplicates.count), (1, 1, 1, 1));
        // A jump back beyond reordering is a restart.
        assert_eq!(s.push(0, 61_539, 16), Some(61_539));
        assert_eq!((s.restarts.count, s.lost), (1, 1));

        // 32 bits: a far jump forward is a restart too, not loss.
        let mut s = SeqTracker::default();
        s.push(0, 7, 32);
        s.push(0, 8 + (1 << 25), 32);
        assert_eq!((s.lost, s.restarts.count), (0, 1));

        // A late packet inside a gap splits it in two; one at its edge shortens it.
        let mut s = SeqTracker::default();
        for v in [100, 110, 105, 101] {
            s.push(0, v, 32);
        }
        assert_eq!((s.lost, s.gaps, s.out_of_order.count), (7, 2, 2));
        assert_eq!(s.missing.iter().map(|(&a, &b)| (a, b)).collect::<Vec<_>>(), [(102, 105), (106, 110)]);
        // Once the sequence is past reordering distance, a gap is forgotten, and a
        // packet from it is a restart.
        s.push(0, 110 + 3_200, 32);
        assert_eq!(s.missing.iter().map(|(&a, &b)| (a, b)).collect::<Vec<_>>(), [(310, 3_310)]);
        s.push(0, 103, 32);
        assert_eq!(s.restarts.count, 1);

        // Jumps of more than the reordering distance on every packet stay cheap.
        let mut s = SeqTracker::default();
        for i in 0..100_000_u32 {
            s.push(0, i.wrapping_mul(5_000), 32);
        }
        assert!(s.missing.len() <= 1, "{}", s.missing.len());
    }
}
