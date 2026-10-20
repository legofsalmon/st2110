//! Analysing captures built packet by packet: a clean facility, then one fault at a time.

use std::collections::BTreeSet;

use st2110_pcap::{Clock, Finding, Options, Report, SdpFile, Timescale, analyse};
use st2110_sdp::Severity;

const NANOS: i128 = 1_000_000_000;
/// 2026-09-27 12:00:00 UTC in PTP seconds.
const NOON: i128 = 1_790_510_437;
const GM: [u8; 8] = [0x08, 0x00, 0x11, 0xFF, 0xFE, 0x21, 0xE1, 0xB0];
const OTHER_GM: [u8; 8] = [0x00, 0x1D, 0xC1, 0xFF, 0xFE, 0x0B, 0x33, 0x01];
const FOLLOWER: [u8; 8] = [0x00, 0x1B, 0x21, 0xFF, 0xFE, 0x8A, 0x2C, 0x10];

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdp/tests/fixtures");

fn fixture(name: &str) -> SdpFile {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}")).expect("a fixture");
    SdpFile { name: name.into(), text }
}

/// Frames to capture, by PTP time, and how far behind PTP time the capturing clock is.
#[derive(Default)]
struct Scene {
    frames: Vec<(i128, Vec<u8>)>,
    behind: i128,
}

impl Scene {
    fn frame(&mut self, ptp: i128, frame: Vec<u8>) {
        self.frames.push((ptp - self.behind, frame));
    }

    fn udp(&mut self, ptp: i128, source: &str, destination: &str, payload: &[u8]) {
        self.frame(ptp, ethernet(&ipv4_udp(source, destination, payload, 0x4000)));
    }

    /// A pcap file with nanosecond timestamps, in time order.
    fn pcap(&self) -> Vec<u8> {
        let mut frames: Vec<&(i128, Vec<u8>)> = self.frames.iter().collect();
        frames.sort_by_key(|(t, _)| *t);
        let mut out = vec![0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
        for (t, frame) in frames {
            out.extend(((t / NANOS) as u32).to_le_bytes());
            out.extend(((t % NANOS) as u32).to_le_bytes());
            out.extend((frame.len() as u32).to_le_bytes());
            out.extend((frame.len() as u32).to_le_bytes());
            out.extend(frame);
        }
        out
    }

    fn analyse(&self, sdp: &[SdpFile]) -> Report {
        analyse(&self.pcap()[..], &Options { sdp: sdp.to_vec(), ..Options::default() }).expect("a capture")
    }
}

fn ethernet(ip: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x01, 0x00, 0x5E, 0x0A, 0x0A, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    frame.extend(ip);
    frame
}

/// An IPv4 packet holding a UDP datagram, with the flags and fragment offset given.
fn ipv4_udp(source: &str, destination: &str, payload: &[u8], flags: u16) -> Vec<u8> {
    let (source, destination): (std::net::SocketAddrV4, std::net::SocketAddrV4) =
        (source.parse().unwrap(), destination.parse().unwrap());
    let mut ip = vec![0x45, 0xB8];
    ip.extend(((20 + 8 + payload.len()) as u16).to_be_bytes());
    ip.extend([0, 1]);
    ip.extend(flags.to_be_bytes());
    ip.extend([64, 17, 0, 0]);
    ip.extend(source.ip().octets());
    ip.extend(destination.ip().octets());
    ip.extend(source.port().to_be_bytes());
    ip.extend(destination.port().to_be_bytes());
    ip.extend(((8 + payload.len()) as u16).to_be_bytes());
    ip.extend([0, 0]);
    ip.extend(payload);
    ip
}

fn rtp(payload_type: u8, marker: bool, seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, payload_type | if marker { 0x80 } else { 0 }];
    out.extend(seq.to_be_bytes());
    out.extend(timestamp.to_be_bytes());
    out.extend(ssrc.to_be_bytes());
    out.extend(payload);
    out
}

/// An ST 2110-20 sender of a small raster: 40 packets a frame, each 1200 octets of one
/// row segment, on the narrow gapped schedule.
#[derive(Clone)]
struct Video {
    source: &'static str,
    destination: &'static str,
    ssrc: u32,
    seq: u32,
    /// Frames a second, as a fraction.
    rate: (i128, i128),
    interlaced: bool,
    packets: u32,
    /// Octets of sample data in each packet.
    octets: usize,
}

impl Video {
    fn new(source: &'static str, destination: &'static str) -> Self {
        Self {
            source,
            destination,
            ssrc: 0x1111_0001,
            seq: 0xFFFF_FFF0,
            rate: (50, 1),
            interlaced: false,
            packets: 40,
            octets: 1_200,
        }
    }

    fn interlaced(mut self) -> Self {
        (self.rate, self.interlaced) = ((25, 1), true);
        self
    }

    fn frame_time(&self) -> i128 {
        self.rate.1 * NANOS / self.rate.0
    }

    /// When packet `j` of frame `n` is read on the gapped schedule: TPR0 + j × TRS, and
    /// the second field from half a frame later.
    fn read_time(&self, n: i128, j: u32) -> i128 {
        let frame = self.frame_time();
        let offset = if self.interlaced { 22 * frame / 1125 } else { 43 * frame / 1125 };
        let step = frame * 1080 / 1125 / i128::from(self.packets);
        let half = self.packets / 2;
        if self.interlaced && j >= half {
            n * frame + offset + frame / 2 + i128::from(j - half) * step
        } else {
            n * frame + offset + i128::from(j) * step
        }
    }

    /// Frame `n`, counted from the SMPTE Epoch: each packet with the time it arrives,
    /// 20 µs before it is read unless `arrive` says otherwise.
    fn frame(&mut self, n: i128, arrive: impl Fn(u32, i128) -> i128) -> Vec<(i128, Vec<u8>)> {
        let (num, den) = self.rate;
        let half = self.packets / 2;
        (0..self.packets)
            .map(|j| {
                let second = self.interlaced && j >= half;
                let timestamp = if second {
                    ((2 * n + 1) * den * 90_000 / (2 * num)) as u32
                } else {
                    (n * den * 90_000 / num) as u32
                };
                let (row, last) = if self.interlaced {
                    ((j % half) * 27, j == half - 1 || j == self.packets - 1)
                } else {
                    (j * 27, j == self.packets - 1)
                };
                let mut payload = ((self.seq >> 16) as u16).to_be_bytes().to_vec();
                payload.extend((self.octets as u16).to_be_bytes());
                payload.extend((row as u16 | if second { 0x8000 } else { 0 }).to_be_bytes());
                payload.extend([0, 0]);
                payload.extend(vec![0x80; self.octets]);
                let packet = rtp(96, last, self.seq as u16, timestamp, self.ssrc, &payload);
                self.seq = self.seq.wrapping_add(1);
                (arrive(j, self.read_time(n, j) - 20_000), packet)
            })
            .collect()
    }

    /// Frames from `first` for `count` frames, sent as `frame` gives them.
    fn send(&mut self, scene: &mut Scene, first: i128, count: i128) {
        for n in first..first + count {
            for (t, packet) in self.frame(n, |_, t| t) {
                scene.udp(t, self.source, self.destination, &packet);
            }
        }
    }
}

/// The first frame of 50 fps video at noon.
const FRAME_50: i128 = NOON * 50;

/// An ST 2110-30 sender: L24 at 48 kHz, arriving 150 µs after their last sample.
struct Audio {
    source: &'static str,
    destination: &'static str,
    payload_type: u8,
    ssrc: u32,
    seq: u16,
    channels: usize,
    /// Samples a packet: 48 for 1 ms.
    samples: i128,
    /// The RTP clock's offset, as `a=mediaclk:direct=` signals it.
    offset: u32,
}

impl Audio {
    fn new() -> Self {
        Self {
            source: "192.168.10.22:5006",
            destination: "239.10.10.2:5006",
            payload_type: 97,
            ssrc: 0x2222_0002,
            seq: 100,
            channels: 8,
            samples: 48,
            offset: 0,
        }
    }

    /// Packet `i`, counting packets from the SMPTE Epoch.
    fn packet(&mut self, i: i128) -> (i128, Vec<u8>) {
        let first_sample = i * self.samples;
        let payload = vec![0x11; self.samples as usize * 3 * self.channels];
        let timestamp = (first_sample as u32).wrapping_add(self.offset);
        let packet = rtp(self.payload_type, false, self.seq, timestamp, self.ssrc, &payload);
        self.seq = self.seq.wrapping_add(1);
        ((first_sample + self.samples) * NANOS / 48_000 + 150_000, packet)
    }

    fn send(&mut self, scene: &mut Scene, first: i128, count: i128) {
        for i in first..first + count {
            let (t, packet) = self.packet(i);
            scene.udp(t, self.source, self.destination, &packet);
        }
    }
}

/// A 10-bit ANC word: the octet with its parity bits (ST 291-1:2011 §6).
fn anc_word(value: u8) -> u16 {
    let b8 = u16::from(value.count_ones() % 2 == 1);
    u16::from(value) | b8 << 8 | (b8 ^ 1) << 9
}

/// One ANC packet as RFC 8331 carries it: on the luma channel with no stream number, its
/// words and checksum, then the bits that complete its last 32-bit word.
fn anc_packet(line: u16, horizontal: u16, did: u8, sdid: u8, udw: &[u8]) -> Vec<u8> {
    let mut words = vec![anc_word(did), anc_word(sdid), anc_word(udw.len() as u8)];
    words.extend(udw.iter().map(|&b| anc_word(b)));
    let sum = words.iter().fold(0, |sum, w| sum + (w & 0x1FF)) & 0x1FF;
    words.push(sum | if sum & 0x100 == 0 { 0x200 } else { 0 });
    let header = u32::from(line) << 20 | u32::from(horizontal) << 8;
    let mut bits: Vec<bool> = (0..32).rev().map(|i| header >> i & 1 == 1).collect();
    for w in words {
        bits.extend((0..10).rev().map(|i| w >> i & 1 == 1));
    }
    bits.resize(bits.len().div_ceil(32) * 32, false);
    bits.chunks(8).map(|byte| byte.iter().fold(0, |b, &bit| b << 1 | u8::from(bit))).collect()
}

/// The closed captions that the clean sender carries: DID 0x61 SDID 0x01, with no
/// location proposed.
fn captions() -> Vec<u8> {
    anc_packet(0x7FF, 0xFFF, 0x61, 0x01, &[0x96, 0x69, 0x55])
}

/// An RFC 8331 payload: the header, with the F field `field`, then the packets.
fn anc_payload(field: u8, packets: &[Vec<u8>]) -> Vec<u8> {
    let data: Vec<u8> = packets.concat();
    let mut payload = vec![0, 0];
    payload.extend((data.len() as u16).to_be_bytes());
    payload.extend([packets.len() as u8, field << 6, 0, 0]);
    payload.extend(data);
    payload
}

/// An ST 2110-40 sender of 50 fps ancillary data: one packet a frame, which `payload`
/// gives (or none, when it gives `None`), arriving `arrive` after the frame starts.
fn send_anc_with(
    scene: &mut Scene,
    destination: &str,
    first: i128,
    count: i128,
    arrive: impl Fn(i128) -> i128,
    payload: impl Fn(i128) -> Option<Vec<u8>>,
) {
    let mut seq = 0_u16;
    for n in first..first + count {
        let Some(payload) = payload(n - first) else { continue };
        let packet = rtp(100, true, seq, (n * 1800) as u32, 0x3333_0003, &payload);
        scene.udp(n * 20_000_000 + arrive(n - first), "192.168.10.21:5008", destination, &packet);
        seq += 1;
    }
}

/// The clean sender: closed captions every frame, 500 µs into it.
fn send_anc(scene: &mut Scene, first: i128, count: i128) {
    send_anc_with(scene, "239.10.10.3:5008", first, count, |_| 500_000, |_| Some(anc_payload(0, &[captions()])));
}

fn ptp_timestamp(t: i128) -> Vec<u8> {
    let mut out = ((t / NANOS) as u64).to_be_bytes()[2..].to_vec();
    out.extend(((t % NANOS) as u32).to_be_bytes());
    out
}

fn port(clock: [u8; 8], number: u16) -> Vec<u8> {
    let mut out = clock.to_vec();
    out.extend(number.to_be_bytes());
    out
}

/// A PTP message: a header for `kind` from port 1 of `clock`, then `body`.
fn ptp(kind: u8, control: u8, log: i8, flags: u16, seq: u16, clock: [u8; 8], body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0x02];
    out.extend(((34 + body.len()) as u16).to_be_bytes());
    out.extend([127, 0]);
    out.extend(flags.to_be_bytes());
    out.extend([0; 12]);
    out.extend(port(clock, 1));
    out.extend(seq.to_be_bytes());
    out.extend([control, log as u8]);
    out.extend(body);
    out
}

const TWO_STEP: u16 = 0x0200;
/// PTP timescale, UTC offset valid, time and frequency traceable.
const ANNOUNCE_FLAGS: u16 = 0x0008 | 0x0004 | 0x0010 | 0x0020;

fn announce(clock: [u8; 8], seq: u16, t: i128, log: i8) -> Vec<u8> {
    let mut body = ptp_timestamp(t);
    body.extend(37_i16.to_be_bytes());
    body.extend([0, 128, 6, 0x21]);
    body.extend(0x4E5D_u16.to_be_bytes());
    body.push(128);
    body.extend(clock);
    body.extend(0_u16.to_be_bytes());
    body.push(0x20);
    ptp(0x0B, 5, log, ANNOUNCE_FLAGS, seq, clock, &body)
}

const GM_ADDRESS: &str = "192.168.1.1:319";
const FOLLOWER_ADDRESS: &str = "192.168.1.50:319";
const PTP_EVENT: &str = "224.0.1.129:319";
const PTP_GENERAL: &str = "224.0.1.129:320";

/// What a grandmaster and one follower send over `seconds` from noon: Announce 4 a
/// second, two-step Sync 8 a second, and a Delay_Req answered by a Delay_Resp every
/// 125 ms. `skip` leaves out the messages it names, by type and sequence number.
fn send_ptp(scene: &mut Scene, clock: [u8; 8], seconds: i128, skip: impl Fn(u8, u16) -> bool) {
    for tick in 0..seconds * 8 {
        let seq = tick as u16;
        let t = NOON * NANOS + tick * 125_000_000 + 1_000_000;
        let mut send = |at: i128, kind: u8, to: &str, from: &str, message: Vec<u8>| {
            if !skip(kind, seq) {
                scene.udp(at + 5_000, from, to, &message);
            }
        };
        send(t, 0x00, PTP_EVENT, GM_ADDRESS, ptp(0x00, 0, -3, TWO_STEP, seq, clock, &ptp_timestamp(t)));
        send(t + 30_000, 0x08, PTP_GENERAL, GM_ADDRESS, ptp(0x08, 2, -3, 0, seq, clock, &ptp_timestamp(t)));
        if tick % 2 == 0 {
            send(t + 40_000, 0x0B, PTP_GENERAL, GM_ADDRESS, announce(clock, seq / 2, t, -2));
        }
        let request = t + 60_000_000;
        send(request, 0x01, PTP_EVENT, FOLLOWER_ADDRESS, ptp(0x01, 1, 127, 0, seq, FOLLOWER, &ptp_timestamp(request)));
        let mut body = ptp_timestamp(request + 5_000);
        body.extend(port(FOLLOWER, 1));
        send(request + 1_000_000, 0x09, PTP_GENERAL, GM_ADDRESS, ptp(0x09, 3, -3, 0, seq, clock, &body));
    }
}

/// A second of a clean facility: both legs of the video, audio, ancillary data and PTP.
fn facility(behind: i128, with_ptp: bool) -> Scene {
    let mut scene = Scene { behind, ..Scene::default() };
    Video::new("192.168.10.21:5004", "239.10.10.1:5004").send(&mut scene, FRAME_50, 50);
    Video::new("192.168.20.21:5004", "239.20.10.1:5004").send(&mut scene, FRAME_50, 50);
    Audio::new().send(&mut scene, NOON * 1000, 1000);
    send_anc(&mut scene, FRAME_50, 50);
    if with_ptp {
        send_ptp(&mut scene, GM, 1, |_, _| false);
    }
    scene
}

fn facility_sdp() -> Vec<SdpFile> {
    vec![fixture("video-dup.sdp"), fixture("audio-pcm.sdp"), fixture("anc.sdp")]
}

fn rules(report: &Report) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.rule).collect()
}

fn finding<'a>(report: &'a Report, rule: &str) -> &'a Finding {
    report.findings.iter().find(|f| f.rule == rule).unwrap_or_else(|| panic!("no {rule} in {:#?}", report.findings))
}

fn close(value: f64, expected: f64) -> bool {
    (value - expected).abs() < 0.01
}

#[test]
fn a_clean_facility_on_ptp_time() {
    let report = facility(0, true).analyse(&facility_sdp());
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    assert!(report.missing.is_empty(), "{:?}", report.missing);
    assert_eq!(report.timescale.clock, Clock::Ptp);
    assert_eq!(
        report.timescale.basis,
        "by the capture's clock, 8 Sync messages arrived a median 5.0 µs after leaving the grandmaster"
    );
    let c = &report.capture;
    assert_eq!((c.format.as_str(), c.frames, c.rtp, c.ptp, c.other), ("pcap (nanosecond)", 5086, 5050, 36, 0));

    let labels: Vec<(&str, Option<&str>)> =
        report.flows.iter().map(|f| (f.destination.as_str(), f.sdp.as_deref())).collect();
    assert_eq!(
        labels,
        [
            ("239.10.10.3:5008", Some("anc.sdp stream 0")),
            ("239.10.10.1:5004", Some("video-dup.sdp stream 0")),
            ("239.20.10.1:5004", Some("video-dup.sdp stream 1")),
            ("239.10.10.2:5006", Some("audio-pcm.sdp stream 0")),
        ]
    );

    let video = report.flows[1].video.as_ref().expect("video");
    assert_eq!((video.frame_rate.as_deref(), video.height, video.interlaced), (Some("50"), Some(1080), false));
    assert_eq!((video.units, video.npackets), (50, Some(40)));
    let fpt = video.fpt.unwrap();
    assert!(close(fpt.min, 744.444) && close(fpt.max, 744.444), "{fpt:?}");
    assert_eq!((video.rtp_offset.unwrap().min, video.rtp_offset.unwrap().max), (0.0, 0.0));
    assert!(close(video.latency.unwrap().mean, 744.444));
    assert!(close(video.gap.unwrap().mean, 1280.0), "{:?}", video.gap);
    let cinst = video.cinst.as_ref().unwrap();
    assert_eq!((cinst.peak, cinst.cmax, cinst.sender_type.as_deref()), (1, Some(4), Some("2110TPN")));
    assert_eq!(cinst.fits, ["2110TPN", "2110TPNL", "2110TPW"]);
    let vrx = video.vrx.as_ref().unwrap();
    assert_eq!((vrx.schedule.as_str(), vrx.vrxfull, vrx.peak, vrx.underflows, vrx.overflows), ("gapped", 8, 1, 0, 0));
    assert!(close(vrx.troffset_us, 764.444) && !vrx.troffset_signalled);
    assert!(close(vrx.margin_us.unwrap().min, 20.0));
    // Each packet arrives 20 µs before its read, and is the only one in the buffer: the
    // RP 2110-25 Margin of every frame is 20 µs.
    let levels = (vrx.min, vrx.average, vrx.steady_min, vrx.steady_average, vrx.gap_min);
    assert_eq!(levels, (Some(0), Some(1.0), Some(0), Some(1.0), Some(0)));
    let margin = vrx.frame_margin_us.unwrap();
    assert!(close(margin.min, 20.0) && close(margin.max, 20.0) && margin.count == 50, "{margin:?}");
    assert_eq!(video.windows.len(), 1);
    assert_eq!((video.windows[0].vrx_min, video.windows[0].vrx_average), (Some(0), Some(1.0)));
    assert_eq!(video.windows[0].second, i64::try_from(NOON).unwrap());

    let anc = report.flows[0].video.as_ref().expect("ancillary data");
    assert!(close(anc.latency.unwrap().max, 500.0));
    assert_eq!((anc.cinst.as_ref(), anc.models_skipped.as_ref(), anc.vrx_skipped.as_ref()), (None, None, None));

    let audio = report.flows[3].audio.as_ref().expect("audio");
    assert_eq!((audio.channels, audio.samples_per_packet, audio.packet_time_us), (Some(8), Some(48), Some(1000.0)));
    assert!(close(audio.latency.unwrap().min, 1150.0) && close(audio.latency.unwrap().max, 1150.0));
    assert!(close(audio.ts_df.unwrap().max, 0.0));
    // 1000 packets of 1192 octets from the first to the last, 999 ms apart.
    assert_eq!(report.flows[3].mbps.map(|m| (m * 10.0).round() / 10.0), Some(9.5));

    // The ancillary data lines up with the video from its own sender; the audio, with
    // no video from its sender, with the first video.
    let anc = report.flows[0].relative.as_ref().expect("ANC against video");
    assert_eq!((anc.video, anc.rtp_offset), (2, Some(0.0)));
    assert!(close(anc.differential_latency_us.unwrap(), 500.0 - 744.444), "{anc:?}");
    let audio = report.flows[3].relative.as_ref().expect("audio against video");
    assert_eq!((audio.video, audio.rtp_offset), (2, None));
    assert!(close(audio.differential_latency_us.unwrap(), 1150.0 - 744.444), "{audio:?}");
    assert_eq!(report.flows[1].relative, None);

    let domain = &report.ptp.domains[0];
    assert_eq!((domain.domain, domain.grandmasters.as_slice()), (127, &["08-00-11-FF-FE-21-E1-B0".to_string()][..]));
    assert!(close(domain.sync_offset_us.unwrap().mean, 5.0));
    let gm = &domain.ports[1];
    assert_eq!((gm.port.as_str(), gm.address.as_str()), ("08-00-11-FF-FE-21-E1-B0 port 1", "192.168.1.1"));
    let kinds: Vec<(&str, u64)> = gm.messages.iter().map(|m| (m.kind.as_str(), m.count)).collect();
    assert_eq!(kinds, [("Sync", 8), ("Follow_Up", 8), ("Delay_Resp", 8), ("Announce", 4)]);
    assert!(close(gm.messages[0].interval_ms.unwrap().mean, 125.0));
    assert_eq!(domain.quality.len(), 1);
    assert_eq!(domain.sync_metadata, None);

    // The two legs of the video, merged: every packet on both, at the same time.
    let pair = &report.pairs[0];
    assert_eq!(pair.group, "video-dup.sdp stream 0 and video-dup.sdp stream 1");
    assert_eq!(pair.flows, [Some(2), Some(3)]);
    assert_eq!((pair.packets, pair.copies, pair.lost, pair.pd_us), (2000, 2000, 0, Some(0.0)));
    assert_eq!(pair.class.as_deref(), Some("D"));
    assert!(pair.outages.is_empty(), "{:?}", pair.outages);
}

/// Both legs of the video, leg 2 running 15 µs behind and gone for frames 10 to 19;
/// both lose packet 5 of frame 30.
fn with_dup_faults() -> Report {
    let mut scene = Scene::default();
    let mut legs =
        [Video::new("192.168.10.21:5004", "239.10.10.1:5004"), Video::new("192.168.20.21:5004", "239.20.10.1:5004")];
    for k in 0..50 {
        for (leg, video) in legs.iter_mut().enumerate() {
            for (j, (t, packet)) in video.frame(FRAME_50 + k, |_, t| t).into_iter().enumerate() {
                if (k == 30 && j == 5) || (leg == 1 && (10..20).contains(&k)) {
                    continue;
                }
                let t = if leg == 1 { t + 15_000 } else { t };
                scene.udp(t, video.source, video.destination, &packet);
            }
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn st_2022_7_legs_are_merged() {
    let report = with_dup_faults();
    // Each leg on its own: leg 2 short of 401 packets, and its buffer model upset by the
    // frames it missed.
    assert_eq!(rules(&report), ["packet-loss", "packet-loss", "vrx-overflow"]);
    let pair = &report.pairs[0];
    assert_eq!((pair.packets, pair.copies, pair.lost), (1999, 1599, 1));
    assert_eq!((pair.pd_us, pair.class.as_deref()), (Some(15.0), Some("D")));
    assert_eq!(pair.seconds.len(), 1);
    assert_eq!((pair.seconds[0].second, pair.seconds[0].lost), (i64::try_from(NOON).unwrap(), 1));
    // Leg 2's last packet of frame 9, 18.72 ms into it, then its first of frame 20.
    assert_eq!(pair.outages.len(), 1);
    let outage = &pair.outages[0];
    assert_eq!(outage.leg, 2);
    assert!(close(outage.from, 0.198_72) && close(outage.to.unwrap(), 0.4), "{outage:?}");
}

#[test]
fn a_capture_on_utc_is_shifted_onto_ptp_time() {
    let report = facility(37 * NANOS, true).analyse(&facility_sdp());
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    assert_eq!((report.timescale.clock, report.timescale.shift), (Clock::Utc, 37_000_000_000));
    assert!(
        report.timescale.basis.ends_with(
            "arrived a median 36.999995 s before leaving the grandmaster: it counts UTC, 37 s behind PTP time"
        ),
        "{}",
        report.timescale.basis
    );
    let video = report.flows[1].video.as_ref().unwrap();
    assert!(close(video.fpt.unwrap().mean, 744.444));
    assert_eq!(video.windows[0].second, i64::try_from(NOON).unwrap());
    // Times in findings and flows count from the capture's start all the same.
    assert!(report.flows[0].first < 0.001);

    // Without PTP messages, the RTP timestamps tell.
    let report = facility(37 * NANOS, false).analyse(&facility_sdp());
    assert_eq!(report.timescale.clock, Clock::Utc);
    assert!(
        report.timescale.basis.contains("the timestamps of 4 of 4 RTP flows sit 37 s ahead"),
        "{}",
        report.timescale.basis
    );
    assert!(close(report.flows[1].video.as_ref().unwrap().fpt.unwrap().mean, 744.444));

    // The options can say so too.
    let options = Options { sdp: facility_sdp(), timescale: Timescale::Utc, tai_utc: 37 };
    let report = analyse(&facility(37 * NANOS, true).pcap()[..], &options).unwrap();
    assert_eq!(
        (report.timescale.clock, report.timescale.basis.as_str()),
        (Clock::Utc, "chosen, not worked out from the capture")
    );
}

#[test]
fn an_unknown_clock_skips_what_needs_ptp_time() {
    let report = facility(5 * NANOS, false).analyse(&facility_sdp());
    assert_eq!(report.timescale.clock, Clock::Unknown);
    assert!(report.timescale.note.as_deref().unwrap().contains("skipped"));
    let video = report.flows[1].video.as_ref().unwrap();
    assert_eq!((video.fpt, video.latency, video.vrx.as_ref()), (None, None, None));
    assert_eq!(video.vrx_skipped.as_deref(), Some("the capture's clock is not on PTP time"));
    // CINST needs only the packets' spacing.
    assert_eq!(video.cinst.as_ref().unwrap().peak, 1);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn interlaced_video_reads_each_field_on_its_own_schedule() {
    let sdp = SdpFile {
        name: "1080i.sdp".into(),
        text: "v=0\r\no=- 1 1 IN IP4 192.168.10.31\r\ns=1080i\r\nt=0 0\r\nm=video 5010 RTP/AVP 96\r\n\
               c=IN IP4 239.10.10.10/32\r\na=rtpmap:96 raw/90000\r\n\
               a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; exactframerate=25; interlace; depth=10; \
               TCS=SDR; colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN\r\n\
               a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127\r\na=mediaclk:direct=0\r\n"
            .into(),
    };
    let mut scene = Scene::default();
    Video::new("192.168.10.31:5010", "239.10.10.10:5010").interlaced().send(&mut scene, NOON * 25, 25);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    let report = scene.analyse(std::slice::from_ref(&sdp));
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    let video = report.flows[0].video.as_ref().unwrap();
    assert_eq!((video.interlaced, video.units, video.npackets), (true, 50, Some(40)));
    // TRODEFAULT for 1125-line interlaced video: 22/1125 of 40 ms.
    assert!(close(video.fpt.unwrap().mean, 762.222), "{:?}", video.fpt);
    assert!(close(video.latency.unwrap().max, 762.222));
    let vrx = video.vrx.as_ref().unwrap();
    assert_eq!((vrx.peak, vrx.underflows, vrx.overflows), (1, 0, 0));
    assert!(close(vrx.margin_us.unwrap().max, 20.0));

    // Without the SDP file, the field bits and row numbers tell as much.
    let report = scene.analyse(&[]);
    let flow = &report.flows[0];
    let video = flow.video.as_ref().unwrap();
    assert!(flow.guessed);
    assert_eq!((video.frame_rate.as_deref(), video.interlaced, video.height), (Some("25"), true, Some(1028)));
    assert!(video.vrx.is_none() && video.vrx_skipped.as_deref().unwrap().contains("no TP"));
}

fn with_bursts() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 25 {
        // Each frame in one burst, a microsecond a packet, as the frame starts to be read.
        let start = video.read_time(n, 0) - 100_000;
        for (t, packet) in video.frame(n, |j, _| start + i128::from(j) * 1_000) {
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn bursts_overflow_the_models() {
    let report = with_bursts();
    assert_eq!(rules(&report), ["cinst", "vrx-overflow"]);
    let cinst = finding(&report, "cinst");
    assert_eq!(cinst.message, "CINST reached 40, over CMAX 4 for sender type 2110TPN, on 900 packets");
    assert_eq!((cinst.flow, cinst.severity), (Some(1), Severity::Error));
    let vrx = report.flows[0].video.as_ref().unwrap().vrx.as_ref().unwrap();
    assert_eq!((vrx.peak, vrx.underflows), (40, 0));
    // Each frame is in the buffer before its first read, so no frame has a steady state.
    assert_eq!((vrx.min, vrx.average, vrx.steady_min, vrx.gap_min), (Some(0), Some(20.5), None, Some(0)));
    assert_eq!(finding(&report, "vrx-overflow").count, 800);
    assert_eq!(report.missing, ["video-dup.sdp stream 1, to 239.20.10.1:5004"]);
}

fn with_late_packets() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 25 {
        for (t, packet) in video.frame(n, |_, t| t + 500_000) {
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn late_packets_underflow_the_buffer() {
    let report = with_late_packets();
    assert_eq!(rules(&report), ["timestamp-late", "vrx-underflow"]);
    let underflow = finding(&report, "vrx-underflow");
    assert_eq!(underflow.count, 1000);
    assert!(underflow.message.contains("the latest by 480.0 µs"), "{}", underflow.message);
    let late = finding(&report, "timestamp-late");
    assert_eq!((late.severity, late.count), (Severity::Info, 25));
    assert!(
        late.message.starts_with("latency from RTP timestamp to first packet reached 1244.4 µs"),
        "{}",
        late.message
    );
}

fn with_network_faults() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 10 {
        let mut packets = video.frame(n, |_, t| t);
        match n - FRAME_50 {
            // A lost packet, two swapped, and one sent twice.
            3 => {
                packets.remove(5);
            }
            4 => {
                // Still in time for their reads.
                packets.swap(7, 8);
                (packets[7].0, packets[8].0) = (packets[8].0, packets[8].0 + 10_000);
            }
            5 => {
                let copy = packets[2].clone();
                packets.insert(3, (copy.0 + 1_000, copy.1));
            }
            // The last packet without the marker bit, and one mid-frame with it.
            6 => packets[39].1[1] &= 0x7F,
            7 => packets[10].1[1] |= 0x80,
            _ => {}
        }
        for (t, packet) in packets {
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn network_faults_and_marker_bits() {
    let report = with_network_faults();
    assert_eq!(rules(&report), ["packet-loss", "packet-order", "marker-bit", "marker-bit"]);
    let loss = finding(&report, "packet-loss");
    assert_eq!(loss.message, "1 packet of 400 never arrived (0.250%), in 1 gap");
    let order = finding(&report, "packet-order");
    assert_eq!(order.message, "1 packet arrived after a later one; 1 packet arrived more than once");
    assert!(report.findings[2].message.starts_with("the last packet of 1 frame had no marker bit"));
    assert!(report.findings[3].message.starts_with("1 packet had the marker bit set but more packets"));
    let flow = &report.flows[0];
    assert_eq!((flow.packets, flow.lost, flow.out_of_order, flow.duplicates), (400, 1, 1, 1));
    // The models count NPACKETS from a whole frame, and carry on past the damage.
    assert_eq!(flow.video.as_ref().unwrap().npackets, Some(40));
}

fn with_big_and_fragmented_datagrams() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    video.octets = 1_440;
    video.send(&mut scene, FRAME_50, 5);
    let mut audio = Audio::new();
    for i in NOON * 1000..NOON * 1000 + 50 {
        let (t, packet) = audio.packet(i);
        // The tenth packet split into two IP fragments.
        let flags = if i % 50 == 9 { 0x2000 } else { 0x4000 };
        scene.frame(t, ethernet(&ipv4_udp(audio.source, audio.destination, &packet, flags)));
        if flags == 0x2000 {
            scene.frame(t + 1, ethernet(&ipv4_udp(audio.source, audio.destination, &[0; 64], 0x00B9)));
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp"), fixture("audio-pcm.sdp")])
}

#[test]
fn datagram_limits() {
    let report = with_big_and_fragmented_datagrams();
    assert_eq!(rules(&report), ["udp-size", "ip-fragment"]);
    let size = finding(&report, "udp-size");
    assert_eq!(size.message, "200 datagrams exceeded 1460 octets, the largest being 1468");
    assert_eq!(finding(&report, "ip-fragment").flow, Some(2));
    assert_eq!(report.capture.fragments, 1);
}

fn with_new_ssrc_and_wrong_payload_type() -> Report {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    audio.payload_type = 98;
    audio.send(&mut scene, NOON * 1000, 100);
    (audio.ssrc, audio.seq) = (0x2222_0099, 7);
    audio.send(&mut scene, NOON * 1000 + 100, 100);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("audio-pcm.sdp")])
}

#[test]
fn ssrc_and_payload_type() {
    let report = with_new_ssrc_and_wrong_payload_type();
    assert_eq!(rules(&report), ["ssrc-change", "payload-type-mismatch"]);
    assert_eq!(
        finding(&report, "ssrc-change").message,
        "the SSRC changed 1 time, from 22220002 to 22220099 by the end"
    );
    assert_eq!(
        finding(&report, "payload-type-mismatch").message,
        "200 packets carried payload type 98, not the 97 of the SDP file's m= line"
    );
    // A new sender restarts the sequence numbers without loss.
    assert_eq!(report.flows[0].lost, 0);
}

fn with_too_few_channels() -> Report {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    audio.channels = 2;
    audio.send(&mut scene, NOON * 1000, 200);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("audio-pcm.sdp")])
}

#[test]
fn audio_with_other_channels_than_its_sdp_file() {
    let report = with_too_few_channels();
    assert_eq!(rules(&report), ["audio-channels"]);
    let channels = finding(&report, "audio-channels");
    assert!(channels.message.contains("the first held 288 octets for 48 samples, not 1152"), "{}", channels.message);
    assert_eq!(report.flows[0].audio.as_ref().unwrap().channels, Some(2));
}

fn with_short_audio_packets() -> Report {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    audio.samples = 6;
    audio.send(&mut scene, NOON * 8000, 800);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("audio-pcm.sdp")])
}

#[test]
fn audio_with_another_packet_time_than_its_sdp_file() {
    let report = with_short_audio_packets();
    assert_eq!(rules(&report), ["packet-time"]);
    assert_eq!(
        finding(&report, "packet-time").message,
        "799 packets held a number of samples other than the 48 that ptime 1 ms gives at 48000 Hz, the first 6"
    );
    let audio = report.flows[0].audio.as_ref().unwrap();
    assert_eq!((audio.channels, audio.samples_per_packet, audio.packet_time_us), (Some(8), Some(6), Some(125.0)));
}

fn with_held_back_audio() -> Report {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    let packets: Vec<(i128, Vec<u8>)> = (NOON * 1000..NOON * 1000 + 1000).map(|i| audio.packet(i)).collect();
    for (i, (t, packet)) in packets.iter().enumerate() {
        // Of every ten packets, the first three held back and sent just before the fourth.
        let held = i % 10;
        let t = if held < 3 { packets[i - held + 3].0 - (3 - held as i128) * 1_000 } else { *t };
        scene.udp(t, audio.source, audio.destination, packet);
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("audio-pcm.sdp")])
}

#[test]
fn held_back_audio_raises_the_delay_factor() {
    let report = with_held_back_audio();
    assert_eq!(rules(&report), ["ts-df"]);
    let ts_df = finding(&report, "ts-df");
    assert_eq!(ts_df.count, 5);
    assert!(
        ts_df.message.starts_with("TS-DF reached 2997.0 µs, over the packet time of 1000.0 µs, in 5 of 5"),
        "{}",
        ts_df.message
    );
}

fn with_future_timestamps() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 25 {
        // Each frame stamped with the next frame's time.
        let arrivals: Vec<i128> = (0..40).map(|j| video.read_time(n, j) - 20_000).collect();
        for (t, packet) in video.frame(n + 1, |j, _| arrivals[j as usize]) {
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn timestamps_ahead_of_arrival() {
    let report = with_future_timestamps();
    assert_eq!(rules(&report), ["timestamp-future"]);
    let future = finding(&report, "timestamp-future");
    assert_eq!(future.count, 25);
    assert!(
        future.message.starts_with("25 frames arrived before the time its RTP timestamp names, by up to 19255.6 µs")
    );
    let video = report.flows[0].video.as_ref().unwrap();
    assert_eq!(video.rtp_offset.unwrap().mean, 1800.0);
}

fn with_misaligned_timestamps() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 25 {
        for (t, mut packet) in video.frame(n, |_, t| t) {
            // 10 ticks early.
            let timestamp = u32::from_be_bytes(packet[4..8].try_into().unwrap()).wrapping_sub(10);
            packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn timestamps_off_the_frame_grid() {
    let report = with_misaligned_timestamps();
    assert_eq!(rules(&report), ["rtp-alignment"]);
    assert!(finding(&report, "rtp-alignment").message.starts_with("25 of 25 timestamps were off the frame boundaries"));
    let video = report.flows[0].video.as_ref().unwrap();
    assert_eq!(video.rtp_offset.unwrap().mean, -10.0);
}

/// A JPEG XS sender at 59.94 frames a second: `packets(n)` packets in frame `n`, each
/// `octets(j)` octets of RTP payload, 700 unless it says otherwise.
fn send_jpeg_xs(scene: &mut Scene, packets: impl Fn(i128) -> i128, octets: impl Fn(i128) -> usize) {
    let mut seq: u16 = 0;
    for n in NOON * 60_000 / 1001..NOON * 60_000 / 1001 + 25 {
        let start = n * 1001 * NANOS / 60_000;
        let timestamp = (n * 1001 * 90_000 / 60_000) as u32;
        let packets = packets(n);
        for j in 0..packets {
            let last = j == packets - 1;
            let mut payload = vec![0u8; octets(j)];
            let header = jxs_payload(last, None, n, j);
            payload[..4].copy_from_slice(&header[..4]);
            let packet = rtp(112, last, seq, timestamp, 0x4444_0004, &payload);
            seq = seq.wrapping_add(1);
            let t = start + 500_000 + j * 16_683_333 * 9 / 10 / 31;
            scene.udp(t, "192.168.10.30:5010", "239.10.10.4:5010", &packet);
        }
    }
    send_ptp(scene, GM, 1, |_, _| false);
}

/// The JPEG XS fixture with `b=AS` set to the rate of 30 packets of 700 octets a frame:
/// 30 × 740 octets of IP packets × 8 × 60000/1001 is 10645.4 kb/s.
fn jpeg_xs_at_rate() -> SdpFile {
    let mut sdp = fixture("jpeg-xs.sdp");
    sdp.text = sdp.text.replace("b=AS:116000", "b=AS:10646");
    sdp
}

fn with_uneven_compressed_frames() -> Report {
    let mut scene = Scene::default();
    // 30 and 31 packets in turn.
    send_jpeg_xs(&mut scene, |n| 30 + n % 2, |_| 700);
    scene.analyse(&[fixture("jpeg-xs.sdp")])
}

/// 700 octets of JPEG XS in codestream mode, sent in order: an RFC 9134 payload header
/// whose L bit is `last`, for field 2 of interlaced video when `second`.
fn jxs_payload(last: bool, second: Option<bool>, frame: i128, packet: i128) -> [u8; 700] {
    let mut payload = [0u8; 700];
    let scan = match second {
        None => 0b00,
        Some(false) => 0b10,
        Some(true) => 0b11,
    };
    let f = (frame % 32) as u8;
    payload[0] = 0x80 | if last { 0x20 } else { 0 } | (scan << 3) | (f >> 2);
    payload[1] = (f & 0b11) << 6;
    payload[2..4].copy_from_slice(&((packet % 2048) as u16).to_be_bytes());
    payload
}

/// 1080i59.94 JPEG XS, each field with its own timestamp and its own marker, as VSF
/// TR-08:2026 §8.1.2.3 and RFC 9134 §4.2 ask.
fn with_interlaced_jpeg_xs(break_marker: bool) -> Report {
    let mut scene = Scene::default();
    let mut seq: u16 = 0;
    let first = NOON * 60_000 / 1001;
    for field in first..first + 50 {
        let start = field * 1001 * NANOS / 60_000;
        let timestamp = (field * 1001 * 90_000 / 60_000) as u32;
        let second = field % 2 == 1;
        for j in 0..20 {
            let last = j == 19;
            let payload = jxs_payload(last, Some(second), field / 2, j);
            let marker = last && !(break_marker && field == first + 10);
            let packet = rtp(112, marker, seq, timestamp, 0x4444_0005, &payload);
            seq = seq.wrapping_add(1);
            let t = start + 500_000 + j * 16_683_333 * 9 / 10 / 20;
            scene.udp(t, "192.168.10.30:5010", "239.10.10.4:5010", &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    let mut sdp = fixture("jpeg-xs.sdp");
    // 40 packets of 740 octets a frame × 8 × 30000/1001 is 7096.9 kb/s.
    sdp.text = sdp
        .text
        .replace("exactframerate=60000/1001", "exactframerate=30000/1001; interlace")
        .replace("b=AS:116000", "b=AS:7097");
    scene.analyse(&[sdp])
}

#[test]
fn interlaced_jpeg_xs_stamps_each_field() {
    let report = with_interlaced_jpeg_xs(false);
    assert_eq!(rules(&report), Vec::<&str>::new());
    let video = report.flows[0].video.as_ref().unwrap();
    assert_eq!(video.frame_rate.as_deref(), Some("30000/1001"));
    let report = with_interlaced_jpeg_xs(true);
    assert_eq!(rules(&report), ["marker-bit", "jxs-payload-header"]);
    assert!(finding(&report, "jxs-payload-header").message.contains("L (1) and M (0)"));
}

#[test]
fn compressed_frames_of_uneven_size() {
    let report = with_uneven_compressed_frames();
    assert_eq!(rules(&report), ["frame-packets", "frame-bytes", "cbr-rate"]);
    let frames = finding(&report, "frame-packets");
    // The first frame may have started before the capture, and the last may be cut short.
    assert_eq!((frames.message.as_str(), frames.count), ("frames carried from 30 to 31 packets", 11));
    let bytes = finding(&report, "frame-bytes");
    assert_eq!((bytes.message.as_str(), bytes.count), ("frames carried from 22200 to 22940 octets of IP packets", 11));
    assert_eq!(
        finding(&report, "cbr-rate").message,
        "b=AS:116000, but 22554 octets of IP packets a frame, on average, at 60000/1001 frames a second make 10816 kb/s"
    );
    let video = report.flows[0].video.as_ref().unwrap();
    assert_eq!(
        (video.frame_rate.as_deref(), video.vrx.as_ref(), video.vrx_skipped.as_ref()),
        (Some("60000/1001"), None, None)
    );
    assert!(video.cinst.as_ref().unwrap().peak <= 4);
}

#[test]
fn compressed_frames_of_one_size_at_the_signalled_rate() {
    let mut scene = Scene::default();
    send_jpeg_xs(&mut scene, |_| 30, |_| 700);
    let report = scene.analyse(&[jpeg_xs_at_rate()]);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    let video = report.flows[0].video.as_ref().unwrap();
    let octets = video.octets_per_frame.unwrap();
    assert_eq!((octets.min, octets.max), (22200.0, 22200.0));
    // A rate a kilobit a second too low.
    let mut low = jpeg_xs_at_rate();
    low.text = low.text.replace("b=AS:10646", "b=AS:10645");
    assert_eq!(rules(&scene.analyse(&[low])), ["cbr-rate"]);
}

fn with_unaligned_jpeg_xs() -> Report {
    let mut scene = Scene::default();
    // The fifth packet of each frame one octet long, and the last of each short.
    send_jpeg_xs(
        &mut scene,
        |_| 30,
        |j| match j {
            4 => 701,
            29 => 333,
            _ => 700,
        },
    );
    let mut sdp = jpeg_xs_at_rate();
    sdp.text = sdp.text.replace("b=AS:10646", "b=AS:10470");
    scene.analyse(&[sdp])
}

#[test]
fn jpeg_xs_payloads_in_multiples_of_eight_octets() {
    let report = with_unaligned_jpeg_xs();
    assert_eq!(rules(&report), ["jxsv-alignment"]);
    let unaligned = finding(&report, "jxsv-alignment");
    assert_eq!(
        unaligned.message,
        "25 packets other than the last of a field or frame carried payload data that is not a multiple of 8 octets, as few as 697"
    );
}

/// Frames whose sample row data headers break ST 2110-20's rules.
fn with_bad_sample_rows() -> Report {
    let mut scene = Scene::default();
    let mut video = Video::new("192.168.10.21:5004", "239.10.10.1:5004");
    for n in FRAME_50..FRAME_50 + 5 {
        let mut packets = video.frame(n, |_, t| t);
        // The payload header's first length, row and offset, after the RTP header and
        // the extended sequence number.
        let set =
            |packet: &mut Vec<u8>, at: usize, value: u16| packet[at..at + 2].copy_from_slice(&value.to_be_bytes());
        match n - FRAME_50 {
            // A length of no whole number of pixel groups, past the end of the payload.
            1 => set(&mut packets[5].1, 14, 1_201),
            // Back up to the top of the picture.
            2 => set(&mut packets[6].1, 16, 0),
            // Below the picture, and a row segment that runs past its right edge.
            3 => {
                set(&mut packets[7].1, 16, 1_080);
                set(&mut packets[39].1, 18, 1_600);
            }
            _ => {}
        }
        for (t, packet) in packets {
            scene.udp(t, video.source, video.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("video-dup.sdp")])
}

#[test]
fn sample_row_data_headers() {
    let report = with_bad_sample_rows();
    assert_eq!(rules(&report), ["srd-length", "srd-order", "srd-geometry"]);
    assert_eq!(
        finding(&report, "srd-length").message,
        "1 packet had sample row data headers that ST 2110-20 does not allow: 1 with lengths that are not whole pixel \
         groups of 5 octets, 1 with row segments that run past the end of the payload"
    );
    // Row 0 after row 135, and row 216 after row 1080.
    let order = finding(&report, "srd-order");
    assert_eq!(order.count, 2);
    assert_eq!(
        finding(&report, "srd-geometry").message,
        "2 packets placed samples outside the 1920x1080 picture the SDP file gives, the first at row 1080, offset 0"
    );
}

/// Block packing with blocks that are not 180 octets, and general packing with short
/// datagrams.
fn with_bad_packing() -> Report {
    let mut scene = Scene::default();
    Video::new("192.168.10.21:5004", "239.10.10.1:5004").send(&mut scene, FRAME_50, 5);
    let mut general = Video::new("192.168.20.21:5004", "239.20.10.1:5004");
    general.octets = 400;
    general.send(&mut scene, FRAME_50, 5);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    let mut sdp = fixture("video-dup.sdp");
    sdp.text = sdp.text.replacen("PM=2110GPM", "PM=2110BPM", 1);
    scene.analyse(&[sdp])
}

#[test]
fn packing_modes() {
    let report = with_bad_packing();
    assert_eq!(rules(&report), ["bpm-blocks", "gpm-short"]);
    let blocks = finding(&report, "bpm-blocks");
    assert_eq!((blocks.flow, blocks.count), (Some(1), 195));
    assert!(blocks.message.ends_with("not a multiple of 180 octets, as few as 1200"), "{}", blocks.message);
    let short = finding(&report, "gpm-short");
    assert_eq!(
        (short.flow, short.message.as_str()),
        (Some(2), "195 IP datagrams other than the last of a field or frame were under 1000 octets, as few as 448")
    );
}

/// The two halves of a MULTI-2SI picture, the second stamped a tick late from its
/// third frame.
fn with_split_timestamps() -> Report {
    let mut scene = Scene::default();
    Video::new("192.168.10.21:5004", "239.10.10.1:5004").send(&mut scene, FRAME_50, 10);
    let mut second = Video::new("192.168.20.21:5004", "239.20.10.1:5004");
    for n in FRAME_50..FRAME_50 + 10 {
        for (t, mut packet) in second.frame(n, |_, t| t) {
            if n >= FRAME_50 + 2 {
                let timestamp = u32::from_be_bytes(packet[4..8].try_into().unwrap()).wrapping_add(1);
                packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            }
            scene.udp(t, second.source, second.destination, &packet);
        }
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    let mut sdp = fixture("video-dup.sdp");
    sdp.text = sdp.text.replace("a=group:DUP", "a=group:MULTI-2SI");
    scene.analyse(&[sdp])
}

#[test]
fn multi_stream_parts_share_their_timestamps() {
    let report = with_split_timestamps();
    assert_eq!(rules(&report), ["rtp-alignment", "multistream-timestamp"]);
    let split = finding(&report, "multistream-timestamp");
    assert_eq!((split.flow, split.count), (Some(2), 8));
    assert!(
        split.message.starts_with(
            "8 frames carried other RTP timestamps than flow 1 of video-dup.sdp a=group:MULTI-2SI primary secondary"
        ),
        "{}",
        split.message
    );
    // Phases of a high frame rate camera have timestamps of their own.
    let mut sdp = fixture("video-dup.sdp");
    sdp.text = sdp.text.replace("a=group:DUP", "a=group:PHASED");
    let mut scene = Scene::default();
    Video::new("192.168.10.21:5004", "239.10.10.1:5004").send(&mut scene, FRAME_50, 3);
    Video::new("192.168.20.21:5004", "239.20.10.1:5004").send(&mut scene, FRAME_50 + 1, 3);
    assert!(rules(&scene.analyse(&[sdp])).is_empty());
}

#[test]
fn flows_without_sdp_files_are_recognised() {
    let report = facility(0, true).analyse(&[]);
    let essences: Vec<(&str, bool)> = report.flows.iter().map(|f| (f.essence.standard(), f.guessed)).collect();
    assert_eq!(essences, [("ST 2110-40", true), ("ST 2110-20", true), ("ST 2110-20", true), ("ST 2110-30", true)]);
    let video = report.flows[1].video.as_ref().unwrap();
    // The last packet starts row 1053; a real raster's last starts on its last row.
    assert_eq!((video.frame_rate.as_deref(), video.height), (Some("50"), Some(1054)));
    assert_eq!(video.vrx_skipped.as_deref(), Some("the SDP file gives no TP, so the read schedule is unknown"));
    assert_eq!(video.cinst.as_ref().unwrap().fits, ["2110TPN", "2110TPNL", "2110TPW"]);
    let audio = report.flows[3].audio.as_ref().unwrap();
    assert_eq!((audio.encoding.as_str(), audio.channels, audio.packet_time_us), ("L24", Some(8), Some(1000.0)));
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

fn with_ptp_faults() -> Report {
    let mut scene = Scene::default();
    // Sync 3 without its Follow_Up, and Delay_Req 5 unanswered.
    send_ptp(&mut scene, GM, 2, |kind, seq| (kind == 0x08 && seq == 3) || (kind == 0x09 && seq == 5));
    // A second grandmaster announcing at the same time.
    for i in 0..2 {
        let t = NOON * NANOS + i * NANOS + 200_000_000;
        scene.udp(t, "192.168.1.2:320", PTP_GENERAL, &announce(OTHER_GM, i as u16, t, -2));
    }
    scene.analyse(&[])
}

fn with_slow_syncs() -> Report {
    // Sync messages every 250 ms that claim 125 ms.
    let mut scene = Scene::default();
    for seq in 0..8 {
        let t = NOON * NANOS + i128::from(seq) * 250_000_000;
        scene.udp(t, GM_ADDRESS, PTP_EVENT, &ptp(0x00, 0, -3, TWO_STEP, seq, GM, &ptp_timestamp(t)));
        scene.udp(t + 30_000, GM_ADDRESS, PTP_GENERAL, &ptp(0x08, 2, -3, 0, seq, GM, &ptp_timestamp(t)));
    }
    scene.analyse(&[])
}

/// A Management COMMAND to every port with the synchronization metadata TLV of
/// ST 2059-2 §6.12: 25 fps, Local Time on UTC, no jam or jump to come, and
/// gmLockingStatus `locking`.
fn sync_metadata(clock: [u8; 8], seq: u16, locking: u8) -> Vec<u8> {
    let mut body = port([0xFF; 8], 0xFFFF);
    body.extend([0, 0, 3, 0]);
    body.extend(0x0003_u16.to_be_bytes());
    body.extend(48_u16.to_be_bytes());
    body.extend([0x68, 0x97, 0xE8, 0, 0, 1]);
    body.extend(25_u32.to_be_bytes());
    body.extend(1_u32.to_be_bytes());
    body.extend([locking, 0]);
    body.extend((-37_i32).to_be_bytes());
    body.extend(0_i32.to_be_bytes());
    body.extend([0; 18]);
    body.extend((-37_i32).to_be_bytes());
    body.extend([0, 0]);
    ptp(0x0D, 4, 127, 0, seq, clock, &body)
}

/// `message` from port 2 of its clock rather than port 1.
fn from_port_2(mut message: Vec<u8>) -> Vec<u8> {
    message[28..30].copy_from_slice(&2_u16.to_be_bytes());
    message
}

/// Four seconds of a grandmaster that breaks the profile's rules across messages, and
/// an SDP file that names another grandmaster.
fn with_ptp_profile_faults() -> Report {
    let mut scene = Scene::default();
    // Delay_Resp 7 goes unicast, though its Delay_Req went multicast.
    send_ptp(&mut scene, GM, 4, |kind, seq| kind == 0x09 && seq == 7);
    let request = NOON * NANOS + 7 * 125_000_000 + 61_000_000;
    let mut body = ptp_timestamp(request - 1_000_000 + 5_000);
    body.extend(port(FOLLOWER, 1));
    scene.udp(request + 5_000, GM_ADDRESS, "192.168.1.50:320", &ptp(0x09, 3, -3, 0, 7, GM, &body));
    // Metadata at 0.5 s and 1.5 s, then none until 3.5 s, when the grandmaster has lost
    // its lock.
    for (seq, (at, locking)) in [(500, 4), (1500, 4), (3500, 1)].into_iter().enumerate() {
        let t = NOON * NANOS + at * 1_000_000;
        scene.udp(t, "192.168.1.1:320", PTP_GENERAL, &sync_metadata(GM, seq as u16, locking));
    }
    // An Announce in holdover, between two locked ones.
    let t = NOON * NANOS + 2_200_000_000;
    let mut holdover = announce(GM, 1000, t, -2);
    holdover[34 + 14] = 7;
    scene.udp(t, "192.168.1.1:320", PTP_GENERAL, &holdover);
    // Port 2 announces once a second, and sends a logMinDelayReqInterval of 4 beside a
    // logSyncInterval of −3.
    for i in 0..4 {
        let t = NOON * NANOS + i * NANOS + 300_000_000;
        scene.udp(t, "192.168.1.1:320", PTP_GENERAL, &from_port_2(announce(GM, i as u16, t, 0)));
        let sync = ptp(0x00, 0, -3, 0, i as u16, GM, &ptp_timestamp(t));
        scene.udp(t + 1_000, "192.168.1.1:319", PTP_EVENT, &from_port_2(sync));
        let mut body = ptp_timestamp(t);
        body.extend(port(OTHER_GM, 1));
        scene.udp(t + 2_000, "192.168.1.1:320", PTP_GENERAL, &from_port_2(ptp(0x09, 3, 4, 0, i as u16, GM, &body)));
    }
    let mut sdp = fixture("audio-pcm.sdp");
    sdp.text = sdp.text.replace("08-00-11-FF-FE-21-E1-B0:127", "00-1D-C1-FF-FE-0B-33-01:127");
    scene.analyse(&[sdp])
}

#[test]
fn ptp_profile_faults_across_ports() {
    let report = with_ptp_profile_faults();
    let mut found = rules(&report);
    found.sort_unstable();
    assert_eq!(
        found,
        [
            "gm-clock-class",
            "ptp-announce-uniform",
            "ptp-delay-req-range",
            "ptp-gm-quality",
            "ptp-masters",
            "ptp-refclk",
            "ptp-sm-locking",
            "ptp-sm-tlv-rate",
            "ptp-transport-mode",
        ]
    );
    assert_eq!(
        finding(&report, "ptp-announce-uniform").message,
        "Announce messages gave logMessageInterval -2 from 08-00-11-FF-FE-21-E1-B0 port 1; 0 from 08-00-11-FF-FE-21-E1-B0 port 2"
    );
    assert_eq!(
        finding(&report, "ptp-delay-req-range").message,
        "08-00-11-FF-FE-21-E1-B0 port 2 sent Delay_Resp messages with logMinDelayReqInterval 4, outside -3 to 2 for its logSyncInterval -3"
    );
    assert_eq!(
        finding(&report, "ptp-transport-mode").message,
        "1 Delay_Resp message went otherwise than its Delay_Req came"
    );
    let rate = finding(&report, "ptp-sm-tlv-rate");
    assert_eq!(
        rate.message,
        "08-00-11-FF-FE-21-E1-B0 port 1 let more than 1.5 s pass between synchronization metadata TLVs 1 time, at most 2.0 s"
    );
    assert!(close(rate.at.unwrap(), 3.5 - 0.001_005), "{:?}", rate.at);
    assert_eq!(
        finding(&report, "ptp-sm-locking").message,
        "gmLockingStatus changed 1 time: at 3.499 s externally locked to internal"
    );
    assert_eq!(
        finding(&report, "ptp-gm-quality").message,
        "the grandmaster's quality changed 2 times: at 2.199 s class 6 to 7 (in holdover), at 2.250 s class 7 to 6 (locked to a primary reference)"
    );
    assert_eq!(
        finding(&report, "ptp-refclk").message,
        "audio-pcm.sdp stream 0 names grandmaster 00-1D-C1-FF-FE-0B-33-01 in domain 127, but its Announce messages named 08-00-11-FF-FE-21-E1-B0"
    );
    let domain = &report.ptp.domains[0];
    let classes: Vec<(u8, bool)> = domain.quality.iter().map(|q| (q.class, q.time_traceable)).collect();
    assert_eq!(classes, [(6, true), (7, true), (6, true)]);
    let metadata = domain.sync_metadata.as_ref().unwrap();
    assert_eq!(metadata.messages, 3);
    let locking: Vec<&str> = metadata.locking.iter().map(|l| l.status.as_str()).collect();
    assert_eq!(locking, ["externally locked", "internal"]);
}

#[test]
fn ptp_transport_modes_and_traceable_clocks() {
    // Announce, Sync and Follow_Up unicast, as in unicast mode, but a Delay_Req multicast.
    let mut scene = Scene::default();
    for seq in 0..4_u16 {
        let t = NOON * NANOS + i128::from(seq) * 250_000_000;
        scene.udp(t, GM_ADDRESS, "192.168.1.50:320", &announce(GM, seq, t, -2));
        scene.udp(t + 1_000, GM_ADDRESS, "192.168.1.50:319", &ptp(0x00, 0, -3, 0, seq, GM, &ptp_timestamp(t)));
    }
    scene.udp(NOON * NANOS + 2_000, FOLLOWER_ADDRESS, PTP_EVENT, &ptp(0x01, 1, 127, 0, 0, FOLLOWER, &ptp_timestamp(0)));
    let mut sdp = fixture("audio-pcm.sdp");
    sdp.text = sdp.text.replace("08-00-11-FF-FE-21-E1-B0:127", "traceable");
    let report = scene.analyse(std::slice::from_ref(&sdp));
    assert_eq!(rules(&report), ["ptp-transport-mode"]);
    assert_eq!(
        finding(&report, "ptp-transport-mode").message,
        "Announce, Sync or Follow_Up messages went unicast, as in unicast mode, beside 1 Delay_Req message sent multicast, as in multicast mode; unicast mode shares a domain with no other"
    );

    // A grandmaster accurate to 1 µs is not traceable as ST 2110-10 has it; nor, after
    // 3 s, is one that sends no synchronization metadata.
    let mut scene = Scene::default();
    for seq in 0..13_u16 {
        let t = NOON * NANOS + i128::from(seq) * 250_000_000;
        let mut message = announce(GM, seq, t, -2);
        message[34 + 15] = 0x23;
        scene.udp(t, GM_ADDRESS, PTP_GENERAL, &message);
    }
    let report = scene.analyse(&[sdp]);
    assert_eq!(rules(&report), ["ptp-sm-tlv-rate", "ptp-refclk"]);
    assert_eq!(
        finding(&report, "ptp-refclk").message,
        "audio-pcm.sdp stream 0 says the PTP is traceable, but grandmaster 08-00-11-FF-FE-21-E1-B0: clockAccuracy 23h is not within 250 ns"
    );
    assert_eq!(
        finding(&report, "ptp-sm-tlv-rate").message,
        "no synchronization metadata TLV came in 3.0 s of Announce messages"
    );
}

#[test]
fn another_profile_on_the_same_domain_number_is_its_own_domain() {
    let mut scene = Scene::default();
    send_ptp(&mut scene, GM, 2, |_, _| false);
    // Another grandmaster on domain 127 with majorSdoId 1 (as gPTP uses), announcing
    // every 8 s, which ST 2059-2 would not allow.
    for i in 0..2 {
        let t = NOON * NANOS + i * NANOS + 200_000_000;
        let mut message = announce(OTHER_GM, i as u16, t, 3);
        message[0] |= 0x10;
        scene.udp(t, "192.168.1.2:320", PTP_GENERAL, &message);
    }
    let report = scene.analyse(&[]);
    assert_eq!(rules(&report), Vec::<&str>::new());
    let domains: Vec<(u8, u16)> = report.ptp.domains.iter().map(|d| (d.domain, d.sdo_id)).collect();
    assert_eq!(domains, [(127, 0), (127, 0x100)]);
}

#[test]
fn ptp_faults_across_messages() {
    let report = with_ptp_faults();
    let mut found = rules(&report);
    found.sort_unstable();
    assert_eq!(found, ["ptp-delay-resp", "ptp-follow-up", "ptp-grandmaster-change", "ptp-masters"]);
    assert_eq!(finding(&report, "ptp-follow-up").message, "1 two-step Sync message had no Follow_Up within a second");
    assert_eq!(
        finding(&report, "ptp-delay-resp").message,
        "1 Delay_Req message had no Delay_Resp within a second, while 15 did"
    );
    assert!(
        finding(&report, "ptp-grandmaster-change")
            .message
            .starts_with("the grandmaster changed 4 times between 08-00-11-FF-FE-21-E1-B0, 00-1D-C1-FF-FE-0B-33-01")
    );
    assert_eq!(finding(&report, "ptp-masters").count, 2);
    assert_eq!(report.ptp.domains[0].grandmasters.len(), 2);

    let report = with_slow_syncs();
    assert_eq!(rules(&report), ["ptp-message-rate"]);
    assert!(
        finding(&report, "ptp-message-rate").message.ends_with(
            "sent Sync messages every 250.0 ms on average, not the 125.0 ms that logMessageInterval -3 gives"
        )
    );
}

#[test]
fn ptp_message_findings_count_once_per_port() {
    let mut scene = Scene::default();
    // Announce messages with clockClass 248, a grandmaster that has lost its reference.
    for i in 0..8 {
        let t = NOON * NANOS + i * 250_000_000;
        let mut message = announce(GM, i as u16, t, -2);
        message[34 + 14] = 248;
        scene.udp(t, "192.168.1.1:320", PTP_GENERAL, &message);
    }
    let report = scene.analyse(&[]);
    assert_eq!(rules(&report), ["gm-clock-class"]);
    let class = &report.findings[0];
    assert_eq!((class.count, class.domain, class.severity), (8, Some(127), Severity::Warning));
    assert!(class.message.starts_with("08-00-11-FF-FE-21-E1-B0 port 1: grandmaster"), "{}", class.message);
    assert!(class.message.ends_with("(8 messages)"), "{}", class.message);
}

#[test]
fn findings_name_sixteen_grandmasters_at_most() {
    let mut scene = Scene::default();
    for i in 0..20_u8 {
        let t = NOON * NANOS + i128::from(i) * 250_000_000;
        let mut gm = GM;
        gm[7] = i;
        scene.udp(t, "192.168.1.1:320", PTP_GENERAL, &announce(gm, 0, t, -2));
    }
    let report = scene.analyse(&[]);
    let change = finding(&report, "ptp-grandmaster-change");
    assert_eq!(change.count, 19);
    assert!(change.message.ends_with(", 08-00-11-FF-FE-21-E1-0F and others"), "{}", change.message);
    assert_eq!(report.ptp.domains[0].grandmasters.len(), 16);
}

#[test]
fn flows_and_ports_past_the_limits_are_counted() {
    let (flows, ports, extra) = (st2110_pcap::FLOW_LIMIT, st2110_pcap::PORT_LIMIT, 3);
    let mut scene = Scene::default();
    for i in 0..flows + extra {
        let t = NOON * NANOS + i as i128 * 1_000;
        let source = format!("10.0.{}.{}:5004", (i >> 8) & 0xFF, i & 0xFF);
        scene.udp(t, &source, "239.1.1.1:5004", &rtp(97, false, 0, 0, 1, &[0; 12]));
    }
    // A Delay_Req from each of many followers.
    for i in 0..ports + extra {
        let t = NOON * NANOS + i as i128 * 1_000;
        let mut clock = FOLLOWER;
        clock[6..].copy_from_slice(&(i as u16).to_be_bytes());
        scene.udp(t, FOLLOWER_ADDRESS, PTP_EVENT, &ptp(0x01, 1, 127, 0, 0, clock, &ptp_timestamp(t)));
    }
    let report = scene.analyse(&[]);
    assert_eq!((report.flows.len(), report.capture.rtp, report.capture.rtp_untracked), (flows, 10_003, 3));
    let ptp = &report.ptp;
    assert_eq!((ptp.domains[0].ports.len(), ptp.messages, ptp.untracked), (ports, 10_003, 3));
}

#[test]
fn values_too_big_to_measure_with_are_set_aside() {
    let mut video = fixture("video-dup.sdp");
    video.text = video.text.replace("exactframerate=50;", "exactframerate=2000000;");
    let mut audio = fixture("audio-pcm.sdp");
    audio.text = audio.text.replace("L24/48000/8", "L24/48000/65535");
    let mut scene = Scene::default();
    Video::new("192.168.10.21:5004", "239.10.10.1:5004").send(&mut scene, FRAME_50, 5);
    // Packets whose timestamps step 30,000 samples: with 65,535 channels, more octets
    // than 32 bits hold.
    for i in 0..10_u16 {
        let t = NOON * NANOS + i128::from(i) * 1_000_000;
        let packet = rtp(97, false, i, u32::from(i) * 30_000, 0x2222_0002, &[0x11; 144]);
        scene.udp(t, "192.168.10.22:5006", "239.10.10.2:5006", &packet);
    }
    let report = scene.analyse(&[video, audio]);
    let video = report.flows.iter().find_map(|f| f.video.as_ref()).unwrap();
    assert_eq!(video.models_skipped.as_deref(), Some("the SDP file's frame rate is out of range"));
    assert_eq!((video.frame_rate.as_deref(), video.fpt.as_ref()), (None, None));
    let channels = finding(&report, "audio-channels");
    assert!(channels.message.ends_with("not 5898150000"), "{}", channels.message);
}

#[test]
fn a_truncated_capture_is_analysed_as_far_as_it_goes() {
    let mut bytes = facility(0, true).pcap();
    bytes.truncate(bytes.len() - 10);
    let report = analyse(&bytes[..], &Options { sdp: facility_sdp(), ..Options::default() }).unwrap();
    assert_eq!(report.capture.error.as_deref(), Some("the file ends partway through a packet"));
    assert_eq!(report.capture.frames, 5085);
    assert!(analyse(&b"not a capture"[..], &Options::default()).is_err());
}

fn with_broken_ancillary_data() -> Report {
    let mut scene = Scene::default();
    send_anc_with(
        &mut scene,
        "239.10.10.3:5008",
        FRAME_50,
        50,
        |_| 500_000,
        |i| match i {
            // Two frames with no packet at all.
            10 | 11 => None,
            20 => {
                let mut broken = captions();
                broken[12] ^= 0x08;
                Some(anc_payload(0, &[broken]))
            }
            21 => Some(anc_payload(0b01, &[captions()])),
            22 => Some(anc_payload(0, &[anc_packet(0x7FF, 0xFFF, 0x41, 0x05, &[1, 2])])),
            23 => Some(anc_payload(0, &[anc_packet(0x7FF, 0xFFF, 0xE7, 0x00, &[0; 4])])),
            // An exact line, then lines out of order.
            24 => Some(anc_payload(0, &[anc_packet(9, 0xFFF, 0x61, 0x01, &[1])])),
            25 => Some(anc_payload(
                0,
                &[anc_packet(12, 0xFFF, 0x61, 0x01, &[1]), anc_packet(10, 0xFFF, 0x61, 0x01, &[2])],
            )),
            26 => {
                let mut long = anc_payload(0, &[captions()]);
                long[3] += 4;
                Some(long)
            }
            _ => Some(anc_payload(0, &[captions()])),
        },
    );
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("anc.sdp")])
}

#[test]
fn ancillary_data_payloads_and_keep_alive_packets() {
    let report = with_broken_ancillary_data();
    let raised: BTreeSet<&str> = rules(&report).into_iter().collect();
    let expected =
        ["anc-audio-edh-packets", "anc-did-sdid", "anc-field", "anc-keepalive", "anc-location", "anc-payload"];
    assert_eq!(raised, expected.into_iter().collect(), "{:#?}", report.findings);
    assert_eq!(
        finding(&report, "anc-keepalive").message,
        "2 frames passed with no packet, though none was lost: a frame with no ANC data still needs a packet with ANC_Count 0 and the marker set"
    );
    let payload = finding(&report, "anc-payload");
    assert_eq!(payload.count, 2);
    assert!(
        payload.message.starts_with("2 packets had malformed payloads; the first: ANC packet 1: its checksum word is")
    );
    let unlisted = finding(&report, "anc-did-sdid");
    assert_eq!(
        unlisted.message,
        "2 packets carried ANC packets of types the SDP file's DID_SDID does not list; the first: ANC packet 1 is DID 0x41 SDID 0x05"
    );
    assert!(finding(&report, "anc-audio-edh-packets").message.ends_with("ANC packet 1 is DID 0xE7, embedded audio"));
    let locations: Vec<&str> =
        report.findings.iter().filter(|f| f.rule == "anc-location").map(|f| f.message.as_str()).collect();
    assert_eq!(
        locations,
        [
            "3 ANC packets proposed an exact line or data stream, but the SDP file signals no VPID_Code to say which SDI format it is in",
            "1 packet proposed locations earlier in the frame than the packets before them; the first: ANC packet 2 proposes line 10 word 4095, after line 12 word 4095",
        ]
    );
}

/// Ancillary data on a second address, with `TM` replaced.
fn anc_sdp(destination: &str, tm: &str) -> SdpFile {
    let mut sdp = fixture("anc.sdp");
    sdp.text = sdp.text.replace("239.10.10.3", destination).replace("TM=CTM", tm);
    sdp.name = format!("anc-{destination}.sdp");
    sdp
}

fn with_mistimed_ancillary_data() -> Report {
    let mut scene = Scene::default();
    let clean = |_| Some(anc_payload(0, &[captions()]));
    // CTM allows a frame and 1 ms: 22 ms is late.
    send_anc_with(&mut scene, "239.10.10.3:5008", FRAME_50, 25, |_| 22_000_000, clean);
    // LLTM allows a frame and 8 line times, at most 305 µs at 50 fps: 20.5 ms is late.
    send_anc_with(&mut scene, "239.10.10.4:5008", FRAME_50, 25, |_| 20_500_000, clean);
    // A frame before the deadline is the earliest, so 21 ms before the frame starts is early.
    send_anc_with(&mut scene, "239.10.10.5:5008", FRAME_50, 25, |_| -21_000_000, clean);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("anc.sdp"), anc_sdp("239.10.10.4", "TM=LLTM"), anc_sdp("239.10.10.5", "TM=LLTM")])
}

#[test]
fn ancillary_data_sent_outside_its_transmission_model() {
    let report = with_mistimed_ancillary_data();
    let flows: Vec<(Option<usize>, &str)> = report.findings.iter().map(|f| (f.flow, f.rule)).collect();
    assert_eq!(
        flows,
        [
            (Some(1), "timestamp-future"),
            (Some(1), "anc-send-time"),
            (Some(2), "anc-send-time"),
            (Some(3), "anc-send-time")
        ],
        "{:#?}",
        report.findings
    );
    let messages: Vec<&str> =
        report.findings.iter().filter(|f| f.rule == "anc-send-time").map(|f| f.message.as_str()).collect();
    assert!(
        messages[0].starts_with(
            "25 packets arrived as much as 21000.0 µs before the start of their frame, earlier than LLTM allows"
        ),
        "{}",
        messages[0]
    );
    assert!(
        messages[1].starts_with(
            "25 packets arrived as much as 20500.0 µs after the start of their frame, later than LLTM allows"
        ),
        "{}",
        messages[1]
    );
    assert!(
        messages[2].starts_with(
            "25 packets arrived as much as 22000.0 µs after the start of their frame, later than CTM allows"
        ),
        "{}",
        messages[2]
    );
}

/// An ST 2110-31 sender of eight AES3 subframes a sample period, 125 µs a packet, with
/// `fault` to spoil a packet's RTP header and payload.
fn with_broken_aes3() -> Report {
    let mut scene = Scene::default();
    let mut seq = 0_u16;
    for i in NOON * 8000..NOON * 8000 + 800 {
        let mut payload = Vec::new();
        for sample in i * 6..i * 6 + 6 {
            for channel in 0..8 {
                let first = channel % 2 == 0;
                let block = first && sample % 192 == 0;
                payload.extend([u8::from(block) << 5 | u8::from(first) << 4, 0x12, 0x34, 0x56]);
            }
        }
        let k = i - NOON * 8000;
        if k == 400 {
            // F on the second subframe of the second AES3 signal, not the first.
            payload[8] ^= 0x10;
            payload[12] ^= 0x10;
        }
        let packet = rtp(98, k == 500, seq, (i * 6) as u32, 0x4444_0004, &payload);
        seq = seq.wrapping_add(1);
        scene.udp((i * 6 + 6) * NANOS / 48_000 + 150_000, "192.168.10.50:5016", "239.10.10.7:5016", &packet);
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("aes3.sdp")])
}

#[test]
fn aes3_subframes_keep_their_framing() {
    let report = with_broken_aes3();
    assert_eq!(rules(&report), ["am824-header", "am824-subframe"], "{:#?}", report.findings);
    assert_eq!(
        finding(&report, "am824-subframe").message,
        "1 packet had AM824 subframes out of AES3 framing; the first: subframe 1 of AES3 signal 2 in sample period 1 has F clear, on the first subframe of its AES3 frame"
    );
    assert_eq!(
        finding(&report, "am824-header").message,
        "1 packet had RTP headers ST 2110-31 does not allow; the first: the marker bit is set"
    );
    assert_eq!(report.flows[0].essence, st2110_sdp::Essence::Aes3);
}

fn with_broken_fast_metadata() -> Report {
    let mut scene = Scene::default();
    let mut seq = 0_u16;
    for k in 0..200_i128 {
        // A packet every 10 ms, none between 1.0 s and 1.6 s.
        if (101..160).contains(&k) {
            continue;
        }
        let mut payload = (0x100_u32 << 10 | 2).to_be_bytes().to_vec();
        payload.extend([0xAB; 8]);
        if k == 50 {
            payload[3] = 0;
            payload.truncate(4);
        }
        let t = NOON * NANOS + k * 10_000_000;
        let packet = rtp(117, k == 20, seq, (t * 48_000 / NANOS) as u32, 0x5555_0005, &payload);
        seq = seq.wrapping_add(1);
        scene.udp(t + 100_000, "192.168.10.22:5012", "239.10.10.5:5012", &packet);
    }
    send_ptp(&mut scene, GM, 2, |_, _| false);
    scene.analyse(&[fixture("fmx.sdp")])
}

#[test]
fn fast_metadata_markers_gaps_and_packages() {
    let report = with_broken_fast_metadata();
    assert_eq!(rules(&report), ["fmx-marker", "fmx-interval", "fmx-payload"], "{:#?}", report.findings);
    assert_eq!(
        finding(&report, "fmx-interval").message,
        "the stream went 1 time without a packet, though none was lost, the longest for 600.0 ms"
    );
    assert_eq!(
        finding(&report, "fmx-payload").message,
        "1 packet had malformed payloads; the first: Data Item Package 1, of type 0x000100, has a Data Item Length of 0"
    );
}

fn with_broken_timed_text() -> Report {
    let mut scene = Scene::default();
    let mut seq = 0_u16;
    let mut send =
        |scene: &mut Scene, t: i128, marker: bool, timestamp: u32, reserved: u16, text: &[u8], skip: bool| {
            let mut payload = reserved.to_be_bytes().to_vec();
            payload.extend((text.len() as u16).to_be_bytes());
            payload.extend(text);
            let packet = rtp(118, marker, seq, timestamp, 0x6666_0006, &payload);
            seq = seq.wrapping_add(1);
            if !skip {
                scene.udp(t, "192.168.10.40:5014", "239.10.10.6:5014", &packet);
            }
        };
    for doc in 0..20_i128 {
        let t = NOON * NANOS + doc * 100_000_000;
        let timestamp = |d: i128| ((NOON * NANOS + d * 100_000_000) * 90_000 / NANOS) as u32;
        // Document 5 repeats document 4's timestamp.
        let stamp = timestamp(if doc == 5 { 4 } else { doc });
        // Its second fragment of document 3 carries another timestamp.
        let second = if doc == 3 { stamp + 1 } else { stamp };
        send(&mut scene, t, false, stamp, u16::from(doc == 7), b"<tt xml:lang=\"en\"><body>", false);
        send(&mut scene, t + 1_000_000, true, second, 0, b"</body></tt>", doc == 9);
        // A keep-alive between documents.
        send(&mut scene, t + 50_000_000, true, stamp, 0, b"", false);
    }
    send_ptp(&mut scene, GM, 2, |_, _| false);
    scene.analyse(&[fixture("ttml.sdp")])
}

#[test]
fn timed_text_documents() {
    let report = with_broken_timed_text();
    assert_eq!(
        rules(&report),
        ["packet-loss", "ttml-payload", "ttml-document", "ttml-document-loss"],
        "{:#?}",
        report.findings
    );
    assert_eq!(
        finding(&report, "ttml-payload").message,
        "1 packet had malformed payload headers; the first: the reserved bits are 0x0001"
    );
    let document = finding(&report, "ttml-document");
    assert_eq!(document.count, 2);
    assert_eq!(
        document.message,
        "2 packets broke a document's framing; the first: a document's packets carried timestamps 3061378376 and then 3061378377"
    );
    assert!(finding(&report, "ttml-document-loss").message.starts_with("1 document lost a packet partway through"));
}

fn with_jitter_beyond_aes67() -> Report {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    let packets: Vec<(i128, Vec<u8>)> = (NOON * 1000..NOON * 1000 + 1000).map(|i| audio.packet(i)).collect();
    for (i, (t, packet)) in packets.iter().enumerate() {
        // Of every hundred packets, the first twenty held back and sent with the 21st.
        let held = i % 100;
        let t = if held < 20 { packets[i - held + 20].0 - (20 - held as i128) * 1_000 } else { *t };
        scene.udp(t, audio.source, audio.destination, packet);
    }
    send_ptp(&mut scene, GM, 1, |_, _| false);
    scene.analyse(&[fixture("audio-pcm.sdp")])
}

#[test]
fn jitter_past_what_aes67_allows_is_an_error() {
    let report = with_jitter_beyond_aes67();
    assert_eq!(rules(&report), ["ts-df-limit", "ts-df"], "{:#?}", report.findings);
    let limit = finding(&report, "ts-df-limit");
    assert_eq!(limit.count, 5);
    assert!(
        limit.message.starts_with(
            "TS-DF reached 19980.0 µs in 5 of 5 200 ms windows, not under the 17000.0 µs that AES67 allows"
        ),
        "{}",
        limit.message
    );
}

#[test]
fn audio_latency_counts_from_the_signalled_offset() {
    let mut scene = Scene::default();
    let mut audio = Audio::new();
    (audio.destination, audio.channels, audio.offset) = ("239.69.83.67:5004", 2, 963_214_424);
    audio.send(&mut scene, NOON * 1000, 1000);
    send_ptp(&mut scene, GM, 1, |_, _| false);
    let report = scene.analyse(&[fixture("aes67-offset.sdp")]);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    assert_eq!(report.timescale.clock, Clock::Ptp);
    let latency = report.flows[0].audio.as_ref().unwrap().latency.unwrap();
    assert!(close(latency.min, 1150.0) && close(latency.max, 1150.0), "{latency:?}");
}

#[test]
fn every_rule_has_a_capture_that_raises_it() {
    let reports = [
        with_bursts(),
        with_late_packets(),
        with_network_faults(),
        with_big_and_fragmented_datagrams(),
        with_new_ssrc_and_wrong_payload_type(),
        with_too_few_channels(),
        with_short_audio_packets(),
        with_held_back_audio(),
        with_future_timestamps(),
        with_misaligned_timestamps(),
        with_uneven_compressed_frames(),
        with_interlaced_jpeg_xs(true),
        with_unaligned_jpeg_xs(),
        with_bad_sample_rows(),
        with_bad_packing(),
        with_split_timestamps(),
        with_ptp_faults(),
        with_slow_syncs(),
        with_broken_ancillary_data(),
        with_mistimed_ancillary_data(),
        with_broken_aes3(),
        with_broken_fast_metadata(),
        with_broken_timed_text(),
        with_jitter_beyond_aes67(),
        with_ptp_profile_faults(),
    ];
    let raised: BTreeSet<&str> = reports.iter().flat_map(|r| r.findings.iter().map(|f| f.rule)).collect();
    for rule in st2110_pcap::rules::ALL {
        assert!(raised.contains(rule.id), "no capture raises {}", rule.id);
    }
}

#[test]
fn docs_list_every_rule() {
    let docs = include_str!("../../../docs/rules.md");
    assert!(
        docs.contains(&st2110_sdp::rules::markdown_table(st2110_pcap::rules::ALL)),
        "docs/rules.md is stale: run `st2110 rules --format markdown > docs/rules.md`"
    );
}
