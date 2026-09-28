//! Streams sent into captures, measured by the RP 2110-25 analyser and received back.

use std::net::{Ipv4Addr, SocketAddrV4};

use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::files::Capture;
use st2110_media::format::{AudioFormat, Packing, SenderType, VideoFormat};
use st2110_media::receive::{Report, Session};
use st2110_media::send::{Output, SendCounts, Sender};
use st2110_pcap::{Options, SdpFile};
use st2110_sdp::Severity;
use st2110_sdp::video::{Depth, Sampling};

const SOURCES: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 168, 10, 21), Ipv4Addr::new(192, 168, 20, 21)];

/// 2026-09-27 12:00:00 UTC, in nanoseconds of TAI.
const NOON: i128 = 1_790_510_437 * 1_000_000_000;

/// Writes each packet into a capture, and gives it to a receiver on every leg, 20 µs
/// later.
struct Both<'a> {
    capture: Capture<Vec<u8>>,
    session: &'a mut Session,
    legs: usize,
}

impl Output for Both<'_> {
    fn send(&mut self, packet: &[u8], at: i128) -> std::io::Result<()> {
        self.capture.send(packet, at)?;
        for (leg, &source) in SOURCES.iter().enumerate().take(self.legs) {
            self.session.push(leg, source, at + 20_000, packet, &mut ());
        }
        Ok(())
    }
}

fn stream(media: Media) -> Description {
    let legs = ["239.10.1.1:5004", "239.10.2.1:5004"]
        .iter()
        .zip(SOURCES)
        .map(|(to, source)| Leg { destination: to.parse().unwrap(), source: Some(source) })
        .collect();
    Description { name: "test".into(), media, payload_type: 96, legs, clock: Some(Clock::Traceable), ttl: 32 }
}

/// Sends `seconds` of the stream from noon, and gives what was sent, what the analyser
/// made of the capture, and what the receiver made of the packets.
fn send(stream: &Description, nanoseconds: i128) -> (SendCounts, st2110_pcap::Report, Report) {
    let mut session = Session::new(stream).unwrap();
    let ports: Vec<(SocketAddrV4, SocketAddrV4)> =
        stream.legs.iter().map(|l| (SocketAddrV4::new(l.source.unwrap(), 5004), l.destination)).collect();
    let capture = Capture::new(Vec::new(), ports, 32, 37).unwrap();
    let mut both = Both { capture, session: &mut session, legs: stream.legs.len() };
    let mut sender = Sender::new(stream, 1000, -18.0, 0x5eed, 65_000).unwrap();
    let sent = sender.run(&mut both, NOON, NOON + nanoseconds).unwrap();
    let bytes = both.capture.into_inner();
    session.finish(&mut ());
    let options = Options { sdp: vec![SdpFile { name: "test.sdp".into(), text: stream.sdp(1) }], ..Options::default() };
    let analysed = st2110_pcap::analyse(&bytes[..], &options).unwrap();
    (sent, analysed, session.report())
}

fn video(name: &str, sampling: Sampling, depth: Depth, packing: Packing, sender_type: SenderType) -> VideoFormat {
    let mut format = VideoFormat::from_name(name).unwrap();
    (format.sampling, format.depth, format.packing, format.sender_type) = (sampling, depth, packing, sender_type);
    format
}

#[test]
fn video_keeps_to_its_sender_type_and_arrives_whole() {
    use {Depth::*, Packing::*, Sampling::*, SenderType::*};
    let formats = [
        video("1080p50", YCbCr422, Bits10, General, Wide),
        video("1080p59.94", YCbCr422, Bits10, Block, Narrow),
        video("720p50", Rgb, Bits12, General, NarrowLinear),
        video("1280x720p25", YCbCr444, Bits8, Block, Narrow),
        video("2160p50", YCbCr422, Bits10, General, Wide),
    ];
    for format in formats {
        let name = format.to_string();
        let tp = format.sender_type.as_str();
        let stream = stream(Media::Video(format));
        // Three frames, whatever the rate.
        let rate = if name.contains("59.94") {
            59.94
        } else if name.contains("p25") {
            25.0
        } else {
            50.0
        };
        let (sent, analysed, received) = send(&stream, (3e9 / rate) as i128 - 1000);
        assert_eq!((sent.frames, sent.skipped), (3, 0), "{name}");
        let serious: Vec<_> = analysed.findings.iter().filter(|f| f.severity != Severity::Info).collect();
        assert!(serious.is_empty(), "{name}: {serious:#?}");
        assert_eq!(analysed.flows.len(), 2, "{name}");
        for flow in &analysed.flows {
            assert_eq!((flow.packets, flow.lost), (sent.packets, 0), "{name}");
            let v = flow.video.as_ref().unwrap();
            let cinst = v.cinst.as_ref().unwrap();
            assert!(cinst.fits.iter().any(|t| t == tp), "{name}: {tp} not in {:?}", cinst.fits);
            let vrx = v.vrx.as_ref().unwrap();
            assert_eq!((vrx.underflows, vrx.overflows), (0, 0), "{name}: {vrx:?}");
            // Each frame's first packet goes after its alignment point, but before its first read.
            let fpt = v.fpt.as_ref().unwrap();
            assert!(fpt.min > 0.0 && fpt.max < vrx.troffset_us, "{name}: {fpt:?} {vrx:?}");
            assert_eq!(v.rtp_offset.as_ref().unwrap().max, 0.0, "{name}");
        }
        let counts = received.video.unwrap().counts;
        assert_eq!((counts.frames, counts.whole), (3, 3), "{name}");
        assert_eq!((received.lost, received.class.as_deref()), (0, Some("D")), "{name}");
        assert!(received.problems.is_empty(), "{name}: {:?}", received.problems);
    }
}

#[test]
fn audio_keeps_its_packet_time() {
    let formats = [
        AudioFormat::new(2),
        AudioFormat { bits: 16, packet_time_us: 125, ..AudioFormat::new(8) },
        AudioFormat { sample_rate: 96_000, ..AudioFormat::new(4) },
    ];
    for format in formats {
        let name = format.to_string();
        let stream = stream(Media::Audio(format.clone()));
        let (sent, analysed, received) = send(&stream, 100_000_000);
        let serious: Vec<_> = analysed.findings.iter().filter(|f| f.severity != Severity::Info).collect();
        assert!(serious.is_empty(), "{name}: {serious:#?}");
        for flow in &analysed.flows {
            assert_eq!((flow.packets, flow.lost), (sent.packets, 0), "{name}");
            let audio = flow.audio.as_ref().unwrap();
            assert_eq!(audio.channels, Some(format.channels), "{name}");
            assert_eq!(audio.packet_time_us, Some(f64::from(format.packet_time_us)), "{name}");
            // Each packet goes as its last sample falls due.
            let latency = audio.latency.as_ref().unwrap();
            assert!((latency.min - f64::from(format.packet_time_us)).abs() < 0.001, "{name}: {latency:?}");
        }
        let audio = received.audio.unwrap();
        assert_eq!(audio.counts.samples, u64::from(format.sample_rate) / 10, "{name}");
        assert!(audio.peaks.iter().all(|p| p.is_some_and(|db| (db + 18.0).abs() < 0.01)), "{name}: {:?}", audio.peaks);
        assert!(received.problems.is_empty(), "{name}: {:?}", received.problems);
    }
}
