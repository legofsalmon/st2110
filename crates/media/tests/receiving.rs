//! Streams received through loss, reordering, legs far apart, outages, pauses,
//! restarts, clock steps and strays.

use std::net::Ipv4Addr;

use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::format::{AudioFormat, VideoFormat};
use st2110_media::receive::{Report, Session, Sink};
use st2110_media::send::{Output, Sender};
use st2110_media::video::FrameInfo;
use st2110_sdp::Rational;

const NANOS: i128 = 1_000_000_000;
/// 2026-09-27 12:00:00 UTC, in nanoseconds of TAI.
const T: i128 = 1_790_510_437 * NANOS;
const SOURCES: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 1, 1)];

#[derive(Default)]
struct Keep(Vec<(Vec<u8>, i128)>);

impl Output for Keep {
    fn send(&mut self, packet: &[u8], at: i128) -> std::io::Result<()> {
        self.0.push((packet.to_vec(), at));
        Ok(())
    }
}

#[derive(Default)]
struct Collect {
    frames: Vec<FrameInfo>,
    samples: usize,
}

impl Sink for Collect {
    fn frame(&mut self, info: &FrameInfo, _: &[u8]) {
        self.frames.push(*info);
    }

    fn samples(&mut self, samples: &[i32]) {
        self.samples += samples.len();
    }
}

fn stream(media: Media, legs: usize) -> Description {
    let legs = ["239.1.1.1:5004", "239.2.1.1:5004"]
        .iter()
        .zip(SOURCES)
        .take(legs)
        .map(|(to, source)| Leg { destination: to.parse().unwrap(), source: Some(source) })
        .collect();
    Description { name: "test".into(), media, payload_type: 96, legs, clock: Some(Clock::Traceable), ttl: 32 }
}

fn video(legs: usize) -> Description {
    stream(Media::Video(VideoFormat::new(640, 360, Rational::new(50, 1).unwrap())), legs)
}

fn audio(legs: usize) -> Description {
    stream(Media::Audio(AudioFormat::new(2)), legs)
}

/// What a sender sends from `T` for `nanoseconds`.
fn sent(stream: &Description, nanoseconds: i128) -> Vec<(Vec<u8>, i128)> {
    let mut out = Keep::default();
    Sender::new(stream, 1000, -18.0, 7, 0).unwrap().run(&mut out, T, T + nanoseconds).unwrap();
    out.0
}

/// Receives datagrams as (arrival, leg, datagram) in the order they arrive, then stops.
fn receive(stream: &Description, mut arrivals: Vec<(i128, usize, Vec<u8>)>) -> (Report, Collect) {
    arrivals.sort_by_key(|a| (a.0, a.1));
    let mut session = Session::new(stream).unwrap();
    let mut sink = Collect::default();
    for (at, leg, datagram) in &arrivals {
        session.push(*leg, SOURCES[*leg], *at, datagram, &mut sink);
    }
    session.finish(arrivals.last().map_or(T, |a| a.0) + NANOS, &mut sink);
    (session.report(), sink)
}

/// Each packet on each leg `delays[leg]` after it was sent, unless `lose(leg, index)`.
fn arrivals(
    packets: &[(Vec<u8>, i128)],
    delays: &[i128],
    lose: impl Fn(usize, usize) -> bool,
) -> Vec<(i128, usize, Vec<u8>)> {
    let mut out = Vec::new();
    for (i, (packet, at)) in packets.iter().enumerate() {
        for (leg, delay) in delays.iter().enumerate() {
            if !lose(leg, i) {
                out.push((at + delay, leg, packet.clone()));
            }
        }
    }
    out
}

fn whole(sink: &Collect) -> bool {
    sink.frames.iter().all(|f| f.whole)
}

#[test]
fn a_leg_a_millisecond_behind_repairs_the_end_of_a_frame() {
    let d = video(2);
    let packets = sent(&d, 3 * 20_000_000 - 1000);
    let per_frame = packets.len() / 3;
    // Leg 1 loses frame 0's last packet, with the marker bit; leg 2 has it 1 ms later.
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 1_020_000], |leg, i| leg == 0 && i == per_frame - 1));
    assert_eq!((sink.frames.len(), whole(&sink)), (3, true), "{:?}", sink.frames);
    assert_eq!((r.lost, r.too_late, r.class.as_deref()), (0, 0, Some("A")));
    assert_eq!(r.skew.unwrap().max_ns, 1_000_000);
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.notes, ["leg 1 (239.1.1.1:5004 from 10.0.0.1) lost 1 packet"]);
}

#[test]
fn a_leg_two_milliseconds_behind_repairs_audio() {
    let d = audio(2);
    let packets = sent(&d, 20_000_000);
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 2_020_000], |leg, i| leg == 0 && i == 5));
    assert_eq!(sink.samples, packets.len() * 96);
    let counts = r.audio.as_ref().unwrap().counts;
    assert_eq!((r.lost, counts.missing, counts.packets), (0, 0, packets.len() as u64));
    assert_eq!(r.class.as_deref(), Some("A"));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
}

#[test]
fn a_leg_further_behind_than_the_wait_is_too_late() {
    let d = audio(2);
    let packets = sent(&d, 200_000_000);
    // Leg 2 runs 80 ms behind, more than the 50 ms the receiver waits, and has the
    // packet leg 1 lost.
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 80_020_000], |leg, i| leg == 0 && i == 50));
    assert_eq!(sink.samples, packets.len() * 96);
    assert_eq!((r.lost, r.too_late, r.audio.as_ref().unwrap().counts.missing), (0, 1, 48));
    assert_eq!(r.class.as_deref(), Some("C"));
    assert_eq!(
        r.problems,
        [
            "1 packet came too late to play, after the receiver had waited 50 ms for it",
            "1.000 ms of audio missing, filled with silence"
        ]
    );
}

#[test]
fn an_outage_of_two_seconds_is_counted_and_filled() {
    let d = audio(1);
    let packets = sent(&d, 4 * NANOS);
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, i| (1000..3000).contains(&i)));
    assert_eq!(sink.samples, packets.len() * 96);
    let counts = r.audio.as_ref().unwrap().counts;
    assert_eq!((r.lost, counts.missing, counts.jumps, r.restarts), (2000, 96_000, 0, 0));
    assert_eq!(r.problems, ["2000 packets lost", "2000.000 ms of audio missing, filled with silence"]);
}

#[test]
fn a_leg_that_goes_down_for_a_second_is_counted() {
    let d = video(2);
    let packets = sent(&d, 3 * NANOS);
    let down = |at: i128| (NANOS / 2..3 * NANOS / 2).contains(&(at - T));
    let outage = packets.iter().filter(|(_, at)| down(*at)).count() as u64;
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 40_000], |leg, i| leg == 0 && down(packets[i].1)));
    assert_eq!((sink.frames.len(), whole(&sink)), (150, true));
    assert_eq!((r.legs[0].rtp.lost, r.legs[1].rtp.lost, r.lost), (outage, 0, 0));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.notes, [format!("leg 1 (239.1.1.1:5004 from 10.0.0.1) lost {outage} packets")]);
}

#[test]
fn a_restarted_sender_starts_again() {
    let d = video(1);
    let mut packets = sent(&d, 3 * 20_000_000 - 1000);
    // 100 ms later it starts again with another synchronisation source and sequence
    // numbers, as RFC 3550 asks.
    let mut out = Keep::default();
    Sender::new(&d, 1000, -18.0, 8, 0x4000_0000)
        .unwrap()
        .run(&mut out, T + 100_000_000, T + 160_000_000 - 1000)
        .unwrap();
    packets.extend(out.0);
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, _| false));
    assert_eq!((sink.frames.len(), whole(&sink)), (6, true));
    let video = r.video.unwrap();
    assert_eq!((video.counts.missing, video.skipped, video.jumps), (0, 0, 0));
    assert_eq!((r.lost, r.restarts, r.ssrc), (0, 1, Some(8)));
    assert_eq!(
        r.problems,
        ["the stream restarted once: a new synchronisation source, or sequence numbers or timestamps that \
             started again elsewhere"]
    );
}

#[test]
fn a_source_that_comes_back_is_followed_again() {
    let d = audio(1);
    let mut first = Sender::new(&d, 1000, -18.0, 7, 0).unwrap();
    let mut out = Keep::default();
    first.run(&mut out, T, T + 100_000_000).unwrap();
    // Another source for 100 ms, then the first again.
    Sender::new(&d, 1000, -18.0, 8, 30_000).unwrap().run(&mut out, T + 100_000_000, T + 200_000_000).unwrap();
    first.run(&mut out, T + 200_000_000, T + 1_200_000_000).unwrap();
    let (r, sink) = receive(&d, arrivals(&out.0, &[20_000], |_, _| false));
    assert_eq!(sink.samples, out.0.len() * 96);
    assert_eq!((r.passed, r.lost, r.restarts, r.stale, r.ssrc), (out.0.len() as u64, 0, 2, 0, Some(7)));
}

#[test]
fn a_capture_played_twice_restarts_on_the_same_numbers() {
    let d = audio(2);
    // A second of packets, then the same again, as a sender whose numbers start in the
    // same place sends them when it restarts, or a capture played in a loop.
    let mut packets = sent(&d, NANOS);
    packets.extend(packets.clone().into_iter().map(|(p, at)| (p, at + NANOS)));
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 320_000], |_, _| false));
    assert_eq!(sink.samples, packets.len() * 96);
    assert_eq!((r.passed, r.lost, r.too_late, r.restarts), (packets.len() as u64, 0, 0, 1));
    assert_eq!(
        r.problems,
        ["the stream restarted once: a new synchronisation source, or sequence numbers or timestamps that \
             started again elsewhere"]
    );
}

#[test]
fn a_clock_that_steps_back_restarts_the_stream() {
    let d = video(1);
    let mut sender = Sender::new(&d, 1000, -18.0, 7, 0).unwrap();
    let mut before = Keep::default();
    sender.run(&mut before, T, T + 100_000_000 - 1000).unwrap();
    // The sender's time steps back a second, and it carries on counting sequence
    // numbers; its packets arrive when they would have.
    let mut after = Keep::default();
    sender.run(&mut after, T - NANOS + 100_000_000, T - NANOS + 600_000_000 - 1000).unwrap();
    let mut packets = before.0;
    packets.extend(after.0.into_iter().map(|(p, at)| (p, at + NANOS)));
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, _| false));
    assert_eq!((sink.frames.len(), whole(&sink)), (30, true));
    assert_eq!((r.lost, r.restarts), (0, 1));
    assert!((r.video.unwrap().frame_rate.unwrap() - 50.0).abs() < 1e-6);
}

#[test]
fn frames_the_timestamps_skip_with_no_packets_missing_were_never_sent() {
    let d = video(1);
    let mut sender = Sender::new(&d, 1000, -18.0, 7, 0).unwrap();
    let mut before = Keep::default();
    sender.run(&mut before, T, T + 100_000_000 - 1000).unwrap();
    // Three frames' time on, with no packets missing: the sender left three frames out,
    // or its clock stepped.
    let mut after = Keep::default();
    sender.run(&mut after, T + 160_000_000, T + 260_000_000 - 1000).unwrap();
    let mut packets = before.0;
    packets.extend(after.0.into_iter().map(|(p, at)| (p, at - 60_000_000)));
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, _| false));
    assert_eq!((sink.frames.len(), whole(&sink)), (10, true));
    let video = r.video.unwrap();
    assert_eq!((video.unsent, video.skipped, video.jumps, r.restarts, r.lost), (3, 0, 0, 0, 0));
    assert_eq!(
        r.problems,
        ["3 frames never sent: the RTP timestamps skip them, with no packets missing to match, so the sender left \
             them out or its clock stepped"]
    );
}

/// What a sender sends from `T` for `first` nanoseconds, then from `T + second.0` to
/// `T + second.1`, counting on its sequence numbers, with each packet sent `shift`
/// nanoseconds after its time from then.
fn sent_twice(stream: &Description, first: i128, second: (i128, i128), shift: i128) -> Vec<(Vec<u8>, i128)> {
    let mut sender = Sender::new(stream, 1000, -18.0, 7, 0).unwrap();
    let mut out = Keep::default();
    sender.run(&mut out, T, T + first).unwrap();
    let mut after = Keep::default();
    sender.run(&mut after, T + second.0, T + second.1).unwrap();
    out.0.extend(after.0.into_iter().map(|(p, at)| (p, at + shift)));
    out.0
}

#[test]
fn a_sender_that_pauses_sends_no_frames_meanwhile() {
    let d = video(1);
    // Five frames, a second with none, then five more.
    let mut packets = sent_twice(&d, 100_000_000 - 1000, (1_100_000_000, 1_200_000_000 - 1000), 0);
    // It stopped halfway through the fifth, and sent the rest of it as it went on.
    let per_frame = packets.len() / 10;
    for (i, packet) in packets[4 * per_frame + per_frame / 2..5 * per_frame].iter_mut().enumerate() {
        packet.1 = T + 1_100_000_000 - 1_000_000 + i as i128;
    }
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, _| false));
    assert_eq!((sink.frames.len(), whole(&sink)), (10, true));
    let video = r.video.unwrap();
    assert_eq!((video.unsent, video.skipped, video.jumps, r.restarts, r.lost), (50, 0, 0, 0, 0));
    assert!((video.frame_rate.unwrap() - 50.0).abs() < 1e-6);
    assert_eq!(
        r.problems,
        ["50 frames never sent: the RTP timestamps skip them, with no packets missing to match, so the sender \
             left them out or its clock stepped"]
    );
}

#[test]
fn an_audio_sender_that_pauses_is_filled_with_silence() {
    let d = audio(2);
    let packets = sent_twice(&d, 100_000_000, (1_100_000_000, 1_200_000_000), 0);
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 40_000], |_, _| false));
    // Two channels of a second's silence as well as the packets.
    assert_eq!(sink.samples, packets.len() * 96 + 2 * 48_000);
    let counts = r.audio.as_ref().unwrap().counts;
    assert_eq!((counts.unsent, counts.missing, counts.jumps, r.restarts, r.lost), (48_000, 0, 0, 0, 0));
    assert_eq!(
        r.problems,
        ["1000.000 ms of audio never sent, filled with silence: the RTP timestamps skip it, with no packets \
             missing to match"]
    );
}

#[test]
fn a_clock_that_steps_on_restarts_the_stream() {
    let d = video(1);
    // The sender's time steps on a second, and it carries on counting sequence numbers;
    // its packets arrive when they would have.
    let packets = sent_twice(&d, 100_000_000 - 1000, (1_100_000_000, 1_600_000_000 - 1000), -NANOS);
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000], |_, _| false));
    assert_eq!((sink.frames.len(), whole(&sink)), (30, true));
    let video = r.video.unwrap();
    assert_eq!((video.unsent, video.jumps, r.lost, r.restarts), (0, 0, 0, 1));
    assert!((video.frame_rate.unwrap() - 50.0).abs() < 1e-6);
}

#[test]
fn legs_further_apart_than_the_window_merge_what_they_can() {
    let d = audio(2);
    let packets = sent(&d, 3 * NANOS);
    // Leg 2 runs 1.1 s behind leg 1, and neither loses anything.
    let (r, sink) = receive(&d, arrivals(&packets, &[20_000, 1_100_020_000], |_, _| false));
    assert_eq!(sink.samples, packets.len() * 96);
    assert_eq!((r.passed, r.lost, r.too_late, r.restarts), (packets.len() as u64, 0, 0, 0));
    // All but the last 512, which come after leg 1 has stopped.
    let too_late = packets.len() as u64 - 512;
    assert_eq!((r.legs[1].rtp.too_late, r.class.as_deref()), (too_late, None));
    assert_eq!(
        r.problems,
        [format!(
            "leg 2 (239.2.1.1:5004 from 10.0.1.1) ran more than 512 packets behind the other: {too_late} packets \
             came too late to merge"
        )]
    );
}

#[test]
fn packets_swapped_across_a_frame_boundary_are_put_back() {
    let d = video(1);
    let mut packets = sent(&d, 3 * 20_000_000 - 1000);
    let per_frame = packets.len() / 3;
    packets.swap(per_frame - 1, per_frame);
    // In the order they arrived, whatever their times.
    let mut session = Session::new(&d).unwrap();
    let mut sink = Collect::default();
    for (packet, at) in &packets {
        session.push(0, SOURCES[0], *at, packet, &mut sink);
    }
    session.finish(T + NANOS, &mut sink);
    let r = session.report();
    assert_eq!((sink.frames.len(), whole(&sink), r.lost), (3, true, 0));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.notes, ["leg 1 (239.1.1.1:5004 from 10.0.0.1): 1 packet arrived out of order"]);
}

#[test]
fn a_stray_is_left_out() {
    let d = video(1);
    let packets = sent(&d, 20 * 20_000_000 - 1000);
    let per_frame = packets.len() / 20;
    // A packet like frame 2's first, but 100 sequence numbers on and 2^30 ticks (3.3
    // hours) later.
    let (first, at) = &packets[2 * per_frame];
    let mut stray = first.clone();
    let timestamp = u32::from_be_bytes(stray[4..8].try_into().unwrap()).wrapping_add(1 << 30);
    stray[4..8].copy_from_slice(&timestamp.to_be_bytes());
    let sequence = u16::from_be_bytes(stray[2..4].try_into().unwrap()).wrapping_add(100);
    stray[2..4].copy_from_slice(&sequence.to_be_bytes());
    let mut arrivals = arrivals(&packets, &[20_000], |_, _| false);
    arrivals.push((at - 1, 0, stray));
    let (r, sink) = receive(&d, arrivals);
    assert_eq!((sink.frames.len(), whole(&sink)), (20, true));
    assert_eq!((r.lost, r.strays, r.restarts), (0, 1, 0));
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.notes, ["1 packet fitted neither the stream nor a restart, left out"]);
}
