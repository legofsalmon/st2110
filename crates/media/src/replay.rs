//! Playing a capture into a receiving session: each datagram to the leg it was sent
//! on, on PTP time, as fast as the capture reads or at the pace it was captured.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use st2110_pcap::{CaptureError, Reader};

use crate::describe::Leg;
use crate::receive::{self, PROGRESS_NS, Session, Sink};

const NANOS: i128 = 1_000_000_000;

/// Feeds a capture's datagrams to the session, each to the leg whose destination (and
/// source, where two legs share a destination) it matches, and finishes the session at
/// the capture's last packet. A capture on UTC is moved onto PTP time by `tai_utc`, and
/// one already on PTP time is not: whichever puts the first packet nearer its RTP
/// timestamp. Before each datagram, `pace` has its time in the capture, and reading
/// stops when it gives false. Gives the shift in seconds, once a packet has decided it.
pub fn replay<R: Read>(
    session: &mut Session,
    mut reader: Reader<R>,
    tai_utc: i32,
    sink: &mut impl Sink,
    mut pace: impl FnMut(i128) -> bool,
) -> Result<Option<i32>, CaptureError> {
    let legs = session.description().legs.clone();
    let clock_rate = session.description().media.clock_rate();
    let mut shift: Option<i32> = None;
    let (mut end, mut reported) = (0, None);
    while let Some(frame) = reader.next_frame() {
        let frame = frame?;
        end = end.max(frame.time);
        let st2110_pcap::net::Packet::Udp(datagram) = st2110_pcap::net::parse(frame.link, frame.data) else {
            continue;
        };
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (datagram.source, datagram.destination) else {
            continue;
        };
        let matching = |l: &&Leg| l.destination == destination;
        let Some(leg) = legs
            .iter()
            .position(|l| matching(&l) && l.source == Some(*source.ip()))
            .or_else(|| legs.iter().position(|l| matching(&l)))
        else {
            continue;
        };
        if !datagram.complete() {
            continue;
        }
        if !pace(frame.time) {
            break;
        }
        let shift = *shift.get_or_insert_with(|| match st2110_pcap::rtp::header(datagram.payload, true) {
            Some(h) => {
                let off = |s: i32| {
                    receive::since_timestamp(h.timestamp, frame.time + i128::from(s) * NANOS, clock_rate).abs()
                };
                if off(tai_utc) < off(0) { tai_utc } else { 0 }
            }
            None => tai_utc,
        });
        session.push(leg, *source.ip(), frame.time + i128::from(shift) * NANOS, datagram.payload, sink);
        let reported = reported.get_or_insert(frame.time);
        if frame.time - *reported >= PROGRESS_NS {
            sink.progress(&session.report());
            *reported = frame.time;
        }
    }
    // The capture stopped at its last packet, whatever it was.
    session.finish(end + i128::from(shift.unwrap_or(0)) * NANOS, sink);
    Ok(shift)
}

/// Paces a capture as it was captured, for [`replay`]: lets each packet go at its time
/// in the capture, counting from when the first went, a millisecond early at most, and
/// stops once `stop` is set.
pub fn as_captured(stop: &AtomicBool) -> impl FnMut(i128) -> bool + '_ {
    let mut first = None;
    move |time| {
        let (start, at) = *first.get_or_insert((time, Instant::now()));
        let due = at + Duration::from_nanos(u64::try_from(time - start).unwrap_or(0));
        loop {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            let now = Instant::now();
            if due <= now + Duration::from_millis(1) {
                return true;
            }
            thread::sleep((due - now).min(Duration::from_millis(50)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;
    use crate::describe::{Clock, Description, Media};
    use crate::files::{Capture, UNKNOWN_SOURCE};
    use crate::format::VideoFormat;
    use crate::receive::Report;
    use crate::send::Sender;

    #[test]
    fn plays_a_capture_at_its_pace_until_stopped() {
        let stop = AtomicBool::new(false);
        let mut pace = as_captured(&stop);
        let started = Instant::now();
        // Times in nanoseconds, 30 ms apart: the second waits for its turn.
        assert!(pace(1_000_000_000));
        assert!(pace(1_030_000_000));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(28) && waited < Duration::from_millis(500), "{waited:?}");
        // A packet from before the first goes at once.
        assert!(pace(999_000_000));
        stop.store(true, Ordering::Relaxed);
        assert!(!pace(1_031_000_000));
    }

    /// Counts frames and keeps each progress report.
    #[derive(Default)]
    struct Follow {
        frames: u64,
        progress: Vec<Report>,
    }

    impl Sink for Follow {
        fn frame(&mut self, _: &crate::video::FrameInfo, _: &[u8]) {
            self.frames += 1;
        }

        fn progress(&mut self, report: &Report) {
            self.progress.push(report.clone());
        }
    }

    #[test]
    fn replays_a_capture_and_reports_progress_every_half_second_of_it() {
        let stream = Description {
            name: "Bars".into(),
            media: Media::Video(VideoFormat::from_name("320x180p25").unwrap()),
            payload_type: 96,
            legs: vec![Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: None }],
            clock: Some(Clock::Traceable),
            ttl: 32,
        };
        // 1.2 s of bars, into a capture in memory on UTC.
        let destination = stream.legs[0].destination;
        let legs = vec![(SocketAddrV4::new(UNKNOWN_SOURCE, 5004), destination)];
        let mut capture = Capture::new(Vec::new(), legs, 32, 37).unwrap();
        let mut sender = Sender::new(&stream, 1000, -18.0, 0x1234, 0).unwrap();
        let start = 1_790_510_437 * NANOS;
        sender.run(&mut capture, start, start + 1_200_000_000).unwrap();
        let file = capture.into_inner();
        let mut session = Session::new(&stream).unwrap();
        let mut follow = Follow::default();
        let reader = Reader::new(&file[..]).unwrap();
        let shift = replay(&mut session, reader, 37, &mut follow, |_| true).unwrap();
        assert_eq!((shift, follow.frames), (Some(37), 30));
        // At 0.5 s and 1.0 s into it, counting as it went.
        let frames: Vec<u64> = follow.progress.iter().map(|r| r.video.unwrap().counts.frames).collect();
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert!(frames[0] >= 12 && frames[0] < frames[1] && frames[1] < 30, "{frames:?}");
        assert!(session.report().problems.is_empty(), "{:?}", session.report());

        // Stopped after ten frames' packets, it stops there.
        let mut session = Session::new(&stream).unwrap();
        let mut follow = Follow::default();
        let reader = Reader::new(&file[..]).unwrap();
        let utc = start - 37 * NANOS;
        replay(&mut session, reader, 37, &mut follow, |time| time < utc + 400_000_000).unwrap();
        assert_eq!(follow.frames, 10);
    }
}
