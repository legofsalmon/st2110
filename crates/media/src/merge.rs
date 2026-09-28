//! ST 2022-7 seamless protection: one stream made of the first copy of each packet to
//! arrive on any leg, put back in sequence order.
//!
//! The [`Merger`] keeps a window of recent sequence numbers, with the legs each came on
//! and when the first copy arrived. A copy on another leg is dropped, and how much later
//! it came is the packet time differential of ST 2022-7:2019 §5 (PD = max |Pi − Pj|).
//! A packet far outside the window, or one in it whose RTP timestamp is far from where
//! the stream's pace puts it, is held until the next one shows what it was, as RFC 3550
//! §A.1 does: the end of an outage, when the timestamps moved on as far as the sequence
//! numbers; a leg running further behind than the window, when they are as much older;
//! a stray, when no packet follows it; and otherwise a sender that restarted.
//!
//! The [`Playout`] then puts the first copies back in sequence order. When one is
//! missing, it holds the packets after it for as long as the legs may differ, so that a
//! copy on a leg that runs behind can still fill the gap.

use std::collections::{BTreeMap, VecDeque};

/// Extends 16-bit RTP sequence numbers to 32 bits by counting wraps, for payloads that
/// carry no extended sequence number, such as ST 2110-30 audio.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extender {
    highest: Option<u32>,
}

impl Extender {
    /// The 32-bit sequence number with these low 16 bits that is nearest the highest
    /// taken so far.
    pub fn extend(&self, sequence: u16) -> u32 {
        match self.highest {
            None => u32::from(sequence),
            Some(highest) => highest.wrapping_add_signed(i32::from(sequence.wrapping_sub(highest as u16) as i16)),
        }
    }

    /// Takes an extended sequence number as the stream's, so that later ones extend
    /// from it when it is the highest. Leave out packets that may be strays, so that
    /// they cannot lead the count astray.
    pub fn take(&mut self, sequence: u32) {
        if self.highest.is_none_or(|highest| (sequence.wrapping_sub(highest) as i32) > 0) {
            self.highest = Some(sequence);
        }
    }

    /// Forgets the stream, for one that starts again.
    pub fn reset(&mut self) {
        self.highest = None;
    }
}

/// How a stream's RTP timestamps move on with its sequence numbers, which tells an
/// outage or a leg running behind, whose timestamps keep pace, from a restart.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pace {
    /// Ticks of the media clock from one packet to the next on average, until the
    /// merger has measured it.
    pub ticks_per_packet: f64,
    /// How far a timestamp may be from where the pace puts it and still keep pace, in
    /// ticks: two frames of video, or two packet times of audio.
    pub slack: f64,
    /// Ticks of the media clock a second, which tells a sender that paused, whose
    /// packets come as late after their timestamps as ever when it goes on, from a clock
    /// that stepped on.
    pub clock_rate: f64,
}

/// What the merger made of a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The first copy to arrive: pass it on.
    First,
    /// A copy of one already passed on, or of the one held.
    Copy,
    /// Older than the window, from a leg that runs further behind than the window
    /// allows: too late to pass on.
    TooLate,
    /// Far from the stream's other packets: held until the next shows what it is.
    Held,
    /// The packet held last and this one both pass: every leg was out, or the sender
    /// paused, and the stream went on.
    Resumed,
    /// The sender restarted: the packet held last and this one start the stream again.
    Restart,
    /// From before the sender restarted, and come since: left out.
    Stale,
}

/// What one leg delivered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LegCounts {
    /// Packets that arrived.
    pub received: u64,
    /// Packets this leg never delivered: gaps in its own sequence numbers.
    pub lost: u64,
    /// Packets that arrived after a later one on this leg.
    pub reordered: u64,
    /// Packets that arrived on this leg twice.
    pub duplicates: u64,
    /// Packets the merged stream took from this leg, the first copy to arrive.
    pub first: u64,
    /// Packets older than the window when they came: the leg ran further behind the
    /// others than the window allows.
    pub too_late: u64,
}

/// How far apart the legs' copies of the same packets arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Skew {
    /// Packets that arrived on more than one leg.
    pub pairs: u64,
    /// The packet time differential, PD: the most one copy of a packet came after the
    /// first, in nanoseconds.
    pub max_ns: i64,
    /// How much later leg 2's copies came than leg 1's on average, in nanoseconds:
    /// negative when leg 2 was ahead.
    pub mean_ns: f64,
}

/// What the merger has counted.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MergeCounts {
    /// Each leg's packets, path 1 first.
    pub legs: Vec<LegCounts>,
    /// Packets passed on.
    pub passed: u64,
    /// Packets no leg delivered.
    pub lost: u64,
    /// Packets from legs that ran too far behind, on every leg.
    pub too_late: u64,
    /// Times the sender restarted: a new synchronisation source, or sequence numbers
    /// or timestamps that started again elsewhere.
    pub restarts: u64,
    /// Packets that fitted neither the stream nor a restart, left out.
    pub strays: u64,
    /// Packets from before a restart that came after it, left out.
    pub stale: u64,
    /// How far apart the legs were, when packets came on more than one.
    pub skew: Option<Skew>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Leg {
    counts: LegCounts,
    highest: Option<u32>,
    lowest: u32,
}

/// The stream the merger follows, from its first packet or its last restart.
#[derive(Clone, Copy, Debug)]
struct Regime {
    ssrc: u32,
    /// The lowest sequence number taken, no more than a window behind the highest.
    lowest: u32,
    highest: u32,
    /// The highest's timestamp.
    timestamp: u32,
    /// The packet the pace is being measured from: its sequence number and timestamp.
    anchor: (u32, u32),
    ticks_per_packet: f64,
}

/// A packet on probation, with when each leg's copy arrived.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    ssrc: u32,
    sequence: u32,
    timestamp: u32,
    arrivals: [Option<i64>; 8],
    /// The stream's packets taken since.
    age: u32,
}

/// Packets that may follow a held one and confirm it, and the stream's packets that
/// may come before it is given up as a stray.
const CONFIRM_WITHIN: i32 = 16;
const PROBATION: u32 = 64;

/// Merges the legs of an ST 2022-7 stream, or follows the sequence numbers of a stream
/// with one leg.
#[derive(Clone, Debug)]
pub struct Merger {
    window: u32,
    pace: Pace,
    /// For each slot, a bit for each leg the packet came on.
    seen: Vec<u8>,
    first_leg: Vec<u8>,
    /// When the first copy came, in nanoseconds after `base`.
    arrival: Vec<i64>,
    base: Option<i128>,
    regime: Option<Regime>,
    /// The synchronisation source and highest sequence number before the last restart.
    retired: Option<(u32, u32)>,
    candidate: Option<Candidate>,
    /// The packets that came soonest after their timestamps, in the stretch of the pace
    /// before this one and in this one: their timestamps and when they came.
    soonest: [Option<(u32, i64)>; 2],
    legs: Vec<Leg>,
    passed: u64,
    lost: u64,
    restarts: u64,
    strays: u64,
    stale: u64,
    pairs: u64,
    max_skew: i64,
    skew_sum: i128,
}

impl Merger {
    /// A merger for 1 to 8 legs that remembers `window` sequence numbers, rounded up to
    /// a power of two ([`Merger::window_for`] gives one to suit a stream), for a stream
    /// whose timestamps keep `pace`.
    pub fn new(legs: usize, window: u32, pace: Pace) -> Self {
        assert!((1..=8).contains(&legs), "1 to 8 legs");
        let window = window.clamp(16, 1 << 22).next_power_of_two();
        Self {
            window,
            pace,
            seen: vec![0; window as usize],
            first_leg: vec![0; window as usize],
            arrival: vec![0; window as usize],
            base: None,
            regime: None,
            retired: None,
            candidate: None,
            soonest: [None; 2],
            legs: vec![Leg::default(); legs],
            passed: 0,
            lost: 0,
            restarts: 0,
            strays: 0,
            stale: 0,
            pairs: 0,
            max_skew: 0,
            skew_sum: 0,
        }
    }

    /// A window of half a second of packets at this rate, enough for the 450 ms by which
    /// ST 2022-7 class C receivers allow the legs to differ, or twice `max_skew_ns` when
    /// that is longer.
    pub fn window_for(packets_per_second: f64, max_skew_ns: i64) -> u32 {
        let seconds = (2.0 * max_skew_ns as f64 / 1e9).max(0.5);
        (packets_per_second * seconds).ceil().clamp(256.0, f64::from(1 << 22)) as u32
    }

    /// The window, in sequence numbers.
    pub fn window(&self) -> u32 {
        self.window
    }

    /// The synchronisation source of the stream it follows.
    pub fn ssrc(&self) -> Option<u32> {
        self.regime.map(|r| r.ssrc)
    }

    /// Takes a packet that arrived on leg `leg` at `at` nanoseconds, with its
    /// synchronisation source, 32-bit sequence number and RTP timestamp, and says what
    /// to do with it.
    pub fn push(&mut self, leg: usize, ssrc: u32, sequence: u32, timestamp: u32, at: i128) -> Verdict {
        let base = *self.base.get_or_insert(at);
        let time = (at - base).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        self.legs[leg].counts.received += 1;
        let Some(regime) = self.regime else {
            self.start(ssrc, sequence, timestamp);
            return self.take(leg, sequence, timestamp, time);
        };
        let window = self.window as i32;
        if ssrc == regime.ssrc {
            let ahead = sequence.wrapping_sub(regime.highest) as i32;
            if -window < ahead && ahead <= window {
                let ticks = timestamp.wrapping_sub(regime.timestamp) as i32;
                if self.near_pace(ahead, ticks, regime.ticks_per_packet) {
                    self.age_candidate();
                    return self.take(leg, sequence, timestamp, time);
                }
            } else if ahead < 0 && self.follows(leg, sequence) {
                return self.too_late(leg, sequence);
            }
        }
        let stale = self.retired.is_some_and(|(retired, highest)| {
            retired == ssrc
                && (ssrc != regime.ssrc
                    || sequence.wrapping_sub(highest).min(highest.wrapping_sub(sequence)) <= self.window)
        });
        if stale {
            self.stale += 1;
            return Verdict::Stale;
        }
        self.probation(leg, ssrc, sequence, timestamp, time)
    }

    /// What it has counted, with the packets missing from the window so far as lost.
    pub fn counts(&self) -> MergeCounts {
        MergeCounts {
            legs: self.legs.iter().map(|l| l.counts).collect(),
            passed: self.passed,
            lost: self.lost + self.open_losses(),
            too_late: self.legs.iter().map(|l| l.counts.too_late).sum(),
            restarts: self.restarts,
            strays: self.strays + u64::from(self.candidate.is_some()),
            stale: self.stale,
            skew: (self.pairs > 0).then(|| Skew {
                pairs: self.pairs,
                max_ns: self.max_skew,
                mean_ns: self.skew_sum as f64 / self.pairs as f64,
            }),
        }
    }

    fn slot(&self, sequence: u32) -> usize {
        (sequence & (self.window - 1)) as usize
    }

    fn start(&mut self, ssrc: u32, sequence: u32, timestamp: u32) {
        let ticks_per_packet = self.regime.map_or(self.pace.ticks_per_packet, |r| r.ticks_per_packet);
        self.soonest = [None; 2];
        self.regime = Some(Regime {
            ssrc,
            lowest: sequence,
            highest: sequence,
            timestamp,
            anchor: (sequence, timestamp),
            ticks_per_packet,
        });
    }

    /// Takes a packet of the stream, in or ahead of the window.
    fn take(&mut self, leg: usize, sequence: u32, timestamp: u32, time: i64) -> Verdict {
        let regime = self.regime.expect("a stream");
        let ahead = sequence.wrapping_sub(regime.highest) as i32;
        if ahead > 0 {
            self.advance(ahead as u32, sequence, timestamp);
        } else if (sequence.wrapping_sub(regime.lowest) as i32) < 0 {
            self.regime.as_mut().expect("a stream").lowest = sequence;
        }
        let slot = self.slot(sequence);
        let bit = 1u8 << leg;
        let mask = self.seen[slot];
        self.leg_arrived(leg, sequence, mask & bit != 0);
        if mask == 0 {
            self.seen[slot] = bit;
            self.first_leg[slot] = leg as u8;
            self.arrival[slot] = time;
            let packet = (timestamp, time);
            if self.soonest[1].is_none_or(|soonest| self.later(packet, soonest) < 0.0) {
                self.soonest[1] = Some(packet);
            }
            self.passed += 1;
            self.legs[leg].counts.first += 1;
            return Verdict::First;
        }
        if mask & bit == 0 {
            self.seen[slot] |= bit;
            let later = time.saturating_sub(self.arrival[slot]);
            self.pairs += 1;
            self.max_skew = self.max_skew.max(later);
            let first = usize::from(self.first_leg[slot]);
            self.skew_sum += if leg > first { i128::from(later) } else { -i128::from(later) };
        }
        Verdict::Copy
    }

    /// Moves the window on `ahead` sequence numbers to `sequence`, counting those that
    /// leave it with no leg having delivered them as lost.
    fn advance(&mut self, ahead: u32, sequence: u32, timestamp: u32) {
        let regime = self.regime.expect("a stream");
        if ahead >= self.window {
            // Every slot leaves the window, and those between never enter it.
            self.lost += self.open_losses() + u64::from(ahead - self.window);
            self.seen.fill(0);
        } else {
            for step in 1..=ahead {
                let entering = regime.highest.wrapping_add(step);
                let slot = self.slot(entering);
                let leaving = entering.wrapping_sub(self.window);
                if self.seen[slot] == 0 && (leaving.wrapping_sub(regime.lowest) as i32) >= 0 {
                    self.lost += 1;
                }
                self.seen[slot] = 0;
            }
        }
        let window = self.window;
        let slack = self.pace.slack;
        let r = self.regime.as_mut().expect("a stream");
        r.highest = sequence;
        r.timestamp = timestamp;
        if sequence.wrapping_sub(r.lowest) >= window {
            r.lowest = sequence.wrapping_sub(window - 1);
        }
        // The pace, measured afresh over every stretch of 32 slacks of timestamps.
        let ticks = timestamp.wrapping_sub(r.anchor.1) as i32;
        let packets = sequence.wrapping_sub(r.anchor.0) as i32;
        if ticks < 0 || packets < 0 {
            r.anchor = (sequence, timestamp);
        } else if f64::from(ticks) >= 32.0 * slack && packets > 0 {
            r.ticks_per_packet = f64::from(ticks) / f64::from(packets);
            r.anchor = (sequence, timestamp);
            self.soonest = [self.soonest[1], None];
        }
    }

    /// Sequence numbers in the window, from the lowest taken to the highest, that no leg
    /// has delivered.
    fn open_losses(&self) -> u64 {
        let Some(regime) = self.regime else { return 0 };
        let span = regime.highest.wrapping_sub(regime.lowest).min(self.window - 1);
        (0..=span).filter(|&back| self.seen[self.slot(regime.highest.wrapping_sub(back))] == 0).count() as u64
    }

    fn leg_arrived(&mut self, leg: usize, sequence: u32, duplicate: bool) {
        let window = self.window;
        let l = &mut self.legs[leg];
        if duplicate {
            l.counts.duplicates += 1;
            return;
        }
        let Some(highest) = l.highest else {
            (l.highest, l.lowest) = (Some(sequence), sequence);
            return;
        };
        let ahead = sequence.wrapping_sub(highest) as i32;
        if ahead > 0 {
            l.counts.lost += (ahead - 1) as u64;
            l.highest = Some(sequence);
            if sequence.wrapping_sub(l.lowest) >= window {
                l.lowest = sequence.wrapping_sub(window - 1);
            }
        } else {
            l.counts.reordered += 1;
            if (sequence.wrapping_sub(l.lowest) as i32) >= 0 {
                l.counts.lost = l.counts.lost.saturating_sub(1);
            } else if highest.wrapping_sub(sequence) < window {
                l.lowest = sequence;
            }
        }
    }

    /// Whether a packet follows on from the leg's own, however far behind the others.
    fn follows(&self, leg: usize, sequence: u32) -> bool {
        let window = self.window as i32;
        self.legs[leg].highest.is_some_and(|highest| {
            let ahead = sequence.wrapping_sub(highest) as i32;
            -window < ahead && ahead <= window
        })
    }

    fn too_late(&mut self, leg: usize, sequence: u32) -> Verdict {
        self.leg_arrived(leg, sequence, false);
        self.legs[leg].counts.too_late += 1;
        Verdict::TooLate
    }

    fn age_candidate(&mut self) {
        if let Some(candidate) = &mut self.candidate {
            candidate.age += 1;
            if candidate.age > PROBATION {
                self.candidate = None;
                self.strays += 1;
            }
        }
    }

    /// Whether `ticks` of timestamps keep pace with `packets` of sequence numbers.
    fn keeps_pace(&self, packets: i32, ticks: i32, ticks_per_packet: f64) -> bool {
        let expected = f64::from(packets) * ticks_per_packet;
        (f64::from(ticks) - expected).abs() <= expected.abs() / 4.0 + self.pace.slack
    }

    /// Whether a packet in the window has a timestamp no further from where the pace puts
    /// it than the pace itself moves, and two slacks: the loosest test, to catch a stray
    /// or a clock that stepped without taking a sender whose packets a frame differ from
    /// the estimate for one.
    fn near_pace(&self, packets: i32, ticks: i32, ticks_per_packet: f64) -> bool {
        let expected = f64::from(packets) * ticks_per_packet;
        (f64::from(ticks) - expected).abs() <= expected.abs() + 2.0 * self.pace.slack
    }

    /// A packet far from the stream: holds it, or confirms the one held.
    fn probation(&mut self, leg: usize, ssrc: u32, sequence: u32, timestamp: u32, time: i64) -> Verdict {
        if let Some(mut candidate) = self.candidate.filter(|c| c.ssrc == ssrc) {
            if candidate.sequence == sequence {
                match candidate.arrivals[leg] {
                    Some(_) => self.legs[leg].counts.duplicates += 1,
                    None => candidate.arrivals[leg] = Some(time),
                }
                self.candidate = Some(candidate);
                return Verdict::Copy;
            }
            let after = sequence.wrapping_sub(candidate.sequence) as i32;
            let ticks = timestamp.wrapping_sub(candidate.timestamp) as i32;
            if (1..=CONFIRM_WITHIN).contains(&after) && self.keeps_pace(after, ticks, self.pace.ticks_per_packet) {
                self.candidate = None;
                return self.confirm(candidate, leg, sequence, timestamp, time);
            }
        }
        if self.candidate.is_some() {
            self.strays += 1;
        }
        let mut arrivals = [None; 8];
        arrivals[leg] = Some(time);
        self.candidate = Some(Candidate { ssrc, sequence, timestamp, arrivals, age: 0 });
        Verdict::Held
    }

    /// The packet after a held one has come: an outage ended, a leg runs far behind, the
    /// sender paused, or it restarted.
    fn confirm(&mut self, candidate: Candidate, leg: usize, sequence: u32, timestamp: u32, time: i64) -> Verdict {
        let regime = self.regime.expect("a stream");
        if candidate.ssrc == regime.ssrc {
            let ahead = candidate.sequence.wrapping_sub(regime.highest) as i32;
            let ticks = candidate.timestamp.wrapping_sub(regime.timestamp) as i32;
            if self.keeps_pace(ahead, ticks, regime.ticks_per_packet) {
                if ahead > -(self.window as i32) {
                    self.replay(&candidate);
                    self.take(leg, sequence, timestamp, time);
                    return Verdict::Resumed;
                }
                for (l, arrival) in candidate.arrivals.iter().enumerate() {
                    if arrival.is_some() {
                        self.too_late(l, candidate.sequence);
                    }
                }
                return self.too_late(leg, sequence);
            }
            if self.paused(&candidate, &regime, ahead, ticks) {
                // The pace is measured afresh from here, not across the pause.
                self.regime.as_mut().expect("a stream").anchor = (candidate.sequence, candidate.timestamp);
                self.replay(&candidate);
                self.take(leg, sequence, timestamp, time);
                return Verdict::Resumed;
            }
        }
        self.lost += self.open_losses();
        self.retired = Some((regime.ssrc, regime.highest));
        self.restarts += 1;
        self.seen.fill(0);
        for l in &mut self.legs {
            l.highest = None;
        }
        self.start(candidate.ssrc, candidate.sequence, candidate.timestamp);
        self.replay(&candidate);
        self.take(leg, sequence, timestamp, time);
        Verdict::Restart
    }

    /// Whether a held packet that follows on from the stream's sequence numbers, with a
    /// timestamp further on than they account for, came no sooner after its timestamp
    /// than the stream's packets lately have: the sender stopped a while, and went on
    /// from where its clock had got to. A clock that stepped on brings them sooner.
    fn paused(&self, candidate: &Candidate, regime: &Regime, ahead: i32, ticks: i32) -> bool {
        let Some(&first) = candidate.arrivals.iter().flatten().min() else { return false };
        if !(1..=CONFIRM_WITHIN).contains(&ahead) || f64::from(ticks) <= f64::from(ahead) * regime.ticks_per_packet {
            return false;
        }
        let soonest = match self.soonest {
            [Some(a), Some(b)] if self.later(a, b) < 0.0 => a,
            [a, b] => match b.or(a) {
                Some(soonest) => soonest,
                None => return false,
            },
        };
        // Allowing for jitter, and for the legs being as far apart as they have been.
        let allowed = 2.0 * self.pace.slack + self.max_skew as f64 * self.pace.clock_rate / 1e9;
        self.later((candidate.timestamp, first), soonest) >= -allowed
    }

    /// How much later after its timestamp one packet came than another did, in ticks.
    fn later(&self, (timestamp, time): (u32, i64), (other_timestamp, other_time): (u32, i64)) -> f64 {
        time.saturating_sub(other_time) as f64 * self.pace.clock_rate / 1e9
            - f64::from(timestamp.wrapping_sub(other_timestamp) as i32)
    }

    /// Takes a confirmed packet's copies, in the order they came.
    fn replay(&mut self, candidate: &Candidate) {
        let mut copies: Vec<(i64, usize)> =
            candidate.arrivals.iter().enumerate().filter_map(|(leg, at)| at.map(|at| (at, leg))).collect();
        copies.sort_unstable();
        for (time, leg) in copies {
            self.take(leg, candidate.sequence, candidate.timestamp, time);
        }
    }
}

/// The tightest ST 2022-7:2019 receiver class (Table 1) whose limit on the packet time
/// differential covers `skew_ns`: D (150 µs), A (10 ms), B (50 ms), then C, which allows
/// 450 ms below 270 Mb/s and 150 ms from there up. `None` when none does.
pub fn receiver_class(skew_ns: i64, bits_per_second: f64) -> Option<char> {
    let c = if bits_per_second < 270e6 { 450_000_000 } else { 150_000_000 };
    [('D', 150_000), ('A', 10_000_000), ('B', 50_000_000), ('C', c)]
        .into_iter()
        .find(|&(_, limit)| skew_ns <= limit)
        .map(|(class, _)| class)
}

/// A packet the playout lets go, in sequence order.
#[derive(Clone, Copy, Debug)]
pub struct Released<'a> {
    /// Its 32-bit sequence number.
    pub sequence: u32,
    /// The datagram.
    pub data: &'a [u8],
    /// When it arrived, in nanoseconds.
    pub at: i128,
    /// Packets given up on just before it: missing from the stream.
    pub missing: u64,
}

/// What became of a packet the playout took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placed {
    /// Let go at once: the packets before it have gone.
    Released,
    /// Held for the packets before it.
    Held,
    /// Come after the playout gave up on it.
    TooLate,
    /// Older than the first packet let go, from a leg that ran behind as receiving
    /// started: left out.
    BeforeStart,
}

/// What the playout has counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PlayoutCounts {
    /// Packets let go, in sequence order.
    pub released: u64,
    /// Packets held for a missing one before them.
    pub held: u64,
    /// Packets given up on: still missing when the packets after them had waited as
    /// long as allowed, or when receiving stopped.
    pub skipped: u64,
    /// Packets that came after they had been given up on.
    pub too_late: u64,
    /// Packets older than the first one let go, left out.
    pub before_start: u64,
}

#[derive(Debug)]
struct HeldPacket {
    at: i128,
    data: Vec<u8>,
}

/// Puts the merged packets back in sequence order.
///
/// A packet that comes in order goes straight through. One that comes after a gap is
/// held, with those after it, until the missing packets come or it has waited `hold`
/// nanoseconds by the arrival times of later packets; then the playout gives up on the
/// gap and lets it go. Packets keep the times they arrived.
#[derive(Debug)]
pub struct Playout {
    hold: i128,
    capacity: u64,
    /// The next sequence number to let go, counted on past 32 bits, and the first.
    next: Option<u64>,
    start: u64,
    held: BTreeMap<u64, HeldPacket>,
    /// When each held packet came, in the order they came.
    order: VecDeque<(i128, u64)>,
    spare: Vec<Vec<u8>>,
    /// Packets given up on since the last one let go.
    missing: u64,
    counts: PlayoutCounts,
}

impl Playout {
    /// A playout that holds packets for up to `hold` nanoseconds, and up to `capacity`
    /// sequence numbers ahead of the next to go.
    pub fn new(hold: i64, capacity: u64) -> Self {
        Self {
            hold: i128::from(hold.max(0)),
            capacity: capacity.max(1),
            next: None,
            start: 0,
            held: BTreeMap::new(),
            order: VecDeque::new(),
            spare: Vec::new(),
            missing: 0,
            counts: PlayoutCounts::default(),
        }
    }

    /// What it has counted.
    pub fn counts(&self) -> PlayoutCounts {
        self.counts
    }

    /// Takes a packet with its 32-bit sequence number, which arrived at `at`, and calls
    /// `out` with each packet it lets go.
    pub fn push(&mut self, sequence: u32, at: i128, data: &[u8], mut out: impl FnMut(Released<'_>)) -> Placed {
        let next = *self.next.get_or_insert_with(|| {
            self.start = u64::from(sequence);
            u64::from(sequence)
        });
        let ahead = sequence.wrapping_sub(next as u32) as i32;
        if ahead < 0 {
            if next as i128 + i128::from(ahead) < i128::from(self.start) {
                self.counts.before_start += 1;
                return Placed::BeforeStart;
            }
            self.counts.too_late += 1;
            return Placed::TooLate;
        }
        let key = next + ahead as u64;
        let placed = if key == next {
            out(Released { sequence, data, at, missing: std::mem::take(&mut self.missing) });
            self.counts.released += 1;
            self.next = Some(next + 1);
            if self.held.is_empty() {
                return Placed::Released;
            }
            self.drain(&mut out);
            Placed::Released
        } else {
            if key - next > self.capacity {
                self.skip_to(key - self.capacity, &mut out);
            }
            if !self.held.contains_key(&key) {
                let mut buffer = self.spare.pop().unwrap_or_default();
                buffer.clear();
                buffer.extend_from_slice(data);
                self.held.insert(key, HeldPacket { at, data: buffer });
                self.order.push_back((at, key));
                self.counts.held += 1;
            }
            Placed::Held
        };
        self.expire(at, &mut out);
        placed
    }

    /// Lets every packet held go, giving up on the gaps between: call it when no more
    /// will come.
    pub fn finish(&mut self, mut out: impl FnMut(Released<'_>)) {
        if let Some((&last, _)) = self.held.last_key_value() {
            self.skip_to(last + 1, &mut out);
        }
        self.order.clear();
    }

    /// Forgets the stream, after [`Playout::finish`], for one that starts again.
    pub fn reset(&mut self) {
        self.next = None;
        self.missing = 0;
        self.held.clear();
        self.order.clear();
    }

    /// Lets go the held packets that follow on from the next to go.
    fn drain(&mut self, out: &mut impl FnMut(Released<'_>)) {
        let Some(mut next) = self.next else { return };
        while let Some(entry) = self.held.first_entry()
            && *entry.key() == next
        {
            let packet = entry.remove();
            out(Released {
                sequence: next as u32,
                data: &packet.data,
                at: packet.at,
                missing: std::mem::take(&mut self.missing),
            });
            self.counts.released += 1;
            self.spare.push(packet.data);
            next += 1;
        }
        self.next = Some(next);
    }

    /// Gives up on every packet before `target` that has not come, letting go those
    /// held on the way.
    fn skip_to(&mut self, target: u64, out: &mut impl FnMut(Released<'_>)) {
        let Some(mut next) = self.next else { return };
        while next < target {
            let to = match self.held.first_key_value() {
                Some((&key, _)) if key < target => key,
                _ => target,
            };
            self.missing += to - next;
            self.counts.skipped += to - next;
            next = to;
            self.next = Some(next);
            self.drain(out);
            next = self.next.expect("started");
        }
    }

    /// Gives up on the gaps before packets that have waited longer than the hold.
    fn expire(&mut self, now: i128, out: &mut impl FnMut(Released<'_>)) {
        loop {
            let Some(next) = self.next else { return };
            while self.order.front().is_some_and(|&(_, key)| key < next) {
                self.order.pop_front();
            }
            let Some(&(since, _)) = self.order.front() else { return };
            if now - since <= self.hold {
                return;
            }
            let Some((&first, _)) = self.held.first_key_value() else { return };
            self.skip_to(first, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1 ms audio at 48 kHz: 48 ticks a packet.
    const AUDIO: Pace = Pace { ticks_per_packet: 48.0, slack: 96.0, clock_rate: 48_000.0 };

    fn merger(legs: usize, window: u32) -> Merger {
        Merger::new(legs, window, AUDIO)
    }

    /// Pushes a packet of the audio stream with SSRC 1 whose sequence number is `seq`.
    fn push(m: &mut Merger, leg: usize, seq: u32, at: i128) -> Verdict {
        m.push(leg, 1, seq, seq.wrapping_mul(48), at)
    }

    #[test]
    fn extends_across_wraps_both_ways() {
        let mut e = Extender::default();
        for (seq, want) in [(65_534, 65_534), (1, 65_537), (65_535, 65_535), (2, 65_538)] {
            let extended = e.extend(seq);
            assert_eq!(extended, want);
            e.take(extended);
        }
        let mut back = Extender::default();
        back.take(back.extend(0));
        assert_eq!(back.extend(65_535), u32::MAX);
        // A stray far ahead, left out, leads nothing astray.
        assert_eq!(back.extend(32_000), 32_000);
        assert_eq!(back.extend(1), 1);
    }

    #[test]
    fn merges_two_legs_that_each_lose_packets() {
        let mut m = merger(2, 64);
        let mut passed = Vec::new();
        // Leg 2 runs 300 µs behind leg 1; leg 1 loses 10 to 12, leg 2 loses 11 and 20.
        for seq in 0u32..40 {
            let at = i128::from(seq) * 1000;
            if !(10..=12).contains(&seq) && push(&mut m, 0, seq, at) == Verdict::First {
                passed.push(seq);
            }
            if seq != 11 && seq != 20 && push(&mut m, 1, seq, at + 300_000) == Verdict::First {
                passed.push(seq);
            }
        }
        let expected: Vec<u32> = (0..40).filter(|&s| s != 11).collect();
        assert_eq!(passed, expected);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.too_late, c.restarts), (39, 1, 0, 0));
        assert_eq!(c.legs[0], LegCounts { received: 37, lost: 3, first: 37, ..LegCounts::default() });
        assert_eq!(c.legs[1], LegCounts { received: 38, lost: 2, first: 2, ..LegCounts::default() });
        let skew = c.skew.unwrap();
        assert_eq!((skew.pairs, skew.max_ns), (36, 300_000));
        assert!((skew.mean_ns - 300_000.0).abs() < 1e-6);
        assert_eq!(receiver_class(skew.max_ns, 2.6e9), Some('A'));
        assert_eq!(receiver_class(100_000, 2.6e9), Some('D'));
        assert_eq!(receiver_class(200_000_000, 2.6e9), None);
        assert_eq!(receiver_class(200_000_000, 3e6), Some('C'));
    }

    #[test]
    fn follows_one_leg_through_loss_reordering_and_duplicates() {
        let mut m = merger(1, 16);
        for seq in [u32::MAX - 1, u32::MAX, 2, 1, 1, 3] {
            push(&mut m, 0, seq, 0);
        }
        let c = m.counts();
        // 0 never came; 1 came late and twice.
        assert_eq!((c.passed, c.lost), (5, 1));
        assert_eq!(c.legs[0], LegCounts { received: 6, lost: 1, reordered: 1, duplicates: 1, first: 5, too_late: 0 });
        assert!(c.skew.is_none());
        // Past the window, the loss stays counted.
        for seq in 4..30 {
            push(&mut m, 0, seq, 0);
        }
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.too_late), (31, 1, 0));
    }

    #[test]
    fn an_outage_of_every_leg_counts_what_it_lost() {
        let mut m = merger(1, 16);
        for seq in 0..10 {
            assert_eq!(push(&mut m, 0, seq, 0), Verdict::First);
        }
        // 1000 packets later, with timestamps to match: held, then confirmed.
        assert_eq!(push(&mut m, 0, 1010, 0), Verdict::Held);
        assert_eq!(push(&mut m, 0, 1011, 0), Verdict::Resumed);
        assert_eq!(push(&mut m, 0, 1012, 0), Verdict::First);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.restarts, c.strays), (13, 1000, 0, 0));
        assert_eq!(c.legs[0].lost, 1000);
    }

    #[test]
    fn a_restart_starts_again_and_leaves_stragglers_out() {
        let mut m = merger(2, 16);
        for seq in 0..10 {
            push(&mut m, 0, seq, 0);
        }
        // A new source whose sequence numbers and timestamps start elsewhere.
        assert_eq!(m.push(0, 2, 40_000, 7, 0), Verdict::Held);
        assert_eq!(m.push(1, 2, 40_000, 7, 0), Verdict::Copy);
        assert_eq!(m.push(0, 2, 40_001, 55, 0), Verdict::Restart);
        assert_eq!(m.ssrc(), Some(2));
        // Leg 2, behind, still brings the old source's packets.
        assert_eq!(push(&mut m, 1, 10, 0), Verdict::Stale);
        assert_eq!(m.push(1, 2, 40_001, 55, 0), Verdict::Copy);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.restarts, c.stale, c.strays), (12, 0, 1, 1, 0));
        // The same source restarting elsewhere, with timestamps that do not keep pace.
        assert_eq!(m.push(0, 2, 7, 1_000_000, 0), Verdict::Held);
        assert_eq!(m.push(0, 2, 8, 1_000_048, 0), Verdict::Restart);
        assert_eq!(m.push(1, 2, 40_002, 103, 0), Verdict::Stale);
        assert_eq!(m.counts().restarts, 2);
    }

    #[test]
    fn a_pause_goes_on_and_a_clock_that_steps_on_restarts() {
        let mut m = merger(1, 16);
        // Each packet 1 ms after the one before, as its timestamp says.
        for seq in 0..10 {
            push(&mut m, 0, seq, i128::from(seq) * 1_000_000);
        }
        // The sender stops for a second, sends the packet it was sending, then goes on
        // from where its clock has got to, counting on its sequence numbers.
        assert_eq!(push(&mut m, 0, 10, 1_010_000_000), Verdict::First);
        assert_eq!(m.push(0, 1, 11, 1011 * 48, 1_011_000_000), Verdict::Held);
        assert_eq!(m.push(0, 1, 12, 1012 * 48, 1_012_000_000), Verdict::Resumed);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.restarts, c.strays), (13, 0, 0, 0));
        // Its clock steps on a second, with no pause.
        assert_eq!(m.push(0, 1, 13, 2013 * 48, 1_013_000_000), Verdict::Held);
        assert_eq!(m.push(0, 1, 14, 2014 * 48, 1_014_000_000), Verdict::Restart);
        assert_eq!(m.counts().restarts, 1);
    }

    #[test]
    fn a_stray_is_held_and_given_up() {
        let mut m = merger(1, 16);
        for seq in 0..10 {
            push(&mut m, 0, seq, 0);
        }
        assert_eq!(m.push(0, 1, 5_000_000, 12_345, 0), Verdict::Held);
        for seq in 10..100 {
            assert_eq!(push(&mut m, 0, seq, 0), Verdict::First);
        }
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.strays, c.restarts), (100, 0, 1, 0));
        // In the window, but hours away by its timestamp: held, and the packet whose
        // sequence number it took still passes.
        assert_eq!(m.push(0, 1, 102, 1 << 30, 0), Verdict::Held);
        for seq in 100..110 {
            assert_eq!(push(&mut m, 0, seq, 0), Verdict::First);
        }
        assert_eq!((m.counts().passed, m.counts().strays), (110, 2));
        // Another source's packet, never followed.
        assert_eq!(m.push(0, 9, 3, 3, 0), Verdict::Held);
        assert_eq!(m.counts().strays, 3);
    }

    #[test]
    fn a_leg_further_behind_than_the_window_is_too_late() {
        let mut m = merger(2, 16);
        // Leg 2 runs 100 packets behind leg 1.
        for seq in 0..300u32 {
            push(&mut m, 0, seq, i128::from(seq));
            if seq >= 100 {
                let verdict = push(&mut m, 1, seq - 100, i128::from(seq));
                assert_eq!(verdict, if seq == 100 { Verdict::Held } else { Verdict::TooLate }, "{seq}");
            }
        }
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.restarts, c.strays), (300, 0, 0, 0));
        assert_eq!((c.legs[1].received, c.legs[1].too_late, c.legs[1].lost), (200, 200, 0));
    }

    #[test]
    fn windows_suit_the_rate() {
        assert_eq!(Merger::new(1, Merger::window_for(1000.0, 50_000_000), AUDIO).window(), 512);
        assert_eq!(Merger::new(1, Merger::window_for(216_000.0, 50_000_000), AUDIO).window(), 131_072);
        assert_eq!(Merger::new(1, Merger::window_for(1000.0, 400_000_000), AUDIO).window(), 1024);
        assert_eq!(Merger::new(2, 100, AUDIO).window(), 128);
    }

    fn release_all(p: &mut Playout, packets: &[(u32, i128)]) -> Vec<(u32, u64, i128)> {
        let mut out = Vec::new();
        for &(seq, at) in packets {
            p.push(seq, at, &seq.to_be_bytes(), |r| {
                assert_eq!(r.data, r.sequence.to_be_bytes());
                out.push((r.sequence, r.missing, r.at));
            });
        }
        out
    }

    #[test]
    fn playout_waits_for_a_gap_to_fill() {
        let mut p = Playout::new(1000, 64);
        // 3 comes 500 ns late: in time.
        let out = release_all(&mut p, &[(1, 0), (2, 100), (4, 200), (5, 300), (3, 500), (6, 600)]);
        assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), [1, 2, 3, 4, 5, 6]);
        assert!(out.iter().all(|o| o.1 == 0));
        // Packets keep their own arrival times.
        assert_eq!(out[3], (4, 0, 200));
        assert_eq!(p.counts(), PlayoutCounts { released: 6, held: 2, ..PlayoutCounts::default() });
    }

    #[test]
    fn playout_gives_up_when_the_wait_runs_out() {
        let mut p = Playout::new(1000, 64);
        let out = release_all(&mut p, &[(1, 0), (3, 100), (4, 1000), (5, 1101), (2, 1200), (6, 1300)]);
        // 2 is given up on when 5 comes, more than 1000 ns after 3.
        assert_eq!(out, [(1, 0, 0), (3, 1, 100), (4, 0, 1000), (5, 0, 1101), (6, 0, 1300)]);
        let c = p.counts();
        assert_eq!((c.skipped, c.too_late, c.before_start), (1, 1, 0));
    }

    #[test]
    fn playout_makes_room_and_finishes() {
        let mut p = Playout::new(1_000_000, 4);
        // 11 is more than four ahead of 2: 2 to 6 are given up, 7 is let go.
        let out = release_all(&mut p, &[(0, 0), (1, 0), (7, 0), (11, 0)]);
        assert_eq!(out, [(0, 0, 0), (1, 0, 0), (7, 5, 0)]);
        let mut rest = Vec::new();
        p.finish(|r| rest.push((r.sequence, r.missing)));
        assert_eq!(rest, [(11, 3)]);
        // Older than the start: a leg that ran behind as receiving started.
        let mut late = Playout::new(0, 16);
        release_all(&mut late, &[(u32::MAX, 0), (u32::MAX - 3, 0), (0, 0)]);
        assert_eq!((late.counts().before_start, late.counts().released), (1, 2));
        late.reset();
        assert_eq!(release_all(&mut late, &[(500, 0)]), [(500, 0, 0)]);
    }
}
