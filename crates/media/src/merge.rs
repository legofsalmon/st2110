//! ST 2022-7 seamless protection: one stream made of the first copy of each packet to
//! arrive on any leg.
//!
//! The merger keeps a window of recent sequence numbers, with the legs each came on and
//! when the first copy arrived. A copy on another leg is dropped, and how much later it
//! came is the packet time differential of ST 2022-7:2019 §5 (PD = max |Pi − Pj|). A
//! packet older than the window is dropped as too late, and one no leg delivered by
//! the time the window passes it is lost from the merged stream.

/// Extends 16-bit RTP sequence numbers to 32 bits by counting wraps, for payloads that
/// carry no extended sequence number, such as ST 2110-30 audio.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extender {
    highest: Option<u32>,
}

impl Extender {
    /// The 32-bit sequence number of the next packet: the one nearest the highest so far.
    pub fn extend(&mut self, sequence: u16) -> u32 {
        let Some(highest) = self.highest else {
            self.highest = Some(u32::from(sequence));
            return u32::from(sequence);
        };
        let ahead = sequence.wrapping_sub(highest as u16) as i16;
        let extended = highest.wrapping_add_signed(i32::from(ahead));
        if ahead > 0 {
            self.highest = Some(extended);
        }
        extended
    }
}

/// What the merger made of a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The first copy to arrive: pass it on.
    First,
    /// A copy of one already passed on.
    Copy,
    /// Older than the window: too late to pass on.
    TooLate,
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
    /// Packets no leg delivered in time.
    pub lost: u64,
    /// Copies that came after the window had passed them.
    pub too_late: u64,
    /// Jumps in the sequence numbers bigger than the window, after which the merger
    /// started again: the sender restarted.
    pub jumps: u64,
    /// How far apart the legs were, when packets came on more than one.
    pub skew: Option<Skew>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Leg {
    counts: LegCounts,
    highest: Option<u32>,
    lowest: u32,
}

/// Merges the legs of an ST 2022-7 stream, or follows the sequence numbers of a stream
/// with one leg.
#[derive(Clone, Debug)]
pub struct Merger {
    window: u32,
    /// For each slot, a bit for each leg the packet came on.
    seen: Vec<u8>,
    first_leg: Vec<u8>,
    /// When the first copy came, in nanoseconds after `base`.
    arrival: Vec<i64>,
    base: Option<i128>,
    highest: Option<u32>,
    lowest: u32,
    legs: Vec<Leg>,
    passed: u64,
    lost: u64,
    too_late: u64,
    jumps: u64,
    pairs: u64,
    max_skew: i64,
    skew_sum: i128,
}

impl Merger {
    /// A merger for 1 to 8 legs that remembers `window` sequence numbers, rounded up to
    /// a power of two: [`Merger::window_for`] gives one to suit a packet rate.
    pub fn new(legs: usize, window: u32) -> Self {
        assert!((1..=8).contains(&legs), "1 to 8 legs");
        let window = window.clamp(16, 1 << 24).next_power_of_two();
        Self {
            window,
            seen: vec![0; window as usize],
            first_leg: vec![0; window as usize],
            arrival: vec![0; window as usize],
            base: None,
            highest: None,
            lowest: 0,
            legs: vec![Leg::default(); legs],
            passed: 0,
            lost: 0,
            too_late: 0,
            jumps: 0,
            pairs: 0,
            max_skew: 0,
            skew_sum: 0,
        }
    }

    /// A window of half a second of packets at this rate, enough for the 450 ms that
    /// ST 2022-7 class C receivers allow the legs to differ by.
    pub fn window_for(packets_per_second: f64) -> u32 {
        (packets_per_second / 2.0).ceil().clamp(256.0, f64::from(1 << 20)) as u32
    }

    /// The window, in sequence numbers.
    pub fn window(&self) -> u32 {
        self.window
    }

    /// Takes a packet with a 32-bit sequence number that arrived on leg `leg` at `at`
    /// nanoseconds, and says whether to pass it on.
    pub fn push(&mut self, leg: usize, sequence: u32, at: i128) -> Verdict {
        let base = *self.base.get_or_insert(at);
        let time = (at - base).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        let window = self.window as i32;
        if let Some(highest) = self.highest {
            let ahead = sequence.wrapping_sub(highest) as i32;
            if ahead > window || ahead <= -2 * window {
                self.lost += self.open_losses();
                self.seen.fill(0);
                self.highest = None;
                self.jumps += 1;
            } else if ahead <= -window {
                self.too_late += 1;
                let l = &mut self.legs[leg];
                l.counts.received += 1;
                l.counts.reordered += 1;
                return Verdict::TooLate;
            } else if ahead > 0 {
                for step in 1..=ahead as u32 {
                    let slot = self.slot(highest.wrapping_add(step));
                    let leaving = highest.wrapping_add(step).wrapping_sub(self.window);
                    if self.seen[slot] == 0 && leaving.wrapping_sub(self.lowest) as i32 >= 0 {
                        self.lost += 1;
                    }
                    self.seen[slot] = 0;
                }
                self.highest = Some(sequence);
            }
        }
        if self.highest.is_none() {
            self.highest = Some(sequence);
            self.lowest = sequence;
        }
        let slot = self.slot(sequence);
        let bit = 1u8 << leg;
        let mask = self.seen[slot];
        self.leg_arrived(leg, sequence, mask & bit != 0);
        if mask == 0 {
            if (sequence.wrapping_sub(self.lowest) as i32) < 0 {
                self.lowest = sequence;
            }
            self.seen[slot] = bit;
            self.first_leg[slot] = leg as u8;
            self.arrival[slot] = time;
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

    /// What it has counted, with the packets missing from the window so far as lost.
    pub fn counts(&self) -> MergeCounts {
        MergeCounts {
            legs: self.legs.iter().map(|l| l.counts).collect(),
            passed: self.passed,
            lost: self.lost + self.open_losses(),
            too_late: self.too_late,
            jumps: self.jumps,
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

    /// Sequence numbers in the window, from the lowest passed on to the highest, that no
    /// leg has delivered.
    fn open_losses(&self) -> u64 {
        let Some(highest) = self.highest else { return 0 };
        let span = highest.wrapping_sub(self.lowest).min(self.window - 1);
        (0..=span).filter(|&back| self.seen[self.slot(highest.wrapping_sub(back))] == 0).count() as u64
    }

    fn leg_arrived(&mut self, leg: usize, sequence: u32, duplicate: bool) {
        let window = self.window as i32;
        let l = &mut self.legs[leg];
        l.counts.received += 1;
        if duplicate {
            l.counts.duplicates += 1;
            return;
        }
        let Some(highest) = l.highest else {
            (l.highest, l.lowest) = (Some(sequence), sequence);
            return;
        };
        let ahead = sequence.wrapping_sub(highest) as i32;
        if ahead > window || ahead <= -2 * window {
            (l.highest, l.lowest) = (Some(sequence), sequence);
        } else if ahead > 0 {
            l.counts.lost += (ahead - 1) as u64;
            l.highest = Some(sequence);
        } else {
            l.counts.reordered += 1;
            if (sequence.wrapping_sub(l.lowest) as i32) < 0 {
                l.lowest = sequence;
            } else {
                l.counts.lost = l.counts.lost.saturating_sub(1);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extends_across_wraps_both_ways() {
        let mut e = Extender::default();
        assert_eq!(e.extend(65_534), 65_534);
        assert_eq!(e.extend(1), 65_537);
        assert_eq!(e.extend(65_535), 65_535);
        assert_eq!(e.extend(2), 65_538);
        let mut back = Extender::default();
        assert_eq!(back.extend(0), 0);
        assert_eq!(back.extend(65_535), u32::MAX);
        assert_eq!(back.extend(1), 1);
    }

    #[test]
    fn merges_two_legs_that_each_lose_packets() {
        let mut m = Merger::new(2, 64);
        let mut passed = Vec::new();
        // Leg 2 runs 300 µs behind leg 1; leg 1 loses 10 to 12, leg 2 loses 11 and 20.
        for seq in 0u32..40 {
            let at = i128::from(seq) * 1000;
            if !(10..=12).contains(&seq) && m.push(0, seq, at) == Verdict::First {
                passed.push(seq);
            }
            if seq != 11 && seq != 20 && m.push(1, seq, at + 300_000) == Verdict::First {
                passed.push(seq);
            }
        }
        let expected: Vec<u32> = (0..40).filter(|&s| s != 11).collect();
        assert_eq!(passed, expected);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.too_late, c.jumps), (39, 1, 0, 0));
        assert_eq!(c.legs[0], LegCounts { received: 37, lost: 3, reordered: 0, duplicates: 0, first: 37 });
        assert_eq!(c.legs[1], LegCounts { received: 38, lost: 2, reordered: 0, duplicates: 0, first: 2 });
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
        let mut m = Merger::new(1, 16);
        for seq in [u32::MAX - 1, u32::MAX, 2, 1, 1, 3] {
            m.push(0, seq, 0);
        }
        let c = m.counts();
        // 0 never came; 1 came late and twice.
        assert_eq!((c.passed, c.lost), (5, 1));
        assert_eq!(c.legs[0], LegCounts { received: 6, lost: 1, reordered: 1, duplicates: 1, first: 5 });
        assert!(c.skew.is_none());
        // Past the window, a straggler is too late and the loss stays counted.
        for seq in 4..30 {
            m.push(0, seq, 0);
        }
        assert_eq!(m.push(0, 0, 0), Verdict::TooLate);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.too_late), (31, 1, 1));
        // A restart far away starts again without counting the gap as lost.
        assert_eq!(m.push(0, 1_000_000, 0), Verdict::First);
        assert_eq!(m.push(0, 1_000_001, 0), Verdict::First);
        let c = m.counts();
        assert_eq!((c.passed, c.lost, c.jumps, c.legs[0].lost), (33, 1, 1, 1));
    }

    #[test]
    fn windows_suit_the_rate() {
        assert_eq!(Merger::new(1, Merger::window_for(1000.0)).window(), 512);
        assert_eq!(Merger::new(1, Merger::window_for(216_000.0)).window(), 131_072);
        assert_eq!(Merger::new(2, 100).window(), 128);
    }
}
