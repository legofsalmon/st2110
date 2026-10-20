//! ST 2022-7 pairs: the flows of an SDP file's `DUP` group measured together, as a
//! receiver that merges them would see them. For each second, and over the capture, the
//! packet time differential (PD = max |Pi − Pj|, ST 2022-7:2019 §7), the receiver class
//! of Table 1 that allows it, and the packets no leg delivered; and when each leg went
//! and came back, which Annex B suggests a receiver signal.

use std::collections::BTreeMap;

use crate::Timeline;
use crate::report::{Outage, PairReport, PairWindow};
use crate::stats::NANOS;

/// How long a copy may come after the first and still count, and a missing packet is
/// waited for before it is counted lost: a second, beyond class C's 450 ms.
const HOLD: i128 = NANOS;

/// A leg that brought nothing for this long while another leg did had gone: a copy
/// later than this is no use to a class B receiver, which allows 50 ms.
const OUTAGE: i128 = 50_000_000;

/// A jump in sequence numbers further than this starts the pair again, as a sender
/// that restarted does, rather than counting the packets between as lost.
const RESTART: i64 = 1 << 15;

/// One sequence number in the window: when it was first seen or missed, and on which
/// legs it came.
#[derive(Clone, Copy)]
struct Slot {
    first: i128,
    legs: u8,
}

/// One second of a pair.
#[derive(Default)]
struct Window {
    pd: Option<i128>,
    lost: u64,
    copies: u64,
}

/// One leg: its flow, when its last packet came, and its outages.
#[derive(Default)]
struct Leg {
    flow: Option<usize>,
    last: Option<i128>,
    outages: Vec<(i128, Option<i128>)>,
}

pub(crate) struct Pair {
    label: String,
    legs: Vec<Leg>,
    /// Whether sequence numbers are 32 bits, extended in the payload header.
    wide: bool,
    highest: Option<i64>,
    slots: BTreeMap<i64, Slot>,
    /// When the first packet came on any leg, and the last.
    first: Option<i128>,
    last: i128,
    packets: u64,
    copies: u64,
    lost: u64,
    restarts: u64,
    pd: Option<i128>,
    bits: u64,
    windows: BTreeMap<i64, Window>,
}

impl Pair {
    /// A pair of `legs` legs, named `label`, whose sequence numbers are `wide`.
    pub(crate) fn new(label: String, legs: usize, wide: bool) -> Self {
        Self {
            label,
            legs: (0..legs.min(8)).map(|_| Leg::default()).collect(),
            wide,
            highest: None,
            slots: BTreeMap::new(),
            first: None,
            last: 0,
            packets: 0,
            copies: 0,
            lost: 0,
            restarts: 0,
            pd: None,
            bits: 0,
            windows: BTreeMap::new(),
        }
    }

    /// Whether its sequence numbers are 32 bits.
    pub(crate) fn wide(&self) -> bool {
        self.wide
    }

    /// Notes the flow that carries leg `leg`.
    pub(crate) fn set_flow(&mut self, leg: usize, flow: usize) {
        if let Some(l) = self.legs.get_mut(leg) {
            l.flow.get_or_insert(flow);
        }
    }

    /// Takes a packet of `octets` that came on leg `leg` at `t`, with its sequence
    /// number: 32 bits for a wide pair, else 16.
    pub(crate) fn push(&mut self, leg: usize, t: i128, sequence: u32, octets: u32) {
        if leg >= self.legs.len() {
            return;
        }
        self.first.get_or_insert(t);
        self.last = self.last.max(t);
        self.expire(t);
        self.leg_arrived(leg, t);
        let modulus: i64 = if self.wide { 1 << 32 } else { 1 << 16 };
        let n = match self.highest {
            None => i64::from(sequence),
            Some(highest) => {
                let mut delta = (i64::from(sequence) - highest).rem_euclid(modulus);
                if delta >= modulus / 2 {
                    delta -= modulus;
                }
                highest + delta
            }
        };
        let highest = self.highest.unwrap_or(n);
        if (n - highest).abs() > RESTART {
            self.settle();
            self.restarts += 1;
            self.highest = Some(n);
        } else if n > highest {
            // Those skipped are missing until a copy on another leg comes.
            for missing in highest + 1..n {
                self.slots.insert(missing, Slot { first: t, legs: 0 });
            }
            self.highest = Some(n);
        } else if n < highest && !self.slots.contains_key(&n) {
            // Older than the window: too late to merge.
            return;
        }
        self.highest = self.highest.max(Some(n));
        let bit = 1u8 << leg;
        let slot = self.slots.entry(n).or_insert(Slot { first: t, legs: 0 });
        if slot.legs & bit != 0 {
            return;
        }
        if slot.legs == 0 {
            slot.first = t;
            slot.legs = bit;
            self.packets += 1;
            self.bits += u64::from(octets) * 8;
            return;
        }
        slot.legs |= bit;
        let later = t - slot.first;
        self.copies += 1;
        self.pd = self.pd.max(Some(later));
        let window = self.windows.entry(slot.first.div_euclid(NANOS) as i64).or_default();
        window.pd = window.pd.max(Some(later));
        window.copies += 1;
    }

    /// Notes a packet on `leg` at `t`, and the outage it ends if it had gone.
    fn leg_arrived(&mut self, leg: usize, t: i128) {
        let others = self.legs.iter().enumerate().filter(|&(i, _)| i != leg).filter_map(|(_, l)| l.last).max();
        let l = &mut self.legs[leg];
        match l.last {
            // Silent for longer than OUTAGE while another leg brought packets.
            Some(last) if t - last > OUTAGE && others.is_some_and(|o| o > last) => l.outages.push((last, Some(t))),
            // Nothing yet, while another leg has brought packets for longer.
            None if self.first.is_some_and(|first| t - first > OUTAGE) => {
                l.outages.push((self.first.unwrap_or(t), Some(t)));
            }
            _ => {}
        }
        l.last = Some(t);
    }

    /// Counts the sequence numbers that have waited longer than [`HOLD`] at `now`, and
    /// came on no leg, as lost.
    fn expire(&mut self, now: i128) {
        while let Some((&n, slot)) = self.slots.first_key_value() {
            if slot.first >= now - HOLD {
                break;
            }
            if slot.legs == 0 {
                self.lost_one(slot.first);
            }
            self.slots.remove(&n);
        }
    }

    fn lost_one(&mut self, t: i128) {
        self.lost += 1;
        self.windows.entry(t.div_euclid(NANOS) as i64).or_default().lost += 1;
    }

    /// Counts what is still missing as lost, and empties the window.
    fn settle(&mut self) {
        let missing: Vec<i128> = self.slots.values().filter(|s| s.legs == 0).map(|s| s.first).collect();
        for t in missing {
            self.lost_one(t);
        }
        self.slots.clear();
    }

    pub(crate) fn finish(mut self, timeline: &Timeline) -> PairReport {
        // A copy of a packet missed just before the end might have come after the
        // capture stopped.
        let end = self.last;
        self.slots.retain(|_, s| s.legs != 0 || s.first < end - OUTAGE);
        self.settle();
        let start = self.first;
        let at = |t: i128| timeline.at(Some(t)).unwrap_or_default();
        let mut outages = Vec::new();
        for (i, leg) in self.legs.iter_mut().enumerate() {
            match leg.last {
                Some(last) if end - last > OUTAGE => leg.outages.push((last, None)),
                None => leg.outages.extend(start.map(|first| (first, None))),
                _ => {}
            }
            for &(from, to) in &leg.outages {
                outages.push(Outage { leg: i + 1, from: at(from), to: to.map(at) });
            }
        }
        outages.sort_by(|a, b| a.from.total_cmp(&b.from));
        let seconds = start.map_or(0.0, |first| (end - first) as f64 / 1e9);
        let bits_per_second = if seconds > 0.0 { self.bits as f64 / seconds } else { 0.0 };
        let us = |nanos: i128| nanos as f64 / 1e3;
        PairReport {
            group: self.label,
            flows: self.legs.iter().map(|l| l.flow).collect(),
            packets: self.packets,
            copies: self.copies,
            pd_us: self.pd.map(us),
            class: self.pd.and_then(|pd| receiver_class(pd, bits_per_second)).map(String::from),
            lost: self.lost,
            restarts: self.restarts,
            seconds: self
                .windows
                .into_iter()
                .map(|(second, w)| PairWindow {
                    second,
                    copies: w.copies,
                    pd_us: w.pd.map(us),
                    class: w.pd.and_then(|pd| receiver_class(pd, bits_per_second)).map(String::from),
                    lost: w.lost,
                })
                .collect(),
            outages,
        }
    }
}

/// The tightest ST 2022-7:2019 receiver class (Table 1) whose limit on PD covers
/// `pd_ns`: D (150 µs), A (10 ms), B (50 ms), then C, which allows 450 ms below
/// 270 Mb/s and 150 ms from there up.
fn receiver_class(pd_ns: i128, bits_per_second: f64) -> Option<&'static str> {
    let c = if bits_per_second < 270e6 { 450_000_000 } else { 150_000_000 };
    [("D", 150_000), ("A", 10_000_000), ("B", 50_000_000), ("C", c)]
        .into_iter()
        .find(|&(_, limit)| pd_ns <= limit)
        .map(|(class, _)| class)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i128 = 1_000_000;

    fn timeline() -> Timeline {
        Timeline { start: 0, shift: 0 }
    }

    #[test]
    fn measures_the_differential_and_merged_loss() {
        let mut pair = Pair::new("a.sdp streams 0 and 1".into(), 2, false);
        // A packet a millisecond; leg 2 runs 2 ms behind, leg 1 loses 10 and 20, leg 2
        // loses 20 too, and from 100 to 199 leg 2 is gone.
        for n in 0..300_u32 {
            let t = i128::from(n) * MS;
            if n != 10 && n != 20 {
                pair.push(0, t, n, 1000);
            }
            if n != 20 && !(100..200).contains(&n) {
                pair.push(1, t + 2 * MS, n, 1000);
            }
        }
        let report = pair.finish(&timeline());
        assert_eq!((report.packets, report.copies, report.lost), (299, 198, 1));
        assert_eq!(report.pd_us, Some(2000.0));
        assert_eq!(report.class.as_deref(), Some("A"));
        assert_eq!(report.seconds.len(), 1);
        assert_eq!(report.outages.len(), 1);
        let outage = &report.outages[0];
        assert_eq!(outage.leg, 2);
        assert!((outage.from - 0.101).abs() < 1e-9 && (outage.to.unwrap() - 0.202).abs() < 1e-9, "{outage:?}");
    }

    #[test]
    fn a_leg_that_never_came_or_stopped() {
        let mut pair = Pair::new("b".into(), 2, true);
        for n in 0..100_u32 {
            pair.push(0, i128::from(n) * MS, n, 100);
        }
        let report = pair.finish(&timeline());
        assert_eq!(report.outages.len(), 1);
        assert_eq!((report.outages[0].leg, report.outages[0].from, report.outages[0].to), (2, 0.0, None));
        assert_eq!(report.pd_us, None);
        assert_eq!(report.class, None);
        // Wide sequence numbers wrap past 16 bits without a restart.
        let mut pair = Pair::new("c".into(), 2, true);
        for n in 65_530..65_540_u32 {
            pair.push(0, i128::from(n) * MS, n, 100);
            pair.push(1, i128::from(n) * MS + 10_000, n, 100);
        }
        let report = pair.finish(&timeline());
        assert_eq!((report.restarts, report.lost, report.class.as_deref()), (0, 0, Some("D")));
    }
}
