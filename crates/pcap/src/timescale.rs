//! Which clock a capture's timestamps count: PTP time, UTC, or neither.
//!
//! PTP evidence comes first: the arrival of each Sync less the time it left the
//! grandmaster, from domains on the PTP timescale. Without it, each RTP flow votes by
//! how far its timestamps sit from the arrival times.

use std::collections::{HashMap, VecDeque};

use st2110_ptp::{Body, Flags, Message, PortIdentity};

use crate::flow::Key;
use crate::report::Clock;
use crate::stats::NANOS;
use crate::{Options, Timescale, duration};

/// RTP clock rates that a flow without an SDP file is taken to have, when its
/// timestamps advance at one of them within 2%.
pub(crate) const STANDARD_CLOCKS: [u32; 4] = [90_000, 48_000, 96_000, 44_100];

/// What was decided about the capture's clock.
#[derive(Clone, Debug)]
pub(crate) struct Decision {
    pub clock: Clock,
    /// Nanoseconds added to capture times to give PTP time.
    pub shift: i128,
    pub basis: String,
    pub note: Option<String>,
}

impl Decision {
    /// Whether analysis times are PTP time.
    pub(crate) fn absolute(&self) -> bool {
        self.clock != Clock::Unknown
    }

    /// The decision that options force, if they do.
    pub(crate) fn forced(options: &Options) -> Option<Self> {
        let clock = match options.timescale {
            Timescale::Auto => return None,
            Timescale::Ptp => Clock::Ptp,
            Timescale::Utc => Clock::Utc,
        };
        Some(Self {
            clock,
            shift: shift(clock, options.tai_utc),
            basis: "chosen, not worked out from the capture".into(),
            note: None,
        })
    }
}

fn shift(clock: Clock, tai_utc: i32) -> i128 {
    if clock == Clock::Utc { i128::from(tai_utc) * NANOS } else { 0 }
}

/// Pairs Sync messages with their Follow_Up, where they are two-step, to give when each
/// Sync left the grandmaster.
#[derive(Debug, Default)]
pub(crate) struct SyncTimes {
    pending: HashMap<(u8, PortIdentity, u16), (i128, i128)>,
    order: VecDeque<(i128, (u8, PortIdentity, u16))>,
}

impl SyncTimes {
    /// Takes a message that arrived at `t` and, when it completes a Sync, returns the
    /// Sync's domain, its arrival, and the PTP time it left the grandmaster, corrections
    /// included, in nanoseconds.
    pub(crate) fn push(&mut self, t: i128, message: &Message) -> Option<(u8, i128, i128)> {
        let h = &message.header;
        let key = (h.domain, h.source, h.sequence_id);
        let correction = i128::from(h.correction) >> 16;
        match &message.body {
            Body::Sync { origin } if !h.flags.has(Flags::TWO_STEP) => {
                Some((h.domain, t, origin.time()?.nanos() + correction))
            }
            Body::Sync { .. } => {
                // Forget Syncs whose Follow_Up is a second late.
                while self.order.front().is_some_and(|(at, _)| *at < t - NANOS) {
                    let (_, stale) = self.order.pop_front().expect("just checked");
                    self.pending.remove(&stale);
                }
                self.pending.insert(key, (t, correction));
                self.order.push_back((t, key));
                None
            }
            Body::FollowUp { precise_origin } => {
                let (arrival, sync_correction) = self.pending.remove(&key)?;
                Some((h.domain, arrival, precise_origin.time()?.nanos() + sync_correction + correction))
            }
            _ => None,
        }
    }
}

/// How far one flow's timestamps sit from the arrival times.
#[derive(Debug, Default)]
struct FlowEvidence {
    /// A clock rate from the SDP file.
    rate: Option<u32>,
    /// Arrival and timestamp of the first packet of each timestamp.
    starts: Vec<(i128, u32)>,
}

/// Gathers the evidence, then decides.
#[derive(Debug)]
pub(crate) struct Detector {
    tai_utc: i32,
    syncs: SyncTimes,
    /// Per domain: whether an Announce said ptpTimescale, and whether one said not.
    timescale: HashMap<u8, (bool, bool)>,
    /// Capture time less PTP time, in nanoseconds, from each Sync.
    offsets: Vec<(u8, i128)>,
    flows: HashMap<Key, FlowEvidence>,
    order: Vec<Key>,
}

/// Timestamps kept per flow, at most.
const STARTS: usize = 4096;

impl Detector {
    pub(crate) fn new(tai_utc: i32) -> Self {
        Self {
            tai_utc,
            syncs: SyncTimes::default(),
            timescale: HashMap::new(),
            offsets: Vec::new(),
            flows: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub(crate) fn ptp(&mut self, t: i128, message: &Message) {
        if let Body::Announce(_) = message.body {
            let seen = self.timescale.entry(message.header.domain).or_default();
            if message.header.flags.has(Flags::PTP_TIMESCALE) {
                seen.0 = true;
            } else {
                seen.1 = true;
            }
        }
        if let Some((domain, arrival, left)) = self.syncs.push(t, message) {
            self.offsets.push((domain, arrival - left));
        }
    }

    pub(crate) fn rtp(&mut self, t: i128, key: Key, timestamp: u32, rate: Option<u32>) {
        let flow = self.flows.entry(key).or_insert_with(|| {
            self.order.push(key);
            FlowEvidence { rate, starts: Vec::new() }
        });
        if flow.starts.len() < STARTS && flow.starts.last().is_none_or(|(_, ts)| *ts != timestamp) {
            flow.starts.push((t, timestamp));
        }
    }

    pub(crate) fn decide(self) -> Decision {
        let tai_utc = i128::from(self.tai_utc) * NANOS;
        // Domains an Announce put on an arbitrary timescale, and none on PTP's.
        let arbitrary = |domain: &u8| self.timescale.get(domain).is_some_and(|&(ptp, arb)| arb && !ptp);
        let mut offsets: Vec<i128> =
            self.offsets.iter().filter(|(domain, _)| !arbitrary(domain)).map(|&(_, d)| d).collect();
        if !offsets.is_empty() {
            offsets.sort_unstable();
            let d = offsets[offsets.len() / 2];
            // What the capture shows: when the Syncs arrived, by its clock, against when
            // they left the grandmaster.
            let arrived = format!(
                "by the capture's clock, {} arrived a median {} {} leaving the grandmaster",
                crate::plural(offsets.len() as u64, "Sync message"),
                duration(d.abs()),
                if d < 0 { "before" } else { "after" }
            );
            let (clock, residual) = if d.abs() < NANOS {
                (Clock::Ptp, d)
            } else if (d + tai_utc).abs() < NANOS {
                (Clock::Utc, d + tai_utc)
            } else {
                return Decision {
                    clock: Clock::Unknown,
                    shift: 0,
                    basis: format!("{arrived}, which fits neither PTP time nor UTC"),
                    note: Some(SKIPPED.into()),
                };
            };
            let side = if residual > 0 { "ahead of" } else { "behind" };
            let basis = match clock {
                Clock::Utc => format!("{arrived}: it counts UTC, {} s behind PTP time", self.tai_utc),
                _ => arrived,
            };
            let note = (residual.abs() > 1_000_000).then(|| {
                format!(
                    "the capture's clock is {} {side} PTP time, so latency, first packet times and the virtual receiver buffer carry that error",
                    duration(residual.abs())
                )
            });
            return Decision { clock, shift: shift(clock, self.tai_utc), basis, note };
        }
        let (mut ptp, mut utc, mut voters) = (0, 0, 0);
        for key in &self.order {
            let flow = &self.flows[key];
            let Some(rate) = flow.rate.or_else(|| estimate_rate(&flow.starts)) else { continue };
            let Some(o) = offset(&flow.starts, rate) else { continue };
            voters += 1;
            if o.abs() < NANOS / 2 {
                ptp += 1;
            } else if (o - tai_utc).abs() < NANOS / 2 {
                utc += 1;
            }
        }
        let clock = match ptp.cmp(&utc) {
            std::cmp::Ordering::Greater => Clock::Ptp,
            std::cmp::Ordering::Less => Clock::Utc,
            std::cmp::Ordering::Equal => Clock::Unknown,
        };
        let basis = match clock {
            _ if voters == 0 => {
                "the capture has no PTP Sync messages, and no RTP flow whose clock rate is known".into()
            }
            Clock::Ptp => format!(
                "with no PTP Sync messages to go by, the timestamps of {ptp} of {} sit within half a second of PTP time",
                crate::plural(voters, "RTP flow")
            ),
            Clock::Utc => format!(
                "with no PTP Sync messages to go by, the timestamps of {utc} of {} sit {} s ahead of the capture's clock: it counts UTC",
                crate::plural(voters, "RTP flow"),
                self.tai_utc
            ),
            Clock::Unknown => format!(
                "the capture has no PTP Sync messages, and of {}, {ptp} have timestamps near PTP time and {utc} near UTC",
                crate::plural(voters, "RTP flow")
            ),
        };
        let note = (clock == Clock::Unknown).then(|| SKIPPED.into());
        Decision { clock, shift: shift(clock, self.tai_utc), basis, note }
    }
}

const SKIPPED: &str = "the measurements that need PTP time are skipped: first packet time, RTP offset, latency and the virtual receiver buffer";

/// The clock rate of timestamps that step as `starts` do, when it is one of
/// [`STANDARD_CLOCKS`] within 2%.
pub(crate) fn estimate_rate(starts: &[(i128, u32)]) -> Option<u32> {
    let (&(t0, ts0), &(t1, ts1)) = (starts.first()?, starts.last()?);
    let elapsed = t1 - t0;
    if starts.len() < 3 || elapsed < 20_000_000 {
        return None;
    }
    let ticks = i128::from(ts1.wrapping_sub(ts0));
    let rate = ticks * NANOS / elapsed;
    STANDARD_CLOCKS.into_iter().find(|&clock| (rate - i128::from(clock)).abs() * 50 <= i128::from(clock))
}

/// How far, in nanoseconds, timestamps run ahead of the arrival times: the median over
/// `starts` of the timestamp less the arrival time's tick count.
fn offset(starts: &[(i128, u32)], rate: u32) -> Option<i128> {
    let rate = i128::from(rate);
    let mut ahead: Vec<i128> = starts
        .iter()
        .map(|&(t, ts)| {
            let now = (t * rate).div_euclid(NANOS);
            i128::from(ts.wrapping_sub(now as u32) as i32) * NANOS / rate
        })
        .collect();
    if ahead.is_empty() {
        return None;
    }
    ahead.sort_unstable();
    Some(ahead[ahead.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_clock_rates() {
        // 50 frames a second at 90 kHz, one entry per frame.
        let frames: Vec<(i128, u32)> = (0..10).map(|i| (i * 20_000_000 + 7, 1_000 + 1_800 * i as u32)).collect();
        assert_eq!(estimate_rate(&frames), Some(90_000));
        // 1 ms packets at 48 kHz, wrapping.
        let audio: Vec<(i128, u32)> =
            (0..30).map(|i| (i * 1_000_000, (u32::MAX - 500).wrapping_add(48 * i as u32))).collect();
        assert_eq!(estimate_rate(&audio), Some(48_000));
        // Too short, and a rate that is none of the standard ones.
        assert_eq!(estimate_rate(&frames[..2]), None);
        let odd: Vec<(i128, u32)> = (0..10).map(|i| (i * 20_000_000, 1_000 * i as u32)).collect();
        assert_eq!(estimate_rate(&odd), None);
    }

    #[test]
    fn votes_by_rtp_timestamps() {
        let base: i128 = 1_790_510_437 * NANOS;
        let flow = |shift: i128| -> Vec<(i128, u32)> {
            (0..10)
                .map(|i| {
                    let t = base + i * 20_000_000 + 50_000;
                    (t - shift, ((base + i * 20_000_000) * 90_000 / NANOS) as u32)
                })
                .collect()
        };
        let decide = |flows: &[Vec<(i128, u32)>]| {
            let mut d = Detector::new(37);
            for (n, starts) in flows.iter().enumerate() {
                let key = (format!("10.0.0.{n}:5000").parse().unwrap(), "239.0.0.1:5000".parse().unwrap());
                for &(t, ts) in starts {
                    d.rtp(t, key, ts, None);
                }
            }
            d.decide()
        };
        let d = decide(&[flow(0), flow(0), flow(37 * NANOS)]);
        assert_eq!((d.clock, d.shift), (Clock::Ptp, 0));
        let d = decide(&[flow(37 * NANOS), flow(37 * NANOS)]);
        assert_eq!((d.clock, d.shift), (Clock::Utc, 37 * NANOS));
        assert_eq!(decide(&[flow(0), flow(37 * NANOS)]).clock, Clock::Unknown);
        assert_eq!(decide(&[flow(5 * NANOS)]).clock, Clock::Unknown);
        assert_eq!(decide(&[]).clock, Clock::Unknown);
    }
}
