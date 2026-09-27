//! Measurements of ST 2110-30 PCM and ST 2110-31 AES3 audio: latency, the intervals
//! between packets, the timestamped delay factor of EBU Tech 3337, and the packet time
//! and channel count the SDP file declares.

use std::collections::BTreeMap;

use st2110_sdp::Rule;

use crate::report::{AudioReport, AudioWindow, Finding};
use crate::stats::{Accumulator, NANOS, Seconds, Tally};
use crate::video::unwrap;
use crate::{Timeline, plural, rules};

/// The window each timestamped delay factor is measured over.
const TS_DF_WINDOW: i128 = 200_000_000;

/// Distinct values a histogram keeps, at most.
const HISTOGRAM_LIMIT: usize = 64;

/// What the SDP file, or the packets, say of the stream.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AudioConfig {
    /// `L24`, `L16` or `AM824`.
    pub encoding: String,
    /// Octets per sample of one channel.
    pub octets: u32,
    pub sample_rate: u32,
    pub channels: Option<u16>,
    pub ptime_ms: Option<f64>,
}

#[derive(Default)]
struct Window {
    latency: Accumulator,
    interval: Accumulator,
    ts_df: Option<f64>,
}

/// The timestamped delay factor over one window: how far arrivals stray from the
/// timestamps' pace, D(i) = (R(i) − R(0)) − (S(i) − S(0)), from the least to the most.
#[derive(Clone, Copy, Debug)]
struct DelayFactor {
    index: i128,
    /// R(0) in nanoseconds and S(0) in ticks.
    origin: (i128, i128),
    min: f64,
    max: f64,
    packets: u32,
}

pub(crate) struct AudioEngine {
    config: AudioConfig,
    absolute: bool,
    /// Samples a packet holds, by the SDP file's packet time.
    expected_step: Option<u32>,
    /// The last packet: arrival, sequence number, timestamp and payload octets.
    last: Option<(i128, u32, u32, u32)>,
    /// The timestamp as a tick count, carried past each wrap.
    ticks: i128,
    steps: BTreeMap<u32, u64>,
    channel_counts: BTreeMap<u32, u64>,
    wrong_step: Tally,
    wrong_step_value: Option<u32>,
    wrong_size: Tally,
    wrong_size_value: Option<(u32, u32)>,
    future: Tally,
    latency: Accumulator,
    interval: Accumulator,
    delay_factor: Option<DelayFactor>,
    /// Each window's start and delay factor.
    delay_factors: Vec<(i128, f64)>,
    windows: Seconds<Window>,
}

impl AudioEngine {
    pub(crate) fn new(config: AudioConfig, absolute: bool) -> Self {
        let expected_step = config.ptime_ms.map(|ms| st2110_sdp::audio::samples_per_packet(config.sample_rate, ms));
        Self {
            config,
            absolute,
            expected_step,
            last: None,
            ticks: 0,
            steps: BTreeMap::new(),
            channel_counts: BTreeMap::new(),
            wrong_step: Tally::default(),
            wrong_step_value: None,
            wrong_size: Tally::default(),
            wrong_size_value: None,
            future: Tally::default(),
            latency: Accumulator::default(),
            interval: Accumulator::default(),
            delay_factor: None,
            delay_factors: Vec::new(),
            windows: Seconds::default(),
        }
    }

    /// Takes the next packet, in arrival order.
    pub(crate) fn push(&mut self, t: i128, seq: u32, timestamp: u32, payload: u32) {
        let rate = i128::from(self.config.sample_rate);
        // Close the delay factor's window first, so that it counts in its own second.
        let index = t.div_euclid(TS_DF_WINDOW);
        if self.delay_factor.is_some_and(|w| w.index != index) {
            self.close_window();
        }
        if let Some((last_t, last_seq, last_ts, last_payload)) = self.last {
            let interval = (t - last_t) as f64 / 1000.0;
            self.interval.add(interval);
            self.windows.at(t).interval.add(interval);
            self.ticks += i128::from(timestamp.wrapping_sub(last_ts) as i32);
            // A packet's samples are how far the next timestamp steps from its own.
            let step = timestamp.wrapping_sub(last_ts);
            if seq == last_seq.wrapping_add(1) && step > 0 && step < 1 << 20 {
                count(&mut self.steps, step);
                if self.expected_step.is_some_and(|expected| expected != step) {
                    self.wrong_step.hit(last_t);
                    self.wrong_step_value.get_or_insert(step);
                }
                let frame = self.config.octets * step;
                count(&mut self.channel_counts, if last_payload % frame == 0 { last_payload / frame } else { 0 });
                if let Some(channels) = self.config.channels
                    && u64::from(last_payload) != u64::from(channels) * u64::from(frame)
                {
                    self.wrong_size.hit(last_t);
                    self.wrong_size_value.get_or_insert((last_payload, step));
                }
            }
        } else {
            self.ticks = i128::from(timestamp);
        }
        self.last = Some((t, seq, timestamp, payload));
        if self.absolute {
            let sampled = unwrap(timestamp, t, rate) * NANOS / rate;
            let latency = (t - sampled) as f64 / 1000.0;
            self.latency.add(latency);
            self.windows.at(t).latency.add(latency);
            if latency < 0.0 {
                self.future.hit_min(t, latency);
            }
        }
        self.delay_factor(t, index, rate);
    }

    fn delay_factor(&mut self, t: i128, index: i128, rate: i128) {
        let window = self.delay_factor.get_or_insert(DelayFactor {
            index,
            origin: (t, self.ticks),
            min: 0.0,
            max: 0.0,
            packets: 0,
        });
        let (r0, s0) = window.origin;
        let d = ((t - r0) as f64 - (self.ticks - s0) as f64 * 1e9 / rate as f64) / 1000.0;
        window.min = window.min.min(d);
        window.max = window.max.max(d);
        window.packets += 1;
    }

    fn close_window(&mut self) {
        if let Some(w) = self.delay_factor.take()
            && w.packets > 1
        {
            let start = w.index * TS_DF_WINDOW;
            let value = w.max - w.min;
            self.delay_factors.push((start, value));
            let window = self.windows.at(start);
            window.ts_df = Some(window.ts_df.map_or(value, |v| v.max(value)));
        }
    }

    pub(crate) fn finish(mut self, flow: usize, timeline: &Timeline) -> (AudioReport, Vec<Finding>) {
        self.close_window();
        let rate = self.config.sample_rate;
        let step = mode(&self.steps).or(self.expected_step);
        let packet_time_us = step.map(|s| f64::from(s) * 1e6 / f64::from(rate));
        let channels =
            mode(&self.channel_counts).filter(|&c| c > 0).and_then(|c| u16::try_from(c).ok()).or(self.config.channels);
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
            if tally.count > 0 {
                findings.push(Finding::new(rule, message, Some(flow), None, timeline.at(tally.first), tally.count));
            }
        };
        if let (Some(expected), Some(ms), Some(seen)) =
            (self.expected_step, self.config.ptime_ms, self.wrong_step_value)
        {
            add(
                &rules::PACKET_TIME,
                &self.wrong_step,
                format!(
                    "{} held a number of samples other than the {expected} that ptime {ms} ms gives at {rate} Hz, the first {seen}",
                    plural(self.wrong_step.count, "packet")
                ),
            );
        }
        if let (Some(declared), Some((octets, samples))) = (self.config.channels, self.wrong_size_value) {
            let size = self.config.octets;
            add(
                &rules::AUDIO_CHANNELS,
                &self.wrong_size,
                format!(
                    "{} did not hold {declared} channels of {} {size}-octet samples each: the first held {octets} octets for {samples} samples, not {}",
                    plural(self.wrong_size.count, "packet"),
                    self.config.encoding,
                    u64::from(declared) * u64::from(size) * u64::from(samples)
                ),
            );
        }
        add(
            &rules::TIMESTAMP_FUTURE,
            &self.future,
            format!(
                "{} arrived before the time its RTP timestamp names, by up to {:.1} µs: the sender's clock, or the capture's, runs ahead of PTP time",
                plural(self.future.count, "packet"),
                -self.future.worst.unwrap_or_default()
            ),
        );
        let mut ts_df = Accumulator::default();
        let mut over = Tally::default();
        for &(start, value) in &self.delay_factors {
            ts_df.add(value);
            if packet_time_us.is_some_and(|limit| value > limit) {
                over.hit_max(start, value);
            }
        }
        if let Some(limit) = packet_time_us {
            add(
                &rules::TS_DF,
                &over,
                format!(
                    "TS-DF reached {:.1} µs, over the packet time of {limit:.1} µs, in {} of {} 200 ms windows",
                    over.worst.unwrap_or_default(),
                    over.count,
                    self.delay_factors.len()
                ),
            );
        }
        let windows = self
            .windows
            .finish()
            .into_iter()
            .map(|(second, w)| AudioWindow {
                second,
                latency: w.latency.stats(),
                interval: w.interval.stats(),
                ts_df: w.ts_df,
            })
            .collect();
        let report = AudioReport {
            encoding: self.config.encoding,
            sample_rate: rate,
            channels,
            samples_per_packet: step,
            packet_time_us,
            latency: self.latency.stats(),
            interval: self.interval.stats(),
            ts_df: ts_df.stats(),
            windows,
        };
        (report, findings)
    }
}

fn count(histogram: &mut BTreeMap<u32, u64>, value: u32) {
    if histogram.len() < HISTOGRAM_LIMIT || histogram.contains_key(&value) {
        *histogram.entry(value).or_default() += 1;
    }
}

/// The commonest value.
fn mode(histogram: &BTreeMap<u32, u64>) -> Option<u32> {
    histogram.iter().max_by_key(|&(value, n)| (n, std::cmp::Reverse(*value))).map(|(value, _)| *value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(channels: Option<u16>, ptime_ms: Option<f64>) -> AudioConfig {
        AudioConfig { encoding: "L24".into(), octets: 3, sample_rate: 48_000, channels, ptime_ms }
    }

    fn timeline() -> Timeline {
        Timeline { start: 0, shift: 0 }
    }

    #[test]
    fn measures_a_steady_stream() {
        let mut a = AudioEngine::new(config(Some(2), Some(1.0)), true);
        let base = 1_790_510_437 * NANOS;
        for i in 0..1000_i128 {
            let sampled = base + i * 1_000_000;
            let ts = (sampled * 48_000 / NANOS) as u32;
            // Arrives 1.2 ms after its first sample, give or take 50 µs.
            let jitter = if i % 2 == 0 { 50_000 } else { -50_000 };
            a.push(sampled + 1_200_000 + jitter, i as u32, ts, 288);
        }
        let (report, findings) = a.finish(1, &timeline());
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            (report.channels, report.samples_per_packet, report.packet_time_us),
            (Some(2), Some(48), Some(1000.0))
        );
        let latency = report.latency.unwrap();
        assert!((latency.min - 1150.0).abs() < 1e-6 && (latency.max - 1250.0).abs() < 1e-6);
        let ts_df = report.ts_df.unwrap();
        assert_eq!(ts_df.count, 5);
        assert!((ts_df.max - 100.0).abs() < 1e-6, "{ts_df:?}");
        // The last packet arrives just after the second ends.
        assert_eq!(report.windows.len(), 2);
        assert_eq!(report.windows[0].ts_df, Some(ts_df.max));
    }

    #[test]
    fn finds_what_differs_from_the_sdp_file() {
        // The SDP file says 2 channels at 1 ms; the packets hold 4 channels of 125 µs.
        let mut a = AudioEngine::new(config(Some(2), Some(1.0)), false);
        for i in 0..100_u32 {
            a.push(i128::from(i) * 125_000, i, i * 6, 72);
        }
        let (report, findings) = a.finish(3, &timeline());
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["packet-time", "audio-channels"]);
        assert_eq!(findings[0].count, 99);
        assert!(findings[1].message.contains("held 72 octets for 6 samples, not 36"), "{}", findings[1].message);
        assert_eq!((report.channels, report.samples_per_packet), (Some(4), Some(6)));
        assert_eq!(report.latency, None);
    }

    #[test]
    fn flags_a_bursty_stream() {
        // Packets of 1 ms that arrive in bursts of four every 4 ms, for 1.6 s.
        let mut a = AudioEngine::new(config(None, None), false);
        for i in 0..1600_u32 {
            let t = i128::from(i / 4) * 4_000_000 + i128::from(i % 4) * 10_000;
            a.push(t, i, i * 48, 288);
        }
        let (report, findings) = a.finish(1, &timeline());
        assert_eq!(findings.len(), 1);
        assert_eq!((findings[0].rule, findings[0].count), ("ts-df", 8));
        assert!(report.ts_df.unwrap().max > 2900.0);
    }
}
