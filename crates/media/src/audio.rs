//! ST 2110-30 audio: samples into RTP packets, and packets back into samples.
//!
//! Samples are signed integers at the format's depth, interleaved: every channel's
//! sample for one instant, then the next instant's.

use crate::format::AudioFormat;
use crate::rtp;

/// Cuts samples into ST 2110-30 packets, one packet time each.
#[derive(Clone, Debug)]
pub struct AudioPacketiser {
    format: AudioFormat,
    payload_type: u8,
    ssrc: u32,
    sequence: u16,
}

impl AudioPacketiser {
    /// A packetiser for one stream.
    pub fn new(format: &AudioFormat, payload_type: u8, ssrc: u32, first_sequence: u16) -> Result<Self, String> {
        format.check()?;
        Ok(Self { format: format.clone(), payload_type, ssrc, sequence: first_sequence })
    }

    /// The sequence number the next packet will carry.
    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Writes one packet into `out`: `samples` holds one packet time of interleaved
    /// samples, and `timestamp` is the RTP timestamp of the first.
    pub fn packet(&mut self, samples: &[i32], timestamp: u32, out: &mut Vec<u8>) {
        debug_assert_eq!(samples.len(), self.format.samples_per_packet as usize * usize::from(self.format.channels));
        out.clear();
        rtp::write_header(out, false, self.payload_type, self.sequence, timestamp, self.ssrc);
        if self.format.bits == 16 {
            for &s in samples {
                out.extend_from_slice(&(s as i16).to_be_bytes());
            }
        } else {
            for &s in samples {
                out.extend_from_slice(&s.to_be_bytes()[1..]);
            }
        }
        self.sequence = self.sequence.wrapping_add(1);
    }
}

/// What the audio depacketiser has counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AudioCounts {
    /// Packets whose samples were played out.
    pub packets: u64,
    /// Samples per channel that arrived.
    pub samples: u64,
    /// Samples per channel of the packets that never did, filled with silence: up to
    /// ten seconds a gap, as long as the run keeps within ten seconds of the time since
    /// the first packet came.
    pub missing: u64,
    /// Samples per channel that the RTP timestamps skip beyond the packets missing,
    /// filled with silence as those are: the sender paused or left them out, or its clock
    /// stepped on a little.
    pub unsent: u64,
    /// Times the RTP timestamps and sequence numbers disagreed: the timestamps stood
    /// still or stepped back, or moved on less than the packets missing between.
    pub jumps: u64,
    /// Packets holding more or fewer samples than the packet time gives, played out all
    /// the same.
    pub odd_sized: u64,
    /// Packets whose payload is not whole sampling instants, left out.
    pub malformed: u64,
}

/// The longest gap filled with silence, and the furthest the run may get ahead of the
/// time since the first packet came, in seconds.
const MOST_SILENCE: u64 = 10;

const NANOS: i128 = 1_000_000_000;

/// Puts ST 2110-30 packets back into a continuous run of samples.
///
/// Packets should come in sequence order, as a [`crate::merge::Playout`] lets them go,
/// with the number missing before each. Their time is filled with silence: as the RTP
/// timestamps say, when they agree with the packets missing, and otherwise as the
/// packet time says. Time the timestamps skip beyond the packets missing is filled too.
/// The run never gets more than ten seconds ahead of the time since the first packet
/// came, so timestamps that run away cannot fill hours of silence in seconds.
#[derive(Clone, Debug)]
pub struct AudioDepacketiser {
    format: AudioFormat,
    next: Option<u32>,
    counts: AudioCounts,
    peaks: Vec<u32>,
    samples: Vec<i32>,
    /// When the first packet came, in nanoseconds, and the samples per channel played
    /// since, silence and all.
    first: Option<i128>,
    played: u64,
}

impl AudioDepacketiser {
    /// A depacketiser for one format.
    pub fn new(format: &AudioFormat) -> Result<Self, String> {
        format.check()?;
        Ok(Self {
            format: format.clone(),
            next: None,
            counts: AudioCounts::default(),
            peaks: vec![0; usize::from(format.channels)],
            samples: Vec::new(),
            first: None,
            played: 0,
        })
    }

    /// What it has counted.
    pub fn counts(&self) -> AudioCounts {
        self.counts
    }

    /// The loudest sample on each channel so far, in dB below full scale; `None` for a
    /// channel that has been silent.
    pub fn peaks(&self) -> Vec<Option<f64>> {
        let full = f64::from(1u32 << (self.format.bits - 1));
        self.peaks.iter().map(|&p| (p > 0).then(|| 20.0 * (f64::from(p) / full).log10())).collect()
    }

    /// Forgets where the stream was, for one that starts again. The run goes on.
    pub fn reset(&mut self) {
        self.next = None;
    }

    /// Takes one RTP packet that arrived at `at` nanoseconds, with `missing` packets lost
    /// just before it, and calls `play` with the samples it adds to the run: silence for
    /// the time of those missing or left out, then its own.
    pub fn push(&mut self, at: i128, packet: &[u8], missing: u64, mut play: impl FnMut(&[i32])) {
        let first = *self.first.get_or_insert(at);
        let Some(header) = rtp::read_header(packet) else {
            self.counts.malformed += 1;
            return;
        };
        let payload = rtp::payload(packet, &header);
        let channels = usize::from(self.format.channels);
        let instant = channels * self.format.sample_bytes();
        if payload.is_empty() || !payload.len().is_multiple_of(instant) {
            self.counts.malformed += 1;
            return;
        }
        let count = (payload.len() / instant) as u32;
        let per_packet = self.format.samples_per_packet;
        if count != per_packet {
            self.counts.odd_sized += 1;
        }
        if let Some(next) = self.next {
            let ahead = i64::from(header.timestamp.wrapping_sub(next) as i32);
            let expected = missing.saturating_mul(u64::from(per_packet));
            let (lost, unsent) = match u64::try_from(ahead) {
                Ok(a) if a == expected => (expected, 0),
                // Packets of other sizes went missing.
                Ok(a) if missing > 0 && a > 0 && a < expected.saturating_mul(2) => (a, 0),
                // The sender left out the time the timestamps skip beyond the packets missing.
                Ok(a) if a > expected => (expected, a - expected),
                _ => {
                    self.counts.jumps += 1;
                    (expected, 0)
                }
            };
            self.counts.missing += lost;
            self.counts.unsent += unsent;
            // No more than keeps the run within ten seconds of the time since the first
            // packet came.
            let rate = u64::from(self.format.sample_rate);
            let since = u64::try_from((at - first).max(0) * i128::from(rate) / NANOS).unwrap_or(u64::MAX);
            let room = since.saturating_add(MOST_SILENCE * rate).saturating_sub(self.played);
            self.silence(lost.saturating_add(unsent).min(MOST_SILENCE * rate).min(room), &mut play);
        }
        self.samples.clear();
        if self.format.bits == 16 {
            self.samples.extend(payload.as_chunks::<2>().0.iter().map(|&b| i32::from(i16::from_be_bytes(b))));
        } else {
            // Into the top three octets, then back down with the sign.
            self.samples
                .extend(payload.as_chunks::<3>().0.iter().map(|&[a, b, c]| i32::from_be_bytes([a, b, c, 0]) >> 8));
        }
        for (i, s) in self.samples.iter().enumerate() {
            let peak = &mut self.peaks[i % channels];
            *peak = (*peak).max(s.unsigned_abs());
        }
        play(&self.samples);
        self.played += u64::from(count);
        self.counts.packets += 1;
        self.counts.samples += u64::from(count);
        self.next = Some(header.timestamp.wrapping_add(count));
    }

    /// Plays `instants` of silence.
    fn silence(&mut self, instants: u64, play: &mut impl FnMut(&[i32])) {
        let channels = usize::from(self.format.channels);
        self.played += instants;
        let mut left = instants;
        while left > 0 {
            let n = left.min(4096);
            self.samples.clear();
            self.samples.resize(n as usize * channels, 0);
            play(&self.samples);
            left -= n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(format: &AudioFormat, runs: usize, first_timestamp: u32) -> (Vec<i32>, Vec<Vec<u8>>) {
        let mut p = AudioPacketiser::new(format, 97, 1, 65_530).unwrap();
        let per = format.samples_per_packet as usize * usize::from(format.channels);
        let full = 1i64 << (format.bits - 1);
        let samples: Vec<i32> = (0..per * runs).map(|i| ((i as i64 * 7919 % (2 * full)) - full) as i32).collect();
        let packets = samples
            .chunks(per)
            .enumerate()
            .map(|(i, chunk)| {
                let mut out = Vec::new();
                p.packet(chunk, first_timestamp.wrapping_add(i as u32 * format.samples_per_packet), &mut out);
                out
            })
            .collect();
        (samples, packets)
    }

    #[test]
    fn samples_come_back_as_they_went() {
        let short = AudioFormat { bits: 16, ..AudioFormat::new(8).with_packet_time(0.125).unwrap() };
        for format in [AudioFormat::new(2), short] {
            let (samples, packets) = packets(&format, 10, u32::MAX - 100);
            assert_eq!(packets[0].len(), 12 + format.payload_bytes());
            // 24-bit samples go big-endian: the first is -2^23.
            if format.bits == 24 {
                assert_eq!(packets[0][12..15], [0x80, 0, 0]);
            }
            let h = st2110_pcap::rtp::header(&packets[9], true).unwrap();
            assert_eq!(h.sequence, 65_530u16.wrapping_add(9));
            let mut d = AudioDepacketiser::new(&format).unwrap();
            let mut out = Vec::new();
            for p in &packets {
                d.push(0, p, 0, |s| out.extend_from_slice(s));
            }
            assert_eq!(out, samples);
            assert_eq!(
                d.counts(),
                AudioCounts { packets: 10, samples: 10 * u64::from(format.samples_per_packet), ..Default::default() }
            );
            // Channel 1 has the first sample, at negative full scale.
            assert_eq!(d.peaks()[0], Some(0.0));
        }
    }

    #[test]
    fn missing_packets_are_filled_with_silence() {
        let format = AudioFormat::new(2);
        let (samples, packets) = packets(&format, 5, 1000);
        let mut d = AudioDepacketiser::new(&format).unwrap();
        let mut out = Vec::new();
        for (i, missing) in [(0, 0), (2, 1), (3, 0)] {
            d.push(i as i128 * 1_000_000, &packets[i], missing, |s| out.extend_from_slice(s));
        }
        let per = 96;
        assert_eq!(out.len(), 4 * per);
        assert_eq!(out[..per], samples[..per]);
        assert!(out[per..2 * per].iter().all(|&s| s == 0));
        assert_eq!(out[2 * per..], samples[2 * per..4 * per]);
        let c = d.counts();
        assert_eq!((c.packets, c.missing, c.jumps), (3, 48, 0));
        // Two seconds of packets lost: two seconds of silence.
        let mut later = packets[4].clone();
        later[4..8].copy_from_slice(&(1000u32 + 4 * 48 + 96_000).to_be_bytes());
        out.clear();
        d.push(2_004_000_000, &later, 2000, |s| out.extend_from_slice(s));
        assert_eq!(out.len(), 96_000 * 2 + 96);
        // A minute of them: ten seconds of silence, and the minute counted.
        later[4..8].copy_from_slice(&(1000u32 + 5 * 48 + 96_000 + 2_880_000).to_be_bytes());
        out.clear();
        d.push(62_005_000_000, &later, 60_000, |s| out.extend_from_slice(s));
        assert_eq!(out.len(), 480_000 * 2 + 96);
        assert_eq!((d.counts().missing, d.counts().jumps), (48 + 96_000 + 2_880_000, 0));
    }

    #[test]
    fn timestamps_that_run_away_fill_no_more_than_the_time_that_passed() {
        let format = AudioFormat::new(2);
        let (_, packets) = packets(&format, 1, 0);
        let mut d = AudioDepacketiser::new(&format).unwrap();
        let mut played = 0;
        // A packet a millisecond, each a second on from the one before by its timestamp.
        for i in 0..100u32 {
            let mut packet = packets[0].clone();
            packet[4..8].copy_from_slice(&(i * 48_000).to_be_bytes());
            d.push(i128::from(i) * 1_000_000, &packet, 0, |s| played += s.len() / 2);
        }
        // Ten seconds of the silence it asked for, and the time that passed.
        assert_eq!(played, 480_000 + 99 * 48 + 48);
        assert_eq!(d.counts().unsent, 99 * (48_000 - 48));
    }

    #[test]
    fn timestamps_that_jump_are_counted_and_time_left_out_is_filled() {
        let format = AudioFormat::new(2);
        let (_, packets) = packets(&format, 3, 1000);
        let mut d = AudioDepacketiser::new(&format).unwrap();
        // Pushes a packet with another timestamp, and gives how many samples it played.
        fn at(d: &mut AudioDepacketiser, packet: &[u8], timestamp: u32, missing: u64) -> usize {
            let mut packet = packet.to_vec();
            packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            let mut out = 0;
            d.push(0, &packet, missing, |s| out += s.len());
            out
        }
        d.push(0, &packets[0], 0, |_| {});
        // The clock steps back a second, and no packet was lost: nothing to fill.
        let back = 1048u32.wrapping_sub(48_000);
        assert_eq!(at(&mut d, &packets[1], back, 0), 96);
        // A packet lost, but the timestamps no further on than without it: its time filled.
        assert_eq!(at(&mut d, &packets[2], back.wrapping_add(48), 1), 96 + 96);
        let c = d.counts();
        assert_eq!((c.packets, c.missing, c.unsent, c.jumps), (3, 48, 0, 2));
        // The timestamps skip a packet time, and no packet is missing: the sender left it out.
        assert_eq!(at(&mut d, &packets[2], back.wrapping_add(3 * 48), 0), 96 + 96);
        // A packet lost, and the timestamps a second on as well: the sender paused.
        assert_eq!(at(&mut d, &packets[2], back.wrapping_add(4 * 48 + 48_000), 1), 2 * 48_000 + 96);
        let c = d.counts();
        assert_eq!((c.packets, c.missing, c.unsent, c.jumps), (5, 96, 48_000, 2));
        // After a restart, the first packet follows nothing.
        d.reset();
        d.push(0, &packets[0], 0, |s| assert_eq!(s.len(), 96));
        assert_eq!(d.counts().jumps, 2);
    }

    #[test]
    fn peaks_and_bad_payloads() {
        let format = AudioFormat::new(2);
        let mut p = AudioPacketiser::new(&format, 97, 1, 0).unwrap();
        let mut packet = Vec::new();
        // Channel 1 at half scale, channel 2 silent.
        let samples: Vec<i32> = (0..96).map(|i| if i % 2 == 0 { -(1 << 22) } else { 0 }).collect();
        p.packet(&samples, 0, &mut packet);
        let mut d = AudioDepacketiser::new(&format).unwrap();
        d.push(0, &packet, 0, |_| {});
        let peaks = d.peaks();
        assert!((peaks[0].unwrap() + 6.0206).abs() < 1e-3, "{peaks:?}");
        assert_eq!(peaks[1], None);
        d.push(0, &packet[..12 + 5], 0, |_| panic!("not whole instants"));
        d.push(0, &packet[..12], 0, |_| panic!("empty"));
        assert_eq!(d.counts().malformed, 2);
        // Half a packet time is odd, but played.
        let mut half = packet[..12 + 144].to_vec();
        half[4..8].copy_from_slice(&48u32.to_be_bytes());
        d.push(0, &half, 0, |s| assert_eq!(s.len(), 48));
        assert_eq!(d.counts().odd_sized, 1);
    }
}
