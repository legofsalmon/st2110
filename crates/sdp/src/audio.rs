//! ST 2110-30 PCM and ST 2110-31 AES3 audio: conformance levels and packet sizes.

/// The largest RTP payload under ST 2110-10's standard UDP size limit, in bytes:
/// 1460 octets less the 8-byte UDP header and the 12-byte RTP header.
pub const STANDARD_PAYLOAD_LIMIT: u32 = 1440;

/// The RTP payload limit in bytes for a signalled `MAXUDP`, or the standard limit without one.
pub fn payload_limit(maxudp: Option<u32>) -> u32 {
    maxudp.map_or(STANDARD_PAYLOAD_LIMIT, |octets| octets.saturating_sub(20))
}

/// Samples in one packet, rounded to whole samples.
pub fn samples_per_packet(sample_rate: u32, packet_time_ms: f64) -> u32 {
    (f64::from(sample_rate) * packet_time_ms / 1000.0).round() as u32
}

/// True for a packet time of 125 µs, written `0.125` or, as ST 2110-31 does, `0.12`.
pub fn is_125us(packet_time_ms: f64) -> bool {
    (packet_time_ms - 0.125).abs() <= 0.0051
}

/// The ST 2110-30:2025 sender conformance level (Table 2) of a PCM stream, or `None`
/// if the combination fits no level.
///
/// | Level | Rate | Packet time | Channels |
/// |---|---|---|---|
/// | A | 48 kHz | 1 ms | 1–8 |
/// | AX | 96 kHz | 1 ms | 1–4 |
/// | B | 48 kHz | 125 µs | 1–8 |
/// | BX | 96 kHz | 125 µs | 1–8 |
/// | C | 48 kHz | 125 µs | 9–64 |
/// | CX | 96 kHz | 125 µs | 9–32 |
pub fn pcm_level(sample_rate: u32, packet_time_ms: f64, channels: u16) -> Option<&'static str> {
    let one_ms = (packet_time_ms - 1.0).abs() < 1e-9;
    let short = is_125us(packet_time_ms);
    match (sample_rate, channels) {
        (48_000, 1..=8) if one_ms => Some("A"),
        (96_000, 1..=4) if one_ms => Some("AX"),
        (48_000, 1..=8) if short => Some("B"),
        (96_000, 1..=8) if short => Some("BX"),
        (48_000, 9..=64) if short => Some("C"),
        (96_000, 9..=32) if short => Some("CX"),
        _ => None,
    }
}

/// Samples per packet for the packet times of ST 2110-31 Table 1, which must be
/// written exactly as the table does; `None` for any other value.
pub fn aes3_samples(sample_rate: u32, ptime: &str) -> Option<u32> {
    match (sample_rate, ptime) {
        (48_000, "1") | (44_100, "1.09") => Some(48),
        (48_000, "0.12") | (44_100, "0.14") => Some(6),
        (48_000, "0.08") | (44_100, "0.09") => Some(4),
        (96_000, "1") => Some(96),
        (96_000, "0.12") => Some(12),
        (96_000, "0.08") => Some(8),
        _ => None,
    }
}

/// The ST 2110-31:2022 level (Table 3) of a 48 kHz AM824 stream; `None` for other
/// rates, whose X levels this crate does not model, or if it fits no level.
pub fn aes3_level(sample_rate: u32, ptime: &str, subframes: u16) -> Option<&'static str> {
    if sample_rate != 48_000 {
        return None;
    }
    match (ptime, subframes) {
        ("1", 1..=6) => Some("A"),
        ("0.12", 1..=8) => Some("B"),
        ("0.12", 9..=60) => Some("C"),
        ("0.08", 1..=80) => Some("D"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm_levels() {
        assert_eq!(pcm_level(48_000, 1.0, 8), Some("A"));
        assert_eq!(pcm_level(48_000, 0.125, 2), Some("B"));
        assert_eq!(pcm_level(48_000, 0.12, 64), Some("C"));
        assert_eq!(pcm_level(96_000, 1.0, 4), Some("AX"));
        assert_eq!(pcm_level(96_000, 0.125, 32), Some("CX"));
        assert_eq!(pcm_level(48_000, 1.0, 16), None);
        assert_eq!(pcm_level(48_000, 0.25, 2), None);
        assert_eq!(pcm_level(44_100, 1.0, 2), None);
    }

    #[test]
    fn packet_sizes() {
        assert_eq!(samples_per_packet(48_000, 1.0), 48);
        assert_eq!(samples_per_packet(48_000, 0.125), 6);
        assert_eq!(samples_per_packet(96_000, 0.125), 12);
        assert_eq!(payload_limit(None), 1440);
        assert_eq!(payload_limit(Some(8960)), 8940);
    }

    #[test]
    fn aes3_levels() {
        assert_eq!(aes3_level(48_000, "1", 6), Some("A"));
        assert_eq!(aes3_level(48_000, "0.12", 60), Some("C"));
        assert_eq!(aes3_level(48_000, "0.08", 80), Some("D"));
        assert_eq!(aes3_level(48_000, "1", 8), None);
        assert_eq!(aes3_samples(44_100, "1.09"), Some(48));
        assert_eq!(aes3_samples(48_000, "0.125"), None);
    }
}
