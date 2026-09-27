//! SMPTE ST 2059-1 arithmetic: alignment points, frame counts and RTP timestamps.
//!
//! Every signal locked to PTP repeats with a fixed period that started at the SMPTE
//! Epoch, so its phase at any PTP time follows from the time alone. The functions
//! here work in exact integer arithmetic: PTP times near 1.79 × 10¹⁸ ns do not fit in
//! a double, and the periods of 1000/1001 rates fall on fractions of a nanosecond.
//!
//! They return `None` only when a result would not fit, which takes a rate with a
//! numerator or denominator far beyond any frame, sample or clock rate.

use st2110_sdp::Rational;

use crate::time::{NANOS, PtpTime};

/// A signal whose alignment points ST 2059-1 defines, with the rate at which they recur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Video at a frame rate: one alignment point per frame (§7).
    Video(Rational),
    /// Video with two-frame alignment, as ST 2051 uses: an alignment point at the start
    /// of the first frame of each pair (§7.4.1).
    VideoPair(Rational),
    /// AES3 audio at a sampling rate in Hz: an alignment point at the start of each
    /// 192-sample block (§8).
    Aes3(u32),
    /// Time code at a codeword rate: an alignment point at the start of each codeword (§9).
    TimeCode(Rational),
}

impl Signal {
    /// Alignment points per second.
    pub fn rate(self) -> Option<Rational> {
        match self {
            Self::Video(rate) | Self::TimeCode(rate) => Some(rate),
            Self::VideoPair(rate) => Rational::new(rate.numerator(), rate.denominator().checked_mul(2)?),
            Self::Aes3(sample_rate) => Rational::new(u64::from(sample_rate), 192),
        }
    }

    /// The time between alignment points, in seconds.
    pub fn period(self) -> Option<Rational> {
        let rate = self.rate()?;
        Rational::new(rate.denominator(), rate.numerator())
    }
}

/// How many whole periods of a signal at `rate` per second have passed at `t` since the
/// epoch: floor(t × rate). Frame 0 started at the epoch, so this is also the index of
/// the frame in progress at `t`.
pub fn period_index(t: PtpTime, rate: Rational) -> Option<i128> {
    let num = t.nanos().checked_mul(i128::from(rate.numerator()))?;
    let den = i128::from(rate.denominator()).checked_mul(NANOS)?;
    Some(num.div_euclid(den))
}

/// When period `index` of a signal at `rate` per second starts: index ÷ rate seconds
/// after the epoch, rounded up to a whole nanosecond so that it falls inside the period.
pub fn period_start(index: i128, rate: Rational) -> Option<PtpTime> {
    let num = index.checked_mul(i128::from(rate.denominator()))?.checked_mul(NANOS)?;
    PtpTime::from_nanos(ceil_div(num, i128::from(rate.numerator())))
}

/// The next alignment point after `t` (§6.2): floor(t ÷ period + 1) × period. Returns
/// its period index and its time, rounded up to a whole nanosecond. A time exactly on
/// an alignment point gives the one after.
pub fn next_alignment(t: PtpTime, signal: Signal) -> Option<(i128, PtpTime)> {
    let rate = signal.rate()?;
    let index = period_index(t, rate)?.checked_add(1)?;
    Some((index, period_start(index, rate)?))
}

/// The RTP timestamp at `t` of a media clock at `clock_rate` Hz that counts from the
/// epoch, as ST 2110-10 §7 requires (`a=mediaclk:direct=0`): floor(t × rate) mod 2³².
pub fn rtp_timestamp(t: PtpTime, clock_rate: u32) -> u32 {
    // At most 2⁴⁸ s × 10⁹ × 2³²: well within an i128.
    (t.nanos() * i128::from(clock_rate) / NANOS) as u32
}

/// The RTP timestamp of video frame `index` at `frame_rate`: the media clock's count at
/// the frame's alignment point, floor(index × clock_rate ÷ frame_rate) mod 2³². At
/// 60000/1001 and 90 kHz the timestamps step by 1501 and 1502 in turn (ST 2110-10 §7.6.1).
pub fn frame_rtp_timestamp(index: i128, frame_rate: Rational, clock_rate: u32) -> Option<u32> {
    let num = index.checked_mul(i128::from(frame_rate.denominator()))?.checked_mul(i128::from(clock_rate))?;
    Some(num.div_euclid(i128::from(frame_rate.numerator())) as u32)
}

/// How far `timestamp` is from the RTP timestamp that PTP time `t` gives a media clock
/// at `clock_rate` Hz, in clock ticks: positive when the timestamp is ahead. Of the
/// values that differ by whole wraps of 2³², the one nearest zero.
pub fn rtp_offset(timestamp: u32, t: PtpTime, clock_rate: u32) -> i64 {
    i64::from(timestamp.wrapping_sub(rtp_timestamp(t, clock_rate)) as i32)
}

fn ceil_div(num: i128, den: i128) -> i128 {
    -(-num).div_euclid(den)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(num: u64, den: u64) -> Rational {
        Rational::new(num, den).unwrap()
    }

    /// 2026-09-27 12:00:00.123456789 UTC.
    fn t() -> PtpTime {
        PtpTime::parse("1790510437.123456789").unwrap()
    }

    #[test]
    fn alignment_points() {
        // Worked out with exact fractions: (rate, index of the next frame, its start in ns).
        for (r, index, nanos) in [
            (rate(25, 1), 44_762_760_929, 1_790_510_437_160_000_000),
            (rate(50, 1), 89_525_521_857, 1_790_510_437_140_000_000),
            (rate(30000, 1001), 53_661_651_463, 1_790_510_437_148_766_667),
            (rate(60000, 1001), 107_323_302_925, 1_790_510_437_132_083_334),
        ] {
            let (i, at) = next_alignment(t(), Signal::Video(r)).unwrap();
            assert_eq!((i, at.nanos()), (index, nanos), "{r}");
            assert_eq!(period_index(at, r), Some(index), "{r}: the rounded start is inside the period");
            assert_eq!(period_index(PtpTime::from_nanos(nanos - 1).unwrap(), r), Some(index - 1));
        }
        // 192-sample AES3 blocks at 48 kHz: every 4 ms.
        let (_, at) = next_alignment(t(), Signal::Aes3(48_000)).unwrap();
        assert_eq!(at.nanos(), 1_790_510_437_124_000_000);
        // Two-frame alignment at 50 fps: every 40 ms.
        let (_, at) = next_alignment(t(), Signal::VideoPair(rate(50, 1))).unwrap();
        assert_eq!(at.nanos(), 1_790_510_437_160_000_000);
        // A time on an alignment point gives the next one.
        let on = PtpTime::parse("1790510437.16").unwrap();
        assert_eq!(next_alignment(on, Signal::Video(rate(25, 1))).unwrap().1.nanos(), 1_790_510_437_200_000_000);
        assert_eq!(Signal::Aes3(96_000).period(), Some(rate(1, 500)));
    }

    #[test]
    fn rtp_timestamps() {
        assert_eq!(rtp_timestamp(t(), 90_000), 3_061_362_487);
        assert_eq!(rtp_timestamp(t(), 48_000), 2_205_388_965);
        assert_eq!(rtp_timestamp(t(), 27_000_000), 3_580_712_085);
        for (r, ts) in
            [(rate(25, 1), 3_061_365_776), (rate(30000, 1001), 3_061_364_765), (rate(60000, 1001), 3_061_363_263)]
        {
            let (index, at) = next_alignment(t(), Signal::Video(r)).unwrap();
            assert_eq!(frame_rtp_timestamp(index, r, 90_000), Some(ts), "{r}");
            assert_eq!(rtp_timestamp(at, 90_000), ts, "{r}");
        }
        // 59.94: 1501.5 ticks a frame, truncated.
        let r = rate(60000, 1001);
        let steps: Vec<u32> = (0..4)
            .map(|i| frame_rtp_timestamp(i + 1, r, 90_000).unwrap() - frame_rtp_timestamp(i, r, 90_000).unwrap())
            .collect();
        assert_eq!(steps, [1501, 1502, 1501, 1502]);
    }

    #[test]
    fn offsets_wrap() {
        let expected = rtp_timestamp(t(), 90_000);
        assert_eq!(rtp_offset(expected, t(), 90_000), 0);
        assert_eq!(rtp_offset(expected.wrapping_add(90), t(), 90_000), 90);
        assert_eq!(rtp_offset(expected.wrapping_sub(3_330_000), t(), 90_000), -3_330_000);
        // A timestamp just past a wrap is still close.
        let at = PtpTime::from_nanos((1_i128 << 32) * NANOS / 90_000 + NANOS / 90_000 * 10).unwrap();
        let expected = rtp_timestamp(at, 90_000);
        assert!(expected < 20, "{expected}");
        assert_eq!(rtp_offset(u32::MAX, at, 90_000), -1 - i64::from(expected));
    }

    #[test]
    fn huge_rates_do_not_overflow() {
        let last = PtpTime::new((1 << 48) - 1, 999_999_999).unwrap();
        assert_eq!(period_index(last, rate(u64::MAX, 1)), None);
        assert_eq!(period_index(last, rate(240, 1)), Some(((1_i128 << 48) - 1) * 240 + 239));
        assert_eq!(period_start(i128::MAX, rate(25, 1)), None);
        assert!(next_alignment(t(), Signal::VideoPair(rate(1, u64::MAX))).is_none());
    }
}
