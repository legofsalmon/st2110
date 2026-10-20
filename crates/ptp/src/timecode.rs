//! Time code from PTP time: SMPTE ST 12-1 time addresses, colour framing and the
//! ST 309 date, from the ST 2059-1 daily jam.

use std::fmt;

use st2110_sdp::Rational;

use crate::epoch::period_index;
use crate::time::{Civil, NANOS, PtpTime};

/// An ST 12-1 time address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAddress {
    /// Hours, 0 to 23.
    pub hours: u8,
    /// Minutes, 0 to 59.
    pub minutes: u8,
    /// Seconds, 0 to 59.
    pub seconds: u8,
    /// The frame number within the second.
    pub frames: u8,
    /// Whether it counts in drop-frame, which skips frame numbers 0 and 1 at the start
    /// of each minute except every tenth.
    pub drop_frame: bool,
    /// The Color Frame Flag of the ST 12-1 codeword: set when the time code is colour
    /// frame aligned (ST 2059-1 §9.3).
    pub color_frame: bool,
}

/// Written `13:00:00:04`, or `13:00:00;04` in drop-frame.
impl fmt::Display for TimeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let separator = if self.drop_frame { ';' } else { ':' };
        write!(f, "{:02}:{:02}:{:02}{separator}{:02}", self.hours, self.minutes, self.seconds, self.frames)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TimeAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Codewords in ten minutes, one minute and one hour of drop-frame time code.
const DF_TEN_MINUTES: i128 = 17_982;
const DF_MINUTE: i128 = 1798;

/// How time code counts: its codeword rate, whether it drops frame numbers, and whether
/// it is colour frame aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimecodeRate {
    rate: Rational,
    drop_frame: bool,
    color_frame: bool,
}

impl TimecodeRate {
    /// Time code at `rate` codewords a second: 24, 25 or 30, or 24000/1001 or 30000/1001.
    /// ST 12-1 defines drop-frame counting at 30000/1001 only.
    pub fn new(rate: Rational, drop_frame: bool) -> Option<Self> {
        let known = matches!((rate.numerator(), rate.denominator()), (24 | 25 | 30, 1) | (24000 | 30000, 1001));
        let drop_ok = !drop_frame || (rate.numerator(), rate.denominator()) == (30000, 1001);
        (known && drop_ok).then_some(Self { rate, drop_frame, color_frame: false })
    }

    /// The same, colour frame aligned to the SMPTE Epoch, as `colorFrameIdentificationMode`
    /// asks: the daily jam waits for the first codeword of a colour frame sequence.
    /// ST 2059-1 §9.3.2.1 defines it at 25 and 30000/1001 codewords a second only.
    pub fn with_color_frame(self) -> Option<Self> {
        self.color_frames().is_some().then_some(Self { color_frame: true, ..self })
    }

    /// Time code for video at `frame_rate`. Above 30 fps, one codeword spans two frames
    /// (or four), so 50 fps counts at 25 and 60000/1001 at 30000/1001.
    pub fn for_frame_rate(frame_rate: Rational, drop_frame: bool) -> Option<Self> {
        let mut rate = frame_rate;
        while u128::from(rate.numerator()) > 30 * u128::from(rate.denominator()) {
            rate = Rational::new(rate.numerator(), rate.denominator().checked_mul(2)?)?;
        }
        Self::new(rate, drop_frame)
    }

    /// Codewords per second.
    pub fn rate(self) -> Rational {
        self.rate
    }

    /// Whether it counts in drop-frame.
    pub fn drop_frame(self) -> bool {
        self.drop_frame
    }

    /// Whether it is colour frame aligned.
    pub fn color_frame(self) -> bool {
        self.color_frame
    }

    /// CF, the codewords in a colour frame sequence (ST 2059-1 §9.3.2.1): 2 at
    /// 30000/1001 and 4 at 25.
    fn color_frames(self) -> Option<i128> {
        match (self.rate.numerator(), self.rate.denominator()) {
            (30000, 1001) => Some(2),
            (25, 1) => Some(4),
            _ => None,
        }
    }

    /// Frame numbers in a second: 24, 25 or 30.
    pub fn frames_per_second(self) -> u32 {
        self.rate.numerator().div_ceil(self.rate.denominator()) as u32
    }

    /// Codewords in a time-code day, from 00:00:00:00 to 23:59:59 and the last frame.
    pub fn frames_per_day(self) -> u64 {
        if self.drop_frame { 24 * 6 * DF_TEN_MINUTES as u64 } else { u64::from(self.frames_per_second()) * 86_400 }
    }

    /// The time address of codeword `count` of the day, counting 00:00:00:00 as 0.
    /// Counts outside the day wrap, so −1 is the last codeword of the day before.
    pub fn address(self, count: i128) -> TimeAddress {
        let fps = i128::from(self.frames_per_second());
        let mut count = count.rem_euclid(i128::from(self.frames_per_day()));
        if self.drop_frame {
            // Put back the frame numbers skipped so far, then count as if none were.
            let (tens, rest) = (count / DF_TEN_MINUTES, count % DF_TEN_MINUTES);
            count += 18 * tens + if rest > 1 { 2 * ((rest - 2) / DF_MINUTE) } else { 0 };
        }
        TimeAddress {
            hours: (count / (fps * 3600)) as u8,
            minutes: (count / (fps * 60) % 60) as u8,
            seconds: (count / fps % 60) as u8,
            frames: (count % fps) as u8,
            drop_frame: self.drop_frame,
            color_frame: self.color_frame,
        }
    }

    /// The count of a time address within its day, or `None` for an address this rate
    /// never shows: a field out of range, or a frame number that drop-frame skips.
    pub fn count(self, address: TimeAddress) -> Option<u64> {
        let TimeAddress { hours, minutes, seconds, frames, .. } = address;
        let fps = self.frames_per_second();
        if hours > 23 || minutes > 59 || seconds > 59 || u32::from(frames) >= fps {
            return None;
        }
        if self.drop_frame && seconds == 0 && frames < 2 && minutes % 10 != 0 {
            return None;
        }
        let total_minutes = u64::from(hours) * 60 + u64::from(minutes);
        let nominal = (total_minutes * 60 + u64::from(seconds)) * u64::from(fps) + u64::from(frames);
        Some(if self.drop_frame { nominal - 2 * (total_minutes - total_minutes / 10) } else { nominal })
    }
}

/// A daily jam (ST 2059-1 §9.3): the instant time code was last set to Local Time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Jam {
    /// When it happened: a whole second, as a grandmaster sends it in
    /// `timeOfPreviousJam`.
    pub time: PtpTime,
    /// The `currentLocalOffset` then, in seconds; the grandmaster's
    /// `previousJamLocalOffset`.
    pub local_offset: i32,
}

impl Jam {
    /// The last Local Time midnight at or before `t`, for when no jam time is known.
    pub fn midnight(t: PtpTime, local_offset: i32) -> Option<Self> {
        let local = i128::from(t.seconds()) + i128::from(local_offset);
        let midnight = local - local.rem_euclid(86_400) - i128::from(local_offset);
        Some(Self { time: PtpTime::from_nanos(midnight * NANOS)?, local_offset })
    }
}

/// An ST 309 date: the Gregorian date and Modified Julian Date of Local Time on the
/// time code's day, which changes as the time address passes 00:00:00:00 (ST 2059-1
/// §9.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Date {
    /// The year, such as 2026.
    pub year: i64,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// Days since 1858-11-17.
    pub mjd: i64,
}

/// Written `2026-09-27 (MJD 61310)`.
impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02} (MJD {})", self.year, self.month, self.day, self.mjd)
    }
}

/// The time address of the time code codeword in progress at `t` (ST 2059-1 §9.3).
///
/// At the daily jam, time code takes the Local Time of day, and from then it counts
/// codewords: the first codeword at or after the jam carries the jam's time of day,
/// and each one after adds a frame. At 1000/1001 rates the count drifts from Local Time
/// until the next jam sets it again; a change to the local offset also waits for it.
///
/// Colour frame aligned, the jam waits for the first codeword of a colour frame
/// sequence, and at 25 codewords a second that codeword is frame 1 (§9.3.2.1).
///
/// `None` when the codeword in progress at `t` began before that first codeword, so
/// that the jam before set it, as for up to a frame after a jam at 1000/1001 rates, or
/// when the jam is not on a whole second.
pub fn timecode_at(t: PtpTime, rate: TimecodeRate, jam: Jam) -> Option<TimeAddress> {
    let (count, _) = since_jam(t, rate, jam)?;
    Some(rate.address(count))
}

/// The ST 309 date of the time code codeword in progress at `t`: the jam's Local Time
/// date, and a day more each time the time address has passed midnight since
/// (ST 2059-1 §9.3.2.5 step 3). `None` when [`timecode_at`] is.
pub fn date_at(t: PtpTime, rate: TimecodeRate, jam: Jam) -> Option<Date> {
    let (count, jam_day) = since_jam(t, rate, jam)?;
    let days = jam_day + count.div_euclid(i128::from(rate.frames_per_day()));
    let civil = Civil::from_nanos(days.checked_mul(86_400 * NANOS)?)?;
    let mjd = i64::try_from(days + 40_587).ok()?;
    Some(Date { year: civil.year, month: civil.month, day: civil.day, mjd })
}

/// The count of the codeword in progress at `t` from midnight of the jam's day, not
/// wrapped at the end of the day, and that day, in days since 1970-01-01 Local Time.
fn since_jam(t: PtpTime, rate: TimecodeRate, jam: Jam) -> Option<(i128, i128)> {
    if jam.time.subsec_nanos() != 0 {
        return None;
    }
    let codewords = rate.rate();
    let now = period_index(t, codewords)?;
    let mut jam_index = ceil_index(jam.time, codewords)?;
    // The codewords on to the start of the colour frame sequence (§9.3.2.1 step 2).
    if let (true, Some(cf)) = (rate.color_frame(), rate.color_frames()) {
        jam_index += (cf - jam_index.rem_euclid(cf)) % cf;
    }
    if now < jam_index {
        return None;
    }
    let local = i128::from(jam.time.seconds()) + i128::from(jam.local_offset);
    let (day, of_day) = (local.div_euclid(86_400), local.rem_euclid(86_400));
    let (hours, minutes, seconds) = ((of_day / 3600) as u8, (of_day / 60 % 60) as u8, (of_day % 60) as u8);
    let frames = match (rate.drop_frame(), rate.color_frame() && rate.color_frames() == Some(4)) {
        // FFpdjam is 1 at 25 codewords a second, colour frame aligned (§9.3.2.1 step 5).
        (_, true) => 1,
        // A drop-frame minute not divisible by ten starts at frame 2.
        (true, false) if seconds == 0 && minutes % 10 != 0 => 2,
        _ => 0,
    };
    let at_jam = rate.count(TimeAddress {
        hours,
        minutes,
        seconds,
        frames,
        drop_frame: rate.drop_frame(),
        color_frame: rate.color_frame(),
    })?;
    Some((i128::from(at_jam) + now - jam_index, day))
}

/// ceil(t × rate): the index of the first period that starts at or after `t`.
fn ceil_index(t: PtpTime, rate: Rational) -> Option<i128> {
    let num = t.nanos().checked_mul(i128::from(rate.numerator()))?;
    let den = i128::from(rate.denominator()).checked_mul(NANOS)?;
    Some(-(-num).div_euclid(den))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(num: u64, den: u64, drop_frame: bool) -> TimecodeRate {
        TimecodeRate::new(Rational::new(num, den).unwrap(), drop_frame).unwrap()
    }

    #[test]
    fn drop_frame_counting() {
        let df = rate(30000, 1001, true);
        for (count, text) in [
            (0, "00:00:00;00"),
            (1799, "00:00:59;29"),
            (1800, "00:01:00;02"),
            (17_981, "00:09:59;29"),
            (17_982, "00:10:00;00"),
            (107_891, "00:59:59;29"),
            (107_892, "01:00:00;00"),
            (2_589_407, "23:59:59;29"),
            (2_589_408, "00:00:00;00"),
            (-1, "23:59:59;29"),
        ] {
            let address = df.address(count);
            assert_eq!(address.to_string(), text, "{count}");
            assert_eq!(df.count(address), Some(count.rem_euclid(2_589_408) as u64), "{text}");
        }
        assert_eq!(df.frames_per_day(), 2_589_408);
        // 00:01:00;00 and ;01 do not exist; 00:10:00;00 does.
        let at = |minutes, frames| TimeAddress {
            hours: 0,
            minutes,
            seconds: 0,
            frames,
            drop_frame: true,
            color_frame: false,
        };
        assert_eq!(df.count(at(1, 0)), None);
        assert_eq!(df.count(at(1, 1)), None);
        assert_eq!(df.count(at(10, 0)), Some(17_982));
    }

    #[test]
    fn every_drop_frame_count_round_trips() {
        let df = rate(30000, 1001, true);
        for count in 0..df.frames_per_day() {
            assert_eq!(df.count(df.address(i128::from(count))), Some(count));
        }
    }

    #[test]
    fn rates() {
        let r = |num, den| Rational::new(num, den).unwrap();
        assert_eq!(TimecodeRate::for_frame_rate(r(50, 1), false).map(|t| t.rate()), Some(r(25, 1)));
        assert_eq!(TimecodeRate::for_frame_rate(r(60000, 1001), true).map(|t| t.rate()), Some(r(30000, 1001)));
        assert_eq!(TimecodeRate::for_frame_rate(r(120, 1), false).map(|t| t.rate()), Some(r(30, 1)));
        assert_eq!(TimecodeRate::for_frame_rate(r(24000, 1001), false).map(|t| t.frames_per_second()), Some(24));
        assert!(TimecodeRate::new(r(25, 1), true).is_none(), "drop-frame is for 30000/1001 only");
        assert!(TimecodeRate::new(r(15, 1), false).is_none());
        assert_eq!(rate(25, 1, false).address(2_160_000 - 1).to_string(), "23:59:59:24");
    }

    #[test]
    fn time_code_from_ptp_time() {
        // 2026-09-27 12:00:00.123456789 UTC; 13:00 British Summer Time.
        let t = PtpTime::parse("1790510437.123456789").unwrap();
        let jam = Jam::midnight(t, 3563).unwrap();
        assert_eq!(jam.time.utc(37).to_string(), "2026-09-26 23:00:00.000000000");
        for (tc, expected) in [
            (rate(25, 1, false), "13:00:00:03"),
            (rate(30, 1, false), "13:00:00:03"),
            (rate(24, 1, false), "13:00:00:02"),
            // Drop-frame stays within a few frames of Local Time; non-drop at 1000/1001
            // falls 3.6 s behind an hour.
            (rate(30000, 1001, true), "13:00:00;04"),
            (rate(30000, 1001, false), "12:59:13:10"),
            (rate(24000, 1001, false), "12:59:13:08"),
        ] {
            assert_eq!(timecode_at(t, tc, jam).unwrap().to_string(), expected, "{tc:?}");
        }
        // The first codeword after the jam starts 28.7 ms after it and carries the jam's
        // time of day; the next starts 33.4 ms later.
        let df = rate(30000, 1001, true);
        let after = |ms: i128| timecode_at(jam.time.add_nanos(ms * 1_000_000).unwrap(), df, jam).map(|a| a.to_string());
        assert_eq!(after(40).as_deref(), Some("00:00:00;00"));
        assert_eq!(after(70).as_deref(), Some("00:00:00;01"));
        // Before it, the codeword in progress began under the jam before.
        assert_eq!(after(10), None);
        assert_eq!(timecode_at(jam.time.add_nanos(-1).unwrap(), df, jam), None);
        // A jam off the whole second is not one a grandmaster could send.
        let fraction = Jam { time: jam.time.add_nanos(500_000_000).unwrap(), ..jam };
        assert_eq!(timecode_at(t, rate(25, 1, false), fraction), None);
    }

    #[test]
    fn colour_framing_waits_for_the_sequence() {
        // 2026-09-27 12:00:00.123456789 UTC, from the jam at midnight British Summer Time.
        let t = PtpTime::parse("1790510437.123456789").unwrap();
        let jam = Jam::midnight(t, 3563).unwrap();
        // At 25 codewords a second the jam is codeword 44761590925 since the epoch, 1 into
        // a sequence of four: time code starts three codewords on, at frame 1.
        let pal = rate(25, 1, false).with_color_frame().unwrap();
        let at = |ms: i128| timecode_at(jam.time.add_nanos(ms * 1_000_000).unwrap(), pal, jam);
        assert_eq!(at(100), None);
        let first = at(120).unwrap();
        assert_eq!((first.to_string(), first.color_frame), ("00:00:00:01".into(), true));
        assert_eq!(timecode_at(t, pal, jam).unwrap().to_string(), "13:00:00:01");
        // At 30000/1001 the sequence is two codewords. Five seconds after midnight the first
        // codeword after the jam, 0.4 ms in, is odd: time code starts at the next, 33.7 ms in.
        let ntsc = rate(30000, 1001, true);
        let jam = Jam { time: jam.time.add_nanos(5 * NANOS).unwrap(), ..jam };
        let at = |tc, ms: i128| timecode_at(jam.time.add_nanos(ms * 1_000_000).unwrap(), tc, jam);
        assert_eq!(at(ntsc, 10).map(|a| a.to_string()).as_deref(), Some("00:00:05;00"));
        let framed = ntsc.with_color_frame().unwrap();
        assert_eq!(at(framed, 10), None);
        assert_eq!(at(framed, 40).map(|a| a.to_string()).as_deref(), Some("00:00:05;00"));
        // ST 2059-1 defines it at those two rates only.
        assert_eq!(rate(30, 1, false).with_color_frame(), None);
        assert_eq!(rate(24000, 1001, false).with_color_frame(), None);
    }

    #[test]
    fn the_date_changes_with_the_time_address() {
        let t = PtpTime::parse("1790510437.123456789").unwrap();
        let jam = Jam::midnight(t, 3563).unwrap();
        let date = date_at(t, rate(25, 1, false), jam).unwrap();
        assert_eq!(date.to_string(), "2026-09-27 (MJD 61310)");
        // Non-drop time code at 30000/1001 runs 86.4 s a day behind Local Time: jammed at
        // midnight a day before, it is still on the 26th 30 s into the 27th, and on the
        // 27th a minute and a half later.
        let ndf = rate(30000, 1001, false);
        let before = Jam { time: jam.time.add_nanos(-86_400 * NANOS).unwrap(), ..jam };
        let at = |s: i128| {
            let t = before.time.add_nanos(s * NANOS).unwrap();
            (timecode_at(t, ndf, before).unwrap().to_string(), date_at(t, ndf, before).unwrap().to_string())
        };
        assert_eq!(at(86_430), ("23:59:03:19".into(), "2026-09-26 (MJD 61309)".into()));
        assert_eq!(at(86_520), ("00:00:33:16".into(), "2026-09-27 (MJD 61310)".into()));
    }

    #[test]
    fn jam_off_the_ten_minutes() {
        // A jam at 00:01:00 local in drop-frame starts at frame 2, the first that exists.
        // 45705660 s is 00:01:00 and a whole number of 30000/1001 codewords.
        let df = rate(30000, 1001, true);
        let jam = Jam { time: PtpTime::new(45_705_660, 0).unwrap(), local_offset: 0 };
        assert_eq!(timecode_at(jam.time, df, jam).unwrap().to_string(), "00:01:00;02");
    }
}
