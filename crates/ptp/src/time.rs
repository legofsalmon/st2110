//! PTP time and its calendar form.

use std::fmt;

/// Nanoseconds in a second.
pub(crate) const NANOS: i128 = 1_000_000_000;

/// PTP seconds are 48 bits on the wire.
const MAX_SECONDS: u64 = 1 << 48;

/// TAI − UTC in seconds from 1 January 2017, when the most recent leap second was added.
pub const TAI_UTC_2017: i32 = 37;

/// A PTP time: nanoseconds since the PTP epoch, 1970-01-01 00:00:00 TAI, which
/// ST 2059-1 calls the SMPTE Epoch.
///
/// PTP time counts TAI seconds, so it runs ahead of UTC by the leap seconds so far:
/// 37 s since 2017. Its range is the 48-bit seconds field of a PTP timestamp.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PtpTime(i128);

impl PtpTime {
    /// The epoch itself.
    pub const EPOCH: Self = Self(0);

    /// The time `seconds` and `nanoseconds` after the epoch. `None` when `nanoseconds`
    /// is a second or more, or `seconds` does not fit in 48 bits.
    pub fn new(seconds: u64, nanoseconds: u32) -> Option<Self> {
        (seconds < MAX_SECONDS && nanoseconds < 1_000_000_000)
            .then(|| Self(i128::from(seconds) * NANOS + i128::from(nanoseconds)))
    }

    /// The time `nanos` nanoseconds after the epoch, if it is within range.
    pub fn from_nanos(nanos: i128) -> Option<Self> {
        (0..i128::from(MAX_SECONDS) * NANOS).contains(&nanos).then_some(Self(nanos))
    }

    /// The PTP time of a UTC instant given as nanoseconds since 1970-01-01 00:00:00 UTC
    /// (Unix time), when TAI − UTC is `tai_utc` seconds.
    pub fn from_utc(unix_nanos: i128, tai_utc: i32) -> Option<Self> {
        Self::from_nanos(unix_nanos.checked_add(i128::from(tai_utc) * NANOS)?)
    }

    /// Nanoseconds since the epoch.
    pub fn nanos(self) -> i128 {
        self.0
    }

    /// Whole seconds since the epoch.
    pub fn seconds(self) -> u64 {
        (self.0 / NANOS) as u64
    }

    /// The nanoseconds past the whole second.
    pub fn subsec_nanos(self) -> u32 {
        (self.0 % NANOS) as u32
    }

    /// This time moved by `nanos` nanoseconds, if the result is within range.
    pub fn add_nanos(self, nanos: i128) -> Option<Self> {
        Self::from_nanos(self.0.checked_add(nanos)?)
    }

    /// Reads `1790510437.123456789` (up to nine decimals, or none) or the IS-04 and
    /// IS-05 form, `1790510437:123456789`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (seconds, fraction) = match text.split_once([':', '.']) {
            Some((seconds, fraction)) => (seconds, fraction),
            None => (text, ""),
        };
        let seconds: u64 = digits(seconds)?.parse().ok()?;
        let nanoseconds = if fraction.is_empty() {
            0
        } else if text.contains(':') {
            // IS-04 writes nanoseconds as an integer: `12:5` is 12 s and 5 ns.
            digits(fraction).filter(|f| f.len() <= 9)?.parse().ok()?
        } else {
            let fraction = digits(fraction).filter(|f| f.len() <= 9)?;
            format!("{fraction:0<9}").parse().ok()?
        };
        Self::new(seconds, nanoseconds)
    }

    /// The calendar date and time this is in UTC, when TAI − UTC is `tai_utc` seconds.
    pub fn utc(self, tai_utc: i32) -> Civil {
        Civil::from_nanos(self.0 - i128::from(tai_utc) * NANOS)
    }

    /// The calendar date and time this is in Local Time, which ST 2059-2 defines as PTP
    /// time plus `currentLocalOffset`.
    pub fn local(self, local_offset: i32) -> Civil {
        Civil::from_nanos(self.0 + i128::from(local_offset) * NANOS)
    }
}

/// Written `1790510437.123456789`.
impl fmt::Display for PtpTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.seconds(), self.subsec_nanos())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PtpTime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn digits(text: &str) -> Option<&str> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then_some(text)
}

/// A calendar date and time of day, proleptic Gregorian, with no leap seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    /// The year, such as 2026.
    pub year: i64,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59.
    pub second: u8,
    /// Nanoseconds past the second.
    pub nanosecond: u32,
}

impl Civil {
    /// The date and time `nanos` nanoseconds after 1970-01-01 00:00:00 on the same scale.
    pub fn from_nanos(nanos: i128) -> Self {
        let seconds = nanos.div_euclid(NANOS);
        let days = seconds.div_euclid(86_400) as i64;
        let of_day = seconds.rem_euclid(86_400) as u32;
        // Days to a date, after Howard Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month,
            day,
            hour: (of_day / 3600) as u8,
            minute: (of_day / 60 % 60) as u8,
            second: (of_day % 60) as u8,
            nanosecond: nanos.rem_euclid(NANOS) as u32,
        }
    }
}

impl Civil {
    /// Nanoseconds from 1970-01-01 00:00:00 on the same scale: the inverse of
    /// [`Civil::from_nanos`].
    pub fn to_nanos(&self) -> i128 {
        // A date to days, after Howard Hinnant's days_from_civil.
        let year = self.year - i64::from(self.month <= 2);
        let era = year.div_euclid(400);
        let yoe = year.rem_euclid(400);
        let doy = (153 * ((i64::from(self.month) + 9) % 12) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = i128::from(era * 146_097 + doe - 719_468);
        let seconds =
            days * 86_400 + i128::from(self.hour) * 3600 + i128::from(self.minute) * 60 + i128::from(self.second);
        seconds * NANOS + i128::from(self.nanosecond)
    }

    /// Reads `2026-09-27 12:00:00`, with `T` for the space if wanted, up to nine decimals
    /// of a second and an optional `Z`, as JavaScript's `toISOString` writes. `None` for
    /// anything else, including a date or time that does not exist, such as a 30 February
    /// or the 61st second of a leap second.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_suffix(['Z', 'z']).unwrap_or(text);
        let (date, time) = text.split_once(['T', 't', ' '])?;
        let [year, month, day] = fields(date, '-')?;
        let [hour, minute, second] = fields(time, ':')?;
        let (second, nanosecond) = match second.split_once('.') {
            None => (second, 0),
            Some((second, fraction)) => {
                (second, format!("{:0<9}", digits(fraction).filter(|f| f.len() <= 9)?).parse().ok()?)
            }
        };
        let two = |text: &str| digits(text).filter(|t| t.len() == 2)?.parse::<u8>().ok();
        let civil = Self {
            year: digits(year).filter(|y| y.len() == 4)?.parse().ok()?,
            month: two(month)?,
            day: two(day)?,
            hour: two(hour)?,
            minute: two(minute)?,
            second: two(second)?,
            nanosecond,
        };
        // Out-of-range fields carry over into others, so a round trip catches them all.
        (Self::from_nanos(civil.to_nanos()) == civil).then_some(civil)
    }
}

/// Splits `text` at `separator` into exactly `N` parts.
fn fields<const N: usize>(text: &str, separator: char) -> Option<[&str; N]> {
    let parts: Vec<&str> = text.split(separator).collect();
    parts.try_into().ok()
}

/// Written `2026-09-27 12:00:00.123456789`. A precision keeps that many decimals, so
/// `{:.0}` writes `2026-09-27 12:00:00`.
impl fmt::Display for Civil {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )?;
        match f.precision().unwrap_or(9).min(9) {
            0 => Ok(()),
            digits => write!(f, ".{:0digits$}", self.nanosecond / 10_u32.pow(9 - digits as u32)),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Civil {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_forms() {
        let t = PtpTime::new(1_790_510_437, 123_456_789).unwrap();
        assert_eq!(PtpTime::parse("1790510437.123456789"), Some(t));
        assert_eq!(PtpTime::parse("1790510437:123456789"), Some(t));
        assert_eq!(PtpTime::parse("1790510437.5").unwrap().subsec_nanos(), 500_000_000);
        assert_eq!(PtpTime::parse("12:5").unwrap().subsec_nanos(), 5);
        assert_eq!(PtpTime::parse("1790510437").unwrap().nanos(), 1_790_510_437 * NANOS);
        for bad in ["", ".5", "1.1234567891", "1:1000000000", "-1", "1e9", "281474976710656"] {
            assert_eq!(PtpTime::parse(bad), None, "{bad}");
        }
        assert_eq!(t.to_string(), "1790510437.123456789");
    }

    #[test]
    fn calendar() {
        let t = PtpTime::parse("1790510437.123456789").unwrap();
        assert_eq!(t.utc(TAI_UTC_2017).to_string(), "2026-09-27 12:00:00.123456789");
        // British Summer Time: UTC+1, so Local Time is PTP time plus 3600 − 37 s.
        assert_eq!(t.local(3563).to_string(), "2026-09-27 13:00:00.123456789");
        assert_eq!(PtpTime::EPOCH.utc(0).to_string(), "1970-01-01 00:00:00.000000000");
        assert_eq!(format!("{:.0}", t.utc(TAI_UTC_2017)), "2026-09-27 12:00:00");
        assert_eq!(format!("{:.3}", t.utc(TAI_UTC_2017)), "2026-09-27 12:00:00.123");
        assert_eq!(Civil::from_nanos(-NANOS).to_string(), "1969-12-31 23:59:59.000000000");
        // 2000 is a leap year, 2100 is not.
        assert_eq!(Civil::from_nanos(951_782_400 * NANOS).to_string(), "2000-02-29 00:00:00.000000000");
        assert_eq!(Civil::from_nanos(4_107_542_400 * NANOS).to_string(), "2100-03-01 00:00:00.000000000");
    }

    #[test]
    fn reads_dates() {
        let noon = Civil::parse("2026-09-27T12:00:00Z").unwrap();
        assert_eq!(noon.to_nanos(), 1_790_510_400 * NANOS);
        assert_eq!(Civil::parse("2026-09-27 12:00:00.5").unwrap().to_nanos(), 1_790_510_400 * NANOS + NANOS / 2);
        assert_eq!(Civil::parse("2026-09-27T12:00:00.123456789z").unwrap().nanosecond, 123_456_789);
        for bad in [
            "",
            "2026-02-29T00:00:00Z",
            "2026-09-27T24:00:00Z",
            "2016-12-31T23:59:60Z",
            "2026-9-27T12:00:00Z",
            "2026-09-27T12:00Z",
            "2026-09-27T12:00:00.Z",
            "2026-09-27T12:00:00.1234567891Z",
            "2026-09-27T12:00:00+01:00",
            "1790510437",
        ] {
            assert_eq!(Civil::parse(bad), None, "{bad}");
        }
        assert!(Civil::parse("2028-02-29T00:00:00Z").is_some());
        for nanos in [-NANOS, 0, 951_782_400 * NANOS + 7, 4_107_542_399 * NANOS, 1 << 60] {
            assert_eq!(Civil::from_nanos(nanos).to_nanos(), nanos);
        }
    }

    #[test]
    fn utc_round_trip() {
        let unix = 1_790_510_400 * NANOS + 123;
        let t = PtpTime::from_utc(unix, TAI_UTC_2017).unwrap();
        assert_eq!(t.nanos(), unix + 37 * NANOS);
        assert_eq!(PtpTime::from_utc(-38 * NANOS, TAI_UTC_2017), None);
    }
}
