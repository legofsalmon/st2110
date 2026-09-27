//! Where one PTP time falls for a set of signals: the frame in progress and the next,
//! their RTP timestamps, the time code, and the audio blocks. This is what `st2110 time`
//! prints and the WebAssembly `timing` export returns.

use std::fmt;

use st2110_sdp::{FrameRateError, Rational, parse_frame_rate};

use crate::epoch::{self, Signal};
use crate::time::{Civil, PtpTime, TAI_UTC_2017};
use crate::timecode::{Jam, TimeAddress, TimecodeRate, timecode_at};

/// The RTP clock rate of ST 2110-20 video and ST 2110-40 ancillary data.
pub const VIDEO_CLOCK_RATE: u32 = 90_000;

/// What to work out, and the facts about the facility that it depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// TAI − UTC in seconds.
    pub tai_utc: i32,
    /// Seconds from PTP time to Local Time, which ST 2059-2 calls `currentLocalOffset`.
    pub local_offset: i32,
    /// Video frame rates.
    pub video: Vec<Rational>,
    /// Audio sampling rates in Hz.
    pub audio: Vec<u32>,
    /// The last daily jam, a whole second of PTP time; when `None`, the last Local Time
    /// midnight.
    pub jam: Option<PtpTime>,
    /// `currentLocalOffset` at the jam, which ST 2059-2 sends as
    /// `previousJamLocalOffset`; when `None`, `local_offset`. Time code keeps the jam's
    /// offset until the next jam, so after a daylight saving change it differs.
    pub jam_local_offset: Option<i32>,
    /// Whether time code at 30000/1001 codewords a second counts in drop-frame.
    pub drop_frame: bool,
}

/// UTC as Local Time, TAI − UTC as it has been since 2017, drop-frame time code, and no
/// signals.
impl Default for Options {
    fn default() -> Self {
        Self {
            tai_utc: TAI_UTC_2017,
            local_offset: -TAI_UTC_2017,
            video: Vec::new(),
            audio: Vec::new(),
            jam: None,
            jam_local_offset: None,
            drop_frame: true,
        }
    }
}

/// One PTP time, on each scale and for each signal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Timing {
    /// The PTP time.
    pub ptp: PtpTime,
    /// The same instant in UTC.
    pub utc: Civil,
    /// TAI − UTC used for it.
    pub tai_utc: i32,
    /// The same instant in Local Time.
    pub local: Civil,
    /// `currentLocalOffset` used for it.
    pub local_offset: i32,
    /// Each video frame rate asked for.
    pub video: Vec<Video>,
    /// Each audio sampling rate asked for.
    pub audio: Vec<Audio>,
}

/// Video at one frame rate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Video {
    /// The frame rate.
    pub rate: Rational,
    /// Frames since the SMPTE Epoch: the index of the frame in progress.
    pub frame: u64,
    /// When that frame began: its alignment point.
    pub frame_start: PtpTime,
    /// When the next frame begins.
    pub next_frame: PtpTime,
    /// The RTP timestamp of the frame in progress, at 90 kHz.
    pub rtp: u32,
    /// The RTP timestamp of the next frame.
    pub next_rtp: u32,
    /// The time code, when ST 12-1 defines one for the rate and the codeword in
    /// progress began after a jam.
    pub timecode: Option<Timecode>,
}

/// Time code at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Timecode {
    /// The time address of the codeword in progress.
    pub address: TimeAddress,
    /// Codewords a second.
    pub rate: Rational,
    /// Whether it counts in drop-frame.
    pub drop_frame: bool,
    /// The daily jam it counts from.
    pub jam: PtpTime,
    /// The jam in Local Time.
    pub jam_local: Civil,
}

/// Audio at one sampling rate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Audio {
    /// Samples a second.
    pub rate: u32,
    /// The RTP timestamp of a sample taken at this instant, with the media clock at
    /// the sampling rate.
    pub rtp: u32,
    /// AES3 blocks of 192 samples since the SMPTE Epoch: the index of the block in
    /// progress.
    pub block: u64,
    /// When that block began: its alignment point.
    pub block_start: PtpTime,
    /// When the next block begins.
    pub next_block: PtpTime,
}

/// Why [`at`] could not work a time out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingError {
    /// A rate too large to work with, far beyond any real frame or sampling rate.
    Rate,
    /// The next frame or block would begin after the last PTP time, 2⁴⁸ s after the
    /// epoch.
    End,
}

impl fmt::Display for TimingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rate => "a rate is too large to work with",
            Self::End => "the next frame or block would begin after the last PTP time, 2⁴⁸ s after the epoch",
        })
    }
}

impl std::error::Error for TimingError {}

/// Where time code counts from.
#[derive(Clone, Copy, Debug)]
enum Jams {
    /// A jam given, and only that one.
    Given(Jam),
    /// Local midnight, each day, at this local offset.
    Midnight(i32),
}

impl Jams {
    /// The time code in progress at `t`, from the jam that set it.
    fn timecode(self, t: PtpTime, rate: TimecodeRate) -> Option<Timecode> {
        let (address, jam) = match self {
            Self::Given(jam) => (timecode_at(t, rate, jam)?, jam),
            Self::Midnight(offset) => {
                let jam = Jam::midnight(t, offset)?;
                match timecode_at(t, rate, jam) {
                    Some(address) => (address, jam),
                    // The codeword in progress began before midnight's first one.
                    None => {
                        let before = Jam::midnight(jam.time.add_nanos(-1)?, offset)?;
                        (timecode_at(t, rate, before)?, before)
                    }
                }
            }
        };
        Some(Timecode {
            address,
            rate: rate.rate(),
            drop_frame: rate.drop_frame(),
            jam: jam.time,
            jam_local: jam.time.local(jam.local_offset),
        })
    }
}

/// Works out where `t` falls for each signal in `options`.
pub fn at(t: PtpTime, options: &Options) -> Result<Timing, TimingError> {
    let jam_offset = options.jam_local_offset.unwrap_or(options.local_offset);
    let jams = match options.jam {
        Some(time) => Jams::Given(Jam { time, local_offset: jam_offset }),
        None => Jams::Midnight(jam_offset),
    };
    let video = options.video.iter().map(|&rate| video(t, rate, jams, options.drop_frame)).collect::<Result<_, _>>()?;
    let audio = options.audio.iter().map(|&rate| audio(t, rate)).collect::<Result<_, _>>()?;
    Ok(Timing {
        ptp: t,
        utc: t.utc(options.tai_utc),
        tai_utc: options.tai_utc,
        local: t.local(options.local_offset),
        local_offset: options.local_offset,
        video,
        audio,
    })
}

fn video(t: PtpTime, rate: Rational, jams: Jams, drop_frame: bool) -> Result<Video, TimingError> {
    use TimingError::{End, Rate};
    let frame = epoch::period_index(t, rate).ok_or(Rate)?;
    let next = frame.checked_add(1).ok_or(Rate)?;
    let timecode = TimecodeRate::for_frame_rate(rate, drop_frame)
        .or_else(|| TimecodeRate::for_frame_rate(rate, false))
        .and_then(|tc| jams.timecode(t, tc));
    Ok(Video {
        rate,
        frame: u64::try_from(frame).map_err(|_| Rate)?,
        frame_start: epoch::period_start(frame, rate).ok_or(Rate)?,
        next_frame: epoch::period_start(next, rate).ok_or(End)?,
        rtp: epoch::frame_rtp_timestamp(frame, rate, VIDEO_CLOCK_RATE).ok_or(Rate)?,
        next_rtp: epoch::frame_rtp_timestamp(next, rate, VIDEO_CLOCK_RATE).ok_or(Rate)?,
        timecode,
    })
}

fn audio(t: PtpTime, rate: u32) -> Result<Audio, TimingError> {
    use TimingError::{End, Rate};
    let blocks = Signal::Aes3(rate).rate().ok_or(Rate)?;
    let block = epoch::period_index(t, blocks).ok_or(Rate)?;
    Ok(Audio {
        rate,
        rtp: epoch::rtp_timestamp(t, rate),
        block: u64::try_from(block).map_err(|_| Rate)?,
        block_start: epoch::period_start(block, blocks).ok_or(Rate)?,
        next_block: epoch::period_start(block.checked_add(1).ok_or(Rate)?, blocks).ok_or(End)?,
    })
}

/// Reads a time as a person might give it: PTP time as [`PtpTime::parse`] reads it, or
/// a UTC date and time as [`Civil::parse`] does, such as `2026-09-27T12:00:00Z`, which
/// becomes PTP time with TAI − UTC of `tai_utc` seconds.
pub fn read_time(text: &str, tai_utc: i32) -> Option<PtpTime> {
    PtpTime::parse(text).or_else(|| PtpTime::from_utc(Civil::parse(text)?.to_nanos(), tai_utc))
}

/// Reads a frame rate: `50`, `60000/1001`, or a decimal such as `59.94` for the rate it
/// stands for.
pub fn read_frame_rate(text: &str) -> Option<Rational> {
    match parse_frame_rate(text) {
        Ok((rate, _)) | Err(FrameRateError::Decimal(Some(rate))) => Some(rate),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noon_in_london() {
        // 2026-09-27 12:00:00.123456789 UTC is 13:00 British Summer Time.
        let t = read_time("2026-09-27T12:00:00.123456789Z", TAI_UTC_2017).unwrap();
        assert_eq!(t, PtpTime::parse("1790510437.123456789").unwrap());
        let options = Options {
            local_offset: 3563,
            video: vec![read_frame_rate("59.94").unwrap(), read_frame_rate("50").unwrap()],
            audio: vec![48_000],
            ..Options::default()
        };
        let timing = at(t, &options).unwrap();
        assert_eq!(timing.utc.to_string(), "2026-09-27 12:00:00.123456789");
        assert_eq!(timing.local.to_string(), "2026-09-27 13:00:00.123456789");

        let v = &timing.video[0];
        assert_eq!(v.rate.to_string(), "60000/1001");
        assert_eq!(v.frame, 107_323_302_924);
        assert_eq!(v.frame_start.to_string(), "1790510437.115400000");
        assert_eq!(v.next_frame.to_string(), "1790510437.132083334");
        assert_eq!((v.rtp, v.next_rtp), (3_061_361_762, 3_061_363_263));
        let tc = v.timecode.as_ref().unwrap();
        assert_eq!((tc.address.to_string(), tc.rate.to_string()), ("13:00:00;04".into(), "30000/1001".into()));
        assert_eq!(tc.jam_local.to_string(), "2026-09-27 00:00:00.000000000");

        let v = &timing.video[1];
        assert_eq!((v.frame, v.rtp), (89_525_521_856, 3_061_362_176));
        assert_eq!(v.timecode.as_ref().unwrap().address.to_string(), "13:00:00:03");

        let a = &timing.audio[0];
        assert_eq!(a.rtp, 2_205_388_965);
        assert_eq!(a.block, 447_627_609_280);
        assert_eq!(a.next_block.to_string(), "1790510437.124000000");
    }

    #[test]
    fn time_code_needs_a_rate_and_an_earlier_jam() {
        let t = PtpTime::parse("1790510437.123456789").unwrap();
        let rate = |text| read_frame_rate(text).unwrap();
        let options = Options { video: vec![rate("15"), rate("30"), rate("50")], ..Options::default() };
        let timing = at(t, &options).unwrap();
        assert!(timing.video[0].timecode.is_none(), "ST 12-1 has no 15 fps time code");
        // Drop-frame is only for 30000/1001; at 30 fps the time code counts every frame.
        assert!(!timing.video[1].timecode.as_ref().unwrap().drop_frame);
        let later = Options { jam: t.add_nanos(1), ..options.clone() };
        assert!(at(t, &later).unwrap().video[2].timecode.is_none());
        // Local midnight before the epoch.
        let first_hour = Options { local_offset: 3600, ..options };
        assert!(at(PtpTime::EPOCH, &first_hour).unwrap().video[2].timecode.is_none());
    }

    #[test]
    fn reads_rates_and_times() {
        assert_eq!(read_frame_rate("29.97").map(|r| r.to_string()).as_deref(), Some("30000/1001"));
        assert_eq!(read_frame_rate("25/1").map(|r| r.to_string()).as_deref(), Some("25"));
        assert_eq!(read_frame_rate("fast"), None);
        assert_eq!(read_time("1790510437:5", 37).map(|t| t.subsec_nanos()), Some(5));
        assert_eq!(read_time("1970-01-01T00:00:00Z", 37).map(|t| t.seconds()), Some(37));
        assert_eq!(read_time("1969-12-31T23:59:00Z", 37), None);
    }

    #[test]
    fn a_jam_keeps_its_own_offset() {
        // The clocks went forward at 01:00 UTC on 28 March 2027, but time code counts from
        // the midnight jam, made at GMT, until the next one.
        let t = read_time("2027-03-28T12:00:00Z", TAI_UTC_2017).unwrap();
        let bst = Options { local_offset: 3563, video: vec![read_frame_rate("25").unwrap()], ..Options::default() };
        let gmt = Options { jam_local_offset: Some(-37), ..bst.clone() };
        for options in [gmt.clone(), Options { jam: read_time("2027-03-28T00:00:00Z", TAI_UTC_2017), ..gmt }] {
            let timing = at(t, &options).unwrap();
            assert_eq!(timing.local.to_string(), "2027-03-28 13:00:00.000000000");
            let tc = timing.video[0].timecode.as_ref().unwrap();
            assert_eq!(tc.address.to_string(), "12:00:00:00");
            assert_eq!(
                (tc.jam.seconds(), tc.jam_local.to_string()),
                (1_806_192_037, "2027-03-28 00:00:00.000000000".into())
            );
        }
        // Without it, the offset is taken not to have changed since the jam.
        let tc = at(t, &bst).unwrap().video.remove(0).timecode.unwrap();
        assert_eq!((tc.address.to_string(), tc.jam.seconds()), ("13:00:00:00".into(), 1_806_188_437));
    }

    #[test]
    fn just_after_midnight() {
        // The first 29.97 codeword after the jam at midnight starts 25.13 ms after it; the
        // one in progress before then counts from the jam the day before, whose count has
        // run 2.6 frames ahead of the clock since.
        let options = Options { video: vec![read_frame_rate("29.97").unwrap()], ..Options::default() };
        let timecode = |text| {
            let tc = at(read_time(text, TAI_UTC_2017).unwrap(), &options).unwrap().video.remove(0).timecode.unwrap();
            (tc.address.to_string(), format!("{:.0}", tc.jam_local))
        };
        assert_eq!(timecode("2026-09-27T00:00:00.010Z"), ("00:00:00;02".into(), "2026-09-26 00:00:00".into()));
        assert_eq!(timecode("2026-09-27T00:00:00.030Z"), ("00:00:00;00".into(), "2026-09-27 00:00:00".into()));
        // A jam given is the only one: before its first codeword there is no time code.
        let jam = Options { jam: read_time("2026-09-27T00:00:00Z", TAI_UTC_2017), ..options.clone() };
        let t = read_time("2026-09-27T00:00:00.010Z", TAI_UTC_2017).unwrap();
        assert!(at(t, &jam).unwrap().video[0].timecode.is_none());
    }

    #[test]
    fn rates_and_times_out_of_reach() {
        let t = PtpTime::parse("1790510437").unwrap();
        let options = Options { video: vec![Rational::new(u64::MAX, 1).unwrap()], ..Options::default() };
        assert_eq!(at(t, &options), Err(TimingError::Rate));
        // The last PTP time has no next frame.
        let last = PtpTime::parse("281474976710655.999999999").unwrap();
        let video = Options { video: vec![read_frame_rate("25").unwrap()], ..Options::default() };
        assert_eq!(at(last, &video), Err(TimingError::End));
        assert_eq!(at(last, &Options { audio: vec![48_000], ..Options::default() }), Err(TimingError::End));
        assert!(TimingError::End.to_string().starts_with("the next frame or block would begin after"));
    }
}
