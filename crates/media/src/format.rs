//! Stream formats: the picture or sound a sender sends and a receiver expects.

use std::fmt;

use st2110_sdp::video::{Depth, PixelGroup, Sampling, pixel_group};
use st2110_sdp::{FrameRateError, Rational, parse_frame_rate};

/// The largest RTP payload under ST 2110-10's standard UDP size limit of 1460 octets,
/// less the 8-octet UDP header and the 12-octet RTP header.
pub const PAYLOAD_LIMIT: usize = st2110_sdp::audio::STANDARD_PAYLOAD_LIMIT as usize;

/// `colorimetry` values ST 2110-20:2022 §7.3 defines.
pub const COLORIMETRY: [&str; 9] =
    ["BT601", "BT709", "BT2020", "BT2100", "ST2065-1", "ST2065-3", "XYZ", "ALPHA", "UNSPECIFIED"];

/// `TCS` values ST 2110-20:2022 §7.4 defines.
pub const TRANSFER: [&str; 11] = [
    "SDR",
    "PQ",
    "HLG",
    "LINEAR",
    "BT2100LINPQ",
    "BT2100LINHLG",
    "ST2065-1",
    "ST428-1",
    "DENSITY",
    "ST2115LOGS3",
    "UNSPECIFIED",
];

/// How ST 2110-20 packs pixel groups into packets (§6.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Packing {
    /// General packing, `2110GPM`: each row split evenly into packets as close to the
    /// UDP size limit as it allows, or up to three short rows to a packet.
    #[default]
    General,
    /// Block packing, `2110BPM`: 180-octet blocks, seven to a packet, running on from
    /// one row into the next.
    Block,
}

impl Packing {
    /// The `PM` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "2110GPM",
            Self::Block => "2110BPM",
        }
    }
}

/// Checks an ST 2110-30 sampling rate.
fn check_rate(rate: u32) -> Result<(), String> {
    if [44_100, 48_000, 96_000].contains(&rate) {
        Ok(())
    } else {
        Err(format!("{rate} Hz is not 48 000, 96 000 or 44 100"))
    }
}

/// An ST 2110-21 sender type, the `TP` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SenderType {
    /// `2110TPN`: narrow, with the gapped read schedule.
    Narrow,
    /// `2110TPNL`: narrow, with the linear read schedule.
    NarrowLinear,
    /// `2110TPW`: wide. Software pacing on ordinary sockets can hope for no more.
    #[default]
    Wide,
}

impl SenderType {
    /// The `TP` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Narrow => "2110TPN",
            Self::NarrowLinear => "2110TPNL",
            Self::Wide => "2110TPW",
        }
    }

    /// Reads a `TP` value.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "2110TPN" => Some(Self::Narrow),
            "2110TPNL" => Some(Self::NarrowLinear),
            "2110TPW" => Some(Self::Wide),
            _ => None,
        }
    }

    /// Whether the virtual receiver reads packets on the gapped schedule, which leaves
    /// the vertical blanking interval empty; the others read them evenly across the frame.
    pub fn gapped(self) -> bool {
        self == Self::Narrow
    }
}

/// The range of code values, the `RANGE` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Range {
    /// `NARROW`: 16 to 235 at 8 bits, and the same fractions of other depths.
    #[default]
    Narrow,
    /// `FULLPROTECT`: every code value but the few at each end that SDI reserves.
    FullProtect,
    /// `FULL`: every code value.
    Full,
}

impl Range {
    /// The `RANGE` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Narrow => "NARROW",
            Self::FullProtect => "FULLPROTECT",
            Self::Full => "FULL",
        }
    }

    /// Reads a `RANGE` value.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "NARROW" => Some(Self::Narrow),
            "FULLPROTECT" => Some(Self::FullProtect),
            "FULL" => Some(Self::Full),
            _ => None,
        }
    }
}

/// How a frame's rows are sent (ST 2110-20:2022 §6.1.2–6.1.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scan {
    /// Progressive: the whole frame at one instant, its rows from the top.
    #[default]
    Progressive,
    /// Interlaced (`interlace`): two fields half a frame apart, each with its own RTP
    /// timestamp and marker bit, the first with the frame's even rows and the second,
    /// whose row headers have the F bit set, with its odd ones.
    Interlaced,
    /// Progressive segmented frame (`interlace; segmented`): a progressive frame sent as
    /// two segments, rows split as an interlaced frame's are, that share its timestamp.
    Segmented,
}

impl Scan {
    /// Whether frames go as two fields or segments.
    pub fn fields(self) -> bool {
        self != Self::Progressive
    }

    /// The letter of a format name: `p`, `i` or `psf`.
    pub fn letter(self) -> &'static str {
        match self {
            Self::Progressive => "p",
            Self::Interlaced => "i",
            Self::Segmented => "psf",
        }
    }
}

/// An ST 2110-20 video format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoFormat {
    /// Pixels per row.
    pub width: u32,
    /// Rows per frame: of both fields, for interlaced and PsF video.
    pub height: u32,
    /// Frames per second, `exactframerate`: for interlaced video, half the fields.
    pub rate: Rational,
    /// Progressive, interlaced or PsF.
    pub scan: Scan,
    /// `sampling`.
    pub sampling: Sampling,
    /// `depth`: bits per sample.
    pub depth: Depth,
    /// `colorimetry`, one of [`COLORIMETRY`].
    pub colorimetry: String,
    /// `TCS`, one of [`TRANSFER`].
    pub transfer: String,
    /// `RANGE`.
    pub range: Range,
    /// `PM`.
    pub packing: Packing,
    /// `TP`.
    pub sender_type: SenderType,
}

impl VideoFormat {
    /// A format of this size and rate, in the most common form: YCbCr-4:2:2 at 10 bits,
    /// BT.709 SDR in the narrow range, general packing, and a wide sender.
    pub fn new(width: u32, height: u32, rate: Rational) -> Self {
        Self {
            width,
            height,
            rate,
            scan: Scan::Progressive,
            sampling: Sampling::YCbCr422,
            depth: Depth::Bits10,
            colorimetry: "BT709".into(),
            transfer: "SDR".into(),
            range: Range::Narrow,
            packing: Packing::General,
            sender_type: SenderType::Wide,
        }
    }

    /// Reads a format name: `1080p50`, `2160p59.94` or `720p60000/1001` for the usual
    /// widths of 1080, 2160, 4320, 720, 576 and 486-line video, or `1280x720p25` for any
    /// size. `1080i50` is interlaced, named by its fields a second as is usual, and
    /// `1080psf25` PsF, named by its frames. Gives YCbCr-4:2:2 at 10 bits, as
    /// [`VideoFormat::new`] does.
    pub fn from_name(name: &str) -> Result<Self, String> {
        let bad = || format!("{name} is not a format such as 1080p50, 1080i59.94, 1080psf25 or 1280x720p25");
        let lower = name.to_ascii_lowercase();
        let (scan, at, letters) = if let Some(at) = lower.find("psf") {
            (Scan::Segmented, at, 3)
        } else if let Some(at) = lower.find('i') {
            (Scan::Interlaced, at, 1)
        } else {
            (Scan::Progressive, lower.find('p').ok_or_else(bad)?, 1)
        };
        let (size, rate) = (&name[..at], &name[at + letters..]);
        let (width, height) = match size.split_once(['x', 'X']) {
            Some((w, h)) => (w.parse().map_err(|_| bad())?, h.parse().map_err(|_| bad())?),
            None => {
                let height: u32 = size.parse().map_err(|_| bad())?;
                let width = match height {
                    486 | 576 => 720,
                    720 => 1280,
                    1080 => 1920,
                    2160 => 3840,
                    4320 => 7680,
                    _ => {
                        return Err(format!("{name}: give the width too for {height} lines, such as 1024x{height}p25"));
                    }
                };
                (width, height)
            }
        };
        let rate = match parse_frame_rate(rate) {
            Ok((rate, _)) => rate,
            Err(FrameRateError::Decimal(Some(rate))) => rate,
            Err(_) => return Err(bad()),
        };
        let rate = match scan {
            Scan::Interlaced => Rational::new(rate.numerator(), 2 * rate.denominator()).ok_or_else(bad)?,
            _ => rate,
        };
        let format = Self { scan, ..Self::new(width, height, rate) };
        format.check()?;
        Ok(format)
    }

    /// Rows in each field, the first then the second: half the frame's each, and for an
    /// odd height one more in the first; the whole frame for progressive video.
    pub fn field_heights(&self) -> [u32; 2] {
        if self.scan.fields() { [self.height.div_ceil(2), self.height / 2] } else { [self.height, 0] }
    }

    /// The rate of fields, twice the frame rate; of frames for progressive video.
    pub fn field_rate(&self) -> Rational {
        match self.scan {
            Scan::Progressive => self.rate,
            _ => Rational::new(2 * self.rate.numerator(), self.rate.denominator()).expect("not zero"),
        }
    }

    /// The pixel group, when ST 2110-20 defines one for the sampling and depth.
    pub fn pixel_group(&self) -> Option<PixelGroup> {
        pixel_group(self.sampling, self.depth)
    }

    /// Rows of the picture that one row of pixel groups covers: 2 for the 4:2:0
    /// samplings, whose pixel groups take two pixels from each of two rows (ST 2110-20
    /// Table 3), and 1 for the others.
    pub fn group_rows(&self) -> u32 {
        match self.sampling {
            Sampling::YCbCr420 | Sampling::ClYCbCr420 | Sampling::ICtCp420 => 2,
            _ => 1,
        }
    }

    /// Octets of one row of pixel groups: of a pair of rows for 4:2:0.
    pub fn row_bytes(&self) -> usize {
        self.pixel_group().map_or(0, |g| (self.width / (g.pixels / self.group_rows()) * g.octets) as usize)
    }

    /// Octets of one frame of pixel groups, rows one after another.
    pub fn frame_bytes(&self) -> usize {
        self.row_bytes() * (self.height / self.group_rows()) as usize
    }

    /// Bits per second of pixel data.
    pub fn bitrate(&self) -> f64 {
        self.frame_bytes() as f64 * 8.0 * self.rate.to_f64()
    }

    /// Says why this crate cannot send or receive the format, if it cannot.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=32767).contains(&self.width) || !(1..=32767).contains(&self.height) {
            return Err(format!("{}x{} is not a picture size from 1 to 32767 each way", self.width, self.height));
        }
        if self.rate.to_f64() > 1000.0 {
            return Err(format!("{} frames a second is more than this crate paces", self.rate));
        }
        if self.scan.fields() && self.height < 2 {
            return Err(format!("{} row is too few for two fields", self.height));
        }
        let Some(group) = self.pixel_group() else {
            return Err(format!("ST 2110-20 defines no pixel group for {} at {}", self.sampling, self.depth_name()));
        };
        let rows = self.group_rows();
        let across = group.pixels / rows;
        if !self.width.is_multiple_of(across) {
            let across = if rows == 1 { format!("{across} pixels") } else { format!("{across} pixels across") };
            return Err(format!(
                "{} pixels is not a whole number of {} {} pixel groups of {across}",
                self.width,
                self.sampling,
                self.depth_name()
            ));
        }
        if !self.height.is_multiple_of(rows) {
            return Err(format!("{} rows is not a whole number of the row pairs {} takes", self.height, self.sampling));
        }
        if rows > 1 && self.scan.fields() {
            return Err(format!(
                "{} is sent progressive only: its pixel groups pair rows that interlaced and PsF video send in different fields",
                self.sampling
            ));
        }
        if !COLORIMETRY.contains(&self.colorimetry.as_str()) {
            return Err(format!("colorimetry {} is not one of {}", self.colorimetry, COLORIMETRY.join(", ")));
        }
        if !TRANSFER.contains(&self.transfer.as_str()) {
            return Err(format!("TCS {} is not one of {}", self.transfer, TRANSFER.join(", ")));
        }
        if self.range == Range::FullProtect && self.colorimetry == "BT2100" {
            return Err("RANGE=FULLPROTECT is not allowed with BT2100 colorimetry".into());
        }
        if self.packing == Packing::Block {
            // Blocks of 180 octets hold whole pixel groups only when the groups divide 180.
            if 180 % group.octets != 0 {
                return Err(format!(
                    "block packing needs pixel groups that divide its 180-octet blocks, not {} octets",
                    group.octets
                ));
            }
            if self.row_bytes() < 90 {
                return Err(format!("rows of {} octets are too short for block packing", self.row_bytes()));
            }
        }
        Ok(())
    }

    /// The depth in words: `10-bit`, or `16-bit float`.
    pub fn depth_name(&self) -> String {
        match self.depth {
            Depth::Bits16Float => "16-bit float".into(),
            depth => format!("{depth}-bit"),
        }
    }

    /// The edition `SSN` names: the 2022 edition only for what it added, a key's
    /// `ALPHA` colorimetry and the `ST2115LOGS3` transfer (ST 2110-20:2022 §7.2).
    pub fn ssn(&self) -> &'static str {
        if self.colorimetry == "ALPHA" || self.transfer == "ST2115LOGS3" { "ST2110-20:2022" } else { "ST2110-20:2017" }
    }

    /// The `a=fmtp` parameters, in the order ST 2110-20's examples write them.
    pub fn fmtp(&self) -> String {
        let mut text = format!(
            "sampling={}; width={}; height={}; exactframerate={}; depth={}; TCS={}; colorimetry={}; PM={}; SSN={}; TP={};",
            self.sampling,
            self.width,
            self.height,
            self.rate,
            self.depth,
            self.transfer,
            self.colorimetry,
            self.packing.as_str(),
            self.ssn(),
            self.sender_type.as_str()
        );
        if self.range != Range::Narrow {
            text.push_str(&format!(" RANGE={};", self.range.as_str()));
        }
        // 525- and 625-line video signals its pixels' shape, here for a 4:3 picture
        // (RP 2110-24:2023 §5).
        let rate = (self.rate.numerator(), self.rate.denominator());
        match (self.scan.fields() && self.width == 720, rate) {
            (true, (30_000, 1001)) if self.height <= 512 => text.push_str(" PAR=10:11;"),
            (true, (25, 1)) if self.height <= 612 => text.push_str(" PAR=12:11;"),
            _ => {}
        }
        match self.scan {
            Scan::Progressive => {}
            Scan::Interlaced => text.push_str(" interlace;"),
            Scan::Segmented => text.push_str(" interlace; segmented;"),
        }
        text
    }

    /// Reads the format from an SDP file's `a=fmtp` parameters: `value` gives a
    /// parameter's value, and `has` says whether it is there at all, as a flag such as
    /// `interlace` is.
    pub fn from_fmtp(value: impl Fn(&str) -> Option<String>, has: impl Fn(&str) -> bool) -> Result<Self, String> {
        let need = |name: &str| value(name).ok_or_else(|| format!("the SDP file gives no {name}"));
        let scan = match (has("interlace"), has("segmented")) {
            (false, false) => Scan::Progressive,
            (true, false) => Scan::Interlaced,
            (true, true) => Scan::Segmented,
            (false, true) => return Err("segmented without interlace: PsF is signalled with both".into()),
        };
        let number = |name: &str| -> Result<u32, String> {
            let text = need(name)?;
            text.trim().parse().map_err(|_| format!("{name}={text} is not a number"))
        };
        let sampling = need("sampling")?;
        let depth = need("depth")?;
        let rate = need("exactframerate")?;
        let format = Self {
            width: number("width")?,
            height: number("height")?,
            rate: match parse_frame_rate(&rate) {
                Ok((rate, _)) | Err(FrameRateError::Decimal(Some(rate))) => rate,
                Err(_) => return Err(format!("exactframerate={rate} is not a frame rate")),
            },
            scan,
            sampling: sampling
                .trim()
                .parse()
                .map_err(|()| format!("sampling={sampling} is not an ST 2110-20 sampling"))?,
            depth: depth.trim().parse().map_err(|()| format!("depth={depth} is not an ST 2110-20 depth"))?,
            colorimetry: value("colorimetry").unwrap_or_else(|| "UNSPECIFIED".into()),
            transfer: value("TCS").unwrap_or_else(|| "SDR".into()),
            range: match value("RANGE") {
                None => Range::Narrow,
                Some(text) => Range::parse(text.trim()).ok_or_else(|| format!("RANGE={text} is not a range"))?,
            },
            packing: match value("PM").as_deref().map(str::trim) {
                Some("2110BPM") => Packing::Block,
                _ => Packing::General,
            },
            sender_type: value("TP").as_deref().and_then(SenderType::parse).unwrap_or_default(),
        };
        format.check()?;
        Ok(format)
    }
}

impl fmt::Display for VideoFormat {
    /// `1920x1080p50 YCbCr-4:2:2 10-bit`, with interlaced video named by its fields a
    /// second, `1920x1080i50`, and PsF by its frames, `1920x1080psf25`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rate = if self.scan == Scan::Interlaced { self.field_rate() } else { self.rate };
        let rate = if rate.is_integer() { rate.to_string() } else { format!("{:.2}", rate.to_f64()) };
        let (width, height, scan) = (self.width, self.height, self.scan.letter());
        write!(f, "{width}x{height}{scan}{rate} {} {}", self.sampling, self.depth_name())
    }
}

/// An ST 2110-30 PCM audio format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioFormat {
    /// Channels, 1 to 64.
    pub channels: u16,
    /// Samples per second: 48 000, 96 000 or 44 100.
    pub sample_rate: u32,
    /// Bits per sample: 24 (`L24`) or 16 (`L16`).
    pub bits: u8,
    /// Samples per channel in each packet: 48 for the 1 ms packets of level A at 48 kHz,
    /// or 6 for the 125 µs of levels B and C.
    pub samples_per_packet: u32,
}

impl AudioFormat {
    /// Level A: 48 kHz, 24 bits, 1 ms packets.
    pub fn new(channels: u16) -> Self {
        Self { channels, sample_rate: 48_000, bits: 24, samples_per_packet: 48 }
    }

    /// The format with packets of `ms` milliseconds, which must come within 1% of a
    /// whole number of samples: at 44.1 kHz, 1 ms is 44 samples and 1.09 ms is 48.
    pub fn with_packet_time(mut self, ms: f64) -> Result<Self, String> {
        check_rate(self.sample_rate)?;
        let khz = f64::from(self.sample_rate) / 1000.0;
        let exact = khz * ms;
        let samples = exact.round();
        if !(1.0..=1e6).contains(&samples) || ((samples - exact) / exact).abs() > 0.01 {
            let fewer = exact.floor().max(1.0);
            return Err(format!(
                "{ms} ms is {exact:.2} samples at {khz} kHz: give a whole number of samples, such as {:.3} or {:.3} ms",
                fewer / khz,
                (fewer + 1.0) / khz
            ));
        }
        self.samples_per_packet = samples as u32;
        self.check()?;
        Ok(self)
    }

    /// Seconds of audio in each packet.
    pub fn packet_time(&self) -> f64 {
        f64::from(self.samples_per_packet) / f64::from(self.sample_rate)
    }

    /// Octets per sample.
    pub fn sample_bytes(&self) -> usize {
        usize::from(self.bits / 8)
    }

    /// Octets of samples in each packet.
    pub fn payload_bytes(&self) -> usize {
        self.samples_per_packet as usize * usize::from(self.channels) * self.sample_bytes()
    }

    /// The `a=rtpmap` encoding: `L24` or `L16`.
    pub fn encoding(&self) -> &'static str {
        if self.bits == 16 { "L16" } else { "L24" }
    }

    /// The `a=ptime` value in milliseconds: exact when the packet time is a whole number
    /// of microseconds, `1` or `0.125`, and otherwise the shortest within 1% that gives
    /// back the samples when a receiver rounds, such as `1.09` for 48 samples at 44.1 kHz.
    pub fn ptime(&self) -> String {
        let trim = |text: String| {
            if text.contains('.') { text.trim_end_matches('0').trim_end_matches('.').to_string() } else { text }
        };
        let (samples, rate) = (u64::from(self.samples_per_packet), u64::from(self.sample_rate));
        if (samples * 1_000_000).is_multiple_of(rate) {
            let us = samples * 1_000_000 / rate;
            return trim(format!("{}.{:03}", us / 1000, us % 1000));
        }
        let ms = self.packet_time() * 1000.0;
        (0..=6)
            .map(|decimals| format!("{ms:.decimals$}"))
            .find(|text| {
                text.parse().is_ok_and(|v: f64| {
                    ((v - ms) / ms).abs() <= 0.01 && samples_in(self.sample_rate, v) == self.samples_per_packet
                })
            })
            .map_or_else(|| format!("{ms}"), trim)
    }

    /// The `channel-order` value: mono, stereo or undefined channels.
    pub fn channel_order(&self) -> String {
        match self.channels {
            1 => "SMPTE2110.(M)".into(),
            2 => "SMPTE2110.(ST)".into(),
            n => format!("SMPTE2110.(U{n:02})"),
        }
    }

    /// Says why this crate cannot send or receive the format, if it cannot.
    pub fn check(&self) -> Result<(), String> {
        if !(1..=64).contains(&self.channels) {
            return Err(format!("{} channels is not 1 to 64", self.channels));
        }
        check_rate(self.sample_rate)?;
        if self.bits != 16 && self.bits != 24 {
            return Err(format!("{}-bit samples are not 16 or 24 bits", self.bits));
        }
        if self.samples_per_packet == 0 || u64::from(self.samples_per_packet) * 250 > u64::from(self.sample_rate) {
            return Err(format!(
                "{} samples a packet is not a packet time up to 4 ms at {} Hz",
                self.samples_per_packet, self.sample_rate
            ));
        }
        if self.payload_bytes() > PAYLOAD_LIMIT {
            return Err(format!(
                "{} channels of {} ms make {} octets a packet, over the {PAYLOAD_LIMIT} the standard UDP size limit allows; use 0.125 ms packets",
                self.channels,
                self.ptime(),
                self.payload_bytes()
            ));
        }
        Ok(())
    }
}

/// Samples in a packet of `ms` milliseconds at `sample_rate`, rounded, as a receiver
/// reads `a=ptime`.
pub fn samples_in(sample_rate: u32, ms: f64) -> u32 {
    st2110_sdp::audio::samples_per_packet(sample_rate, ms)
}

impl fmt::Display for AudioFormat {
    /// `L24 48 kHz, 2 channels, 1 ms`, or `125 µs` for packets shorter than 1 ms.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let khz = f64::from(self.sample_rate) / 1000.0;
        let channels = if self.channels == 1 { "1 channel".to_string() } else { format!("{} channels", self.channels) };
        let us = self.packet_time() * 1e6;
        let time = if us >= 999.5 {
            format!("{} ms", self.ptime())
        } else if (us - us.round()).abs() < 1e-6 {
            format!("{us:.0} µs")
        } else {
            format!("{us:.1} µs")
        };
        write!(f, "{} {khz} kHz, {channels}, {time}", self.encoding())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(num: u64, den: u64) -> Rational {
        Rational::new(num, den).unwrap()
    }

    #[test]
    fn names() {
        let f = VideoFormat::from_name("1080p50").unwrap();
        assert_eq!((f.width, f.height, f.rate), (1920, 1080, rate(50, 1)));
        assert_eq!(f.row_bytes(), 4800);
        assert_eq!(f.frame_bytes(), 5_184_000);
        let f = VideoFormat::from_name("2160p59.94").unwrap();
        assert_eq!((f.width, f.height, f.rate), (3840, 2160, rate(60000, 1001)));
        let f = VideoFormat::from_name("640x360p30000/1001").unwrap();
        assert_eq!((f.width, f.height, f.rate), (640, 360, rate(30000, 1001)));
        assert_eq!(f.to_string(), "640x360p29.97 YCbCr-4:2:2 10-bit");
        assert!(VideoFormat::from_name("1080x50").unwrap_err().contains("not a format"));
        assert!(VideoFormat::from_name("600p50").unwrap_err().contains("give the width"));
        assert!(VideoFormat::from_name("641x360p25").unwrap_err().contains("pixel groups of 2 pixels"));
    }

    #[test]
    fn interlaced_and_psf_names() {
        // Interlaced video is named by its fields a second, and carries frames half as often.
        let f = VideoFormat::from_name("1080i59.94").unwrap();
        assert_eq!((f.width, f.height, f.rate, f.scan), (1920, 1080, rate(30000, 1001), Scan::Interlaced));
        assert_eq!((f.field_heights(), f.field_rate()), ([540, 540], rate(60000, 1001)));
        assert_eq!(f.to_string(), "1920x1080i59.94 YCbCr-4:2:2 10-bit");
        assert!(f.fmtp().contains("height=1080; exactframerate=30000/1001;"));
        let f = VideoFormat::from_name("1080PsF25").unwrap();
        assert_eq!(
            (f.rate, f.scan, f.to_string()),
            (rate(25, 1), Scan::Segmented, "1920x1080psf25 YCbCr-4:2:2 10-bit".into())
        );
        let f = VideoFormat::from_name("720x487i59.94").unwrap();
        assert_eq!(f.field_heights(), [244, 243]);
        let f = VideoFormat::from_name("576i50").unwrap();
        assert_eq!(f.width, 720);
        assert!(f.fmtp().ends_with(" PAR=12:11; interlace;"));
        let mut f = VideoFormat::from_name("1080i50").unwrap();
        f.sampling = Sampling::YCbCr420;
        assert!(f.check().unwrap_err().contains("progressive only"));
    }

    #[test]
    fn four_two_zero_and_floating_point() {
        let mut f = VideoFormat::from_name("1080p50").unwrap();
        f.sampling = Sampling::YCbCr420;
        // Pairs of rows of 480 pixel groups of 15 octets, 8 pixels each.
        assert_eq!((f.group_rows(), f.row_bytes(), f.frame_bytes()), (2, 7200, 3_888_000));
        f.width = 1922;
        assert!(f.check().unwrap_err().contains("pixel groups of 4 pixels across"), "{:?}", f.check());
        f.depth = Depth::Bits16;
        assert!(f.check().unwrap_err().contains("no pixel group for YCbCr-4:2:0 at 16-bit"));
        let mut f = VideoFormat::from_name("640x360p25").unwrap();
        (f.sampling, f.depth) = (Sampling::Rgb, Depth::Bits16Float);
        assert_eq!((f.row_bytes(), f.to_string()), (3840, "640x360p25 RGB 16-bit float".to_string()));
        assert!(f.fmtp().contains("sampling=RGB; width=640; height=360; exactframerate=25; depth=16f;"));
    }

    #[test]
    fn fmtp_round_trips() {
        let mut f = VideoFormat::new(1280, 720, rate(50, 1));
        f.range = Range::Full;
        f.packing = Packing::Block;
        f.sender_type = SenderType::Narrow;
        let text = f.fmtp();
        assert_eq!(
            text,
            "sampling=YCbCr-4:2:2; width=1280; height=720; exactframerate=50; depth=10; TCS=SDR; colorimetry=BT709; \
             PM=2110BPM; SSN=ST2110-20:2017; TP=2110TPN; RANGE=FULL;"
        );
        let (fmtp, _) = st2110_sdp::Fmtp::parse(&text);
        let back = VideoFormat::from_fmtp(|name| fmtp.value(name).map(str::to_string), |name| fmtp.has(name)).unwrap();
        assert_eq!(back, f);
        for (flags, scan) in [(" interlace;", Scan::Interlaced), (" interlace; segmented;", Scan::Segmented)] {
            let interlaced = VideoFormat { scan, ..f.clone() };
            assert!(interlaced.fmtp().ends_with(flags));
            let (fmtp, _) = st2110_sdp::Fmtp::parse(&interlaced.fmtp());
            let read = VideoFormat::from_fmtp(|name| fmtp.value(name).map(str::to_string), |name| fmtp.has(name));
            assert_eq!(read.unwrap(), interlaced);
        }
        let (fmtp, _) = st2110_sdp::Fmtp::parse(&format!("{text} segmented;"));
        let read = VideoFormat::from_fmtp(|name| fmtp.value(name).map(str::to_string), |name| fmtp.has(name));
        assert!(read.unwrap_err().contains("segmented without interlace"));
        let mut key = f.clone();
        key.sampling = Sampling::Key;
        key.colorimetry = "ALPHA".into();
        assert_eq!(key.ssn(), "ST2110-20:2022");
    }

    #[test]
    fn audio() {
        let a = AudioFormat::new(2);
        assert_eq!((a.samples_per_packet, a.payload_bytes(), a.ptime()), (48, 288, "1".to_string()));
        assert_eq!(a.to_string(), "L24 48 kHz, 2 channels, 1 ms");
        let c = AudioFormat::new(64).with_packet_time(0.125).unwrap();
        assert_eq!((c.samples_per_packet, c.payload_bytes(), c.ptime()), (6, 1152, "0.125".to_string()));
        assert_eq!(c.to_string(), "L24 48 kHz, 64 channels, 125 µs");
        assert_eq!(c.channel_order(), "SMPTE2110.(U64)");
        assert!(AudioFormat::new(16).check().unwrap_err().contains("use 0.125 ms packets"));
        let e = AudioFormat::new(2).with_packet_time(0.3).unwrap_err();
        assert!(e.contains("0.3 ms is 14.40 samples at 48 kHz") && e.contains("such as 0.292 or 0.312 ms"), "{e}");
        let f = AudioFormat::new(2).with_packet_time(0.292).unwrap();
        assert_eq!((f.samples_per_packet, f.ptime()), (14, "0.29".to_string()));
        assert!(AudioFormat::new(2).with_packet_time(5.0).unwrap_err().contains("up to 4 ms"));
    }

    #[test]
    fn audio_at_44_1_khz() {
        let base = AudioFormat { sample_rate: 44_100, ..AudioFormat::new(2) };
        // 1 ms is 44 samples, which a receiver rounding ptime=1 finds again.
        let one = base.clone().with_packet_time(1.0).unwrap();
        assert_eq!((one.samples_per_packet, one.ptime()), (44, "1".to_string()));
        assert_eq!(one.to_string(), "L24 44.1 kHz, 2 channels, 997.7 µs");
        // 48 samples, as ST 2110-31 writes it.
        let long = base.clone().with_packet_time(1.09).unwrap();
        assert_eq!((long.samples_per_packet, long.ptime()), (48, "1.09".to_string()));
        assert_eq!(long.to_string(), "L24 44.1 kHz, 2 channels, 1.09 ms");
        assert!(base.with_packet_time(0.125).is_err());
        for (rate, samples) in [(44_100, 6), (44_100, 12), (96_000, 12), (96_000, 96), (48_000, 1), (48_000, 192)] {
            let f = AudioFormat { sample_rate: rate, samples_per_packet: samples, ..AudioFormat::new(1) };
            assert_eq!(samples_in(rate, f.ptime().parse().unwrap()), samples, "{rate} {samples} {}", f.ptime());
        }
    }
}
