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

/// An ST 2110-20 video format. Only progressive video: interlaced and PsF video, and
/// the 4:2:0 samplings, whose rows go in pairs, are not supported yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoFormat {
    /// Pixels per row.
    pub width: u32,
    /// Rows per frame.
    pub height: u32,
    /// Frames per second, `exactframerate`.
    pub rate: Rational,
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
    /// widths of 1080, 2160, 4320 and 720-line video, or `1280x720p25` for any size.
    /// Gives YCbCr-4:2:2 at 10 bits, as [`VideoFormat::new`] does.
    pub fn from_name(name: &str) -> Result<Self, String> {
        let bad = || format!("{name} is not a format such as 1080p50, 2160p59.94 or 1280x720p25");
        let (size, rate) = name.split_once(['p', 'P']).ok_or_else(bad)?;
        let (width, height) = match size.split_once(['x', 'X']) {
            Some((w, h)) => (w.parse().map_err(|_| bad())?, h.parse().map_err(|_| bad())?),
            None => {
                let height: u32 = size.parse().map_err(|_| bad())?;
                let width = match height {
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
        let format = Self::new(width, height, rate);
        format.check()?;
        Ok(format)
    }

    /// The pixel group, when ST 2110-20 defines one for the sampling and depth.
    pub fn pixel_group(&self) -> Option<PixelGroup> {
        pixel_group(self.sampling, self.depth)
    }

    /// Octets of one row of pixel groups.
    pub fn row_bytes(&self) -> usize {
        self.pixel_group().map_or(0, |g| (self.width / g.pixels * g.octets) as usize)
    }

    /// Octets of one frame of pixel groups, rows one after another.
    pub fn frame_bytes(&self) -> usize {
        self.row_bytes() * self.height as usize
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
        let unsupported = |what: &str| Err(format!("{what} is not supported yet"));
        match self.sampling {
            Sampling::YCbCr420 | Sampling::ClYCbCr420 | Sampling::ICtCp420 => {
                return unsupported(&format!("{} sampling", self.sampling));
            }
            _ => {}
        }
        if self.depth == Depth::Bits16Float {
            return unsupported("16-bit floating point");
        }
        let Some(group) = self.pixel_group() else {
            return Err(format!("ST 2110-20 defines no pixel group for {} at {} bits", self.sampling, self.depth));
        };
        if !self.width.is_multiple_of(group.pixels) {
            return Err(format!(
                "{} pixels is not a whole number of {} {}-bit pixel groups of {} pixels",
                self.width, self.sampling, self.depth, group.pixels
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
        text
    }

    /// Reads the format from an SDP file's `a=fmtp` parameters.
    pub fn from_fmtp(value: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let need = |name: &str| value(name).ok_or_else(|| format!("the SDP file gives no {name}"));
        if value("interlace").is_some() {
            return Err("interlaced and PsF video are not supported yet".into());
        }
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
    /// `1920x1080p50 YCbCr-4:2:2 10-bit`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rate = if self.rate.is_integer() { self.rate.to_string() } else { format!("{:.2}", self.rate.to_f64()) };
        write!(f, "{}x{}p{} {} {}-bit", self.width, self.height, rate, self.sampling, self.depth)
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
    /// Microseconds of audio in each packet: 1000, or 125 for the short packets of
    /// levels B and C.
    pub packet_time_us: u32,
}

impl AudioFormat {
    /// Level A: 48 kHz, 24 bits, 1 ms packets.
    pub fn new(channels: u16) -> Self {
        Self { channels, sample_rate: 48_000, bits: 24, packet_time_us: 1000 }
    }

    /// Samples per channel in each packet.
    pub fn samples_per_packet(&self) -> u32 {
        (u64::from(self.sample_rate) * u64::from(self.packet_time_us) / 1_000_000) as u32
    }

    /// Octets per sample.
    pub fn sample_bytes(&self) -> usize {
        usize::from(self.bits / 8)
    }

    /// Octets of samples in each packet.
    pub fn payload_bytes(&self) -> usize {
        self.samples_per_packet() as usize * usize::from(self.channels) * self.sample_bytes()
    }

    /// The `a=rtpmap` encoding: `L24` or `L16`.
    pub fn encoding(&self) -> &'static str {
        if self.bits == 16 { "L16" } else { "L24" }
    }

    /// The `a=ptime` value in milliseconds: `1` or `0.125`.
    pub fn ptime(&self) -> String {
        let ms = f64::from(self.packet_time_us) / 1000.0;
        format!("{ms}")
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
        if ![44_100, 48_000, 96_000].contains(&self.sample_rate) {
            return Err(format!("{} Hz is not 48 000, 96 000 or 44 100", self.sample_rate));
        }
        if self.bits != 16 && self.bits != 24 {
            return Err(format!("{}-bit samples are not 16 or 24 bits", self.bits));
        }
        if self.packet_time_us == 0
            || self.packet_time_us > 4000
            || u64::from(self.sample_rate) * u64::from(self.packet_time_us) % 1_000_000 != 0
        {
            return Err(format!(
                "{} µs is not a packet time up to 4 ms of whole samples at {} Hz",
                self.packet_time_us, self.sample_rate
            ));
        }
        if self.payload_bytes() > PAYLOAD_LIMIT {
            return Err(format!(
                "{} channels of {} µs make {} octets a packet, over the {PAYLOAD_LIMIT} the standard UDP size limit allows; use 125 µs packets",
                self.channels,
                self.packet_time_us,
                self.payload_bytes()
            ));
        }
        Ok(())
    }
}

impl fmt::Display for AudioFormat {
    /// `L24 48 kHz, 2 channels, 1 ms`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let khz = f64::from(self.sample_rate) / 1000.0;
        let channels = if self.channels == 1 { "1 channel".to_string() } else { format!("{} channels", self.channels) };
        let time = if self.packet_time_us.is_multiple_of(1000) {
            format!("{} ms", self.packet_time_us / 1000)
        } else {
            format!("{} µs", self.packet_time_us)
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
        assert!(VideoFormat::from_name("1080i50").unwrap_err().contains("not a format"));
        assert!(VideoFormat::from_name("576p50").unwrap_err().contains("give the width"));
        assert!(VideoFormat::from_name("641x360p25").unwrap_err().contains("pixel groups of 2 pixels"));
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
        let back = VideoFormat::from_fmtp(|name| fmtp.value(name).map(str::to_string)).unwrap();
        assert_eq!(back, f);
        let mut key = f.clone();
        key.sampling = Sampling::Key;
        key.colorimetry = "ALPHA".into();
        assert_eq!(key.ssn(), "ST2110-20:2022");
    }

    #[test]
    fn audio() {
        let a = AudioFormat::new(2);
        assert_eq!((a.samples_per_packet(), a.payload_bytes(), a.ptime()), (48, 288, "1".to_string()));
        assert_eq!(a.to_string(), "L24 48 kHz, 2 channels, 1 ms");
        let c = AudioFormat { channels: 64, packet_time_us: 125, ..AudioFormat::new(64) };
        assert_eq!((c.samples_per_packet(), c.payload_bytes(), c.ptime()), (6, 1152, "0.125".to_string()));
        assert_eq!(c.channel_order(), "SMPTE2110.(U64)");
        assert!(c.check().is_ok());
        assert!(AudioFormat::new(16).check().unwrap_err().contains("use 125 µs packets"));
        let odd = AudioFormat { sample_rate: 44_100, ..AudioFormat::new(2) };
        assert!(odd.check().unwrap_err().contains("whole samples"));
    }
}
