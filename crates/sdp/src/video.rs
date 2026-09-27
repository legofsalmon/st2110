//! ST 2110-20 video formats: pixel groups, data rates and ST 2110-21 read offsets.

use std::fmt;
use std::str::FromStr;

use crate::Rational;

/// A `sampling` value from ST 2110-20.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sampling {
    /// `YCbCr-4:4:4`
    YCbCr444,
    /// `YCbCr-4:2:2`
    YCbCr422,
    /// `YCbCr-4:2:0`
    YCbCr420,
    /// `CLYCbCr-4:4:4`
    ClYCbCr444,
    /// `CLYCbCr-4:2:2`
    ClYCbCr422,
    /// `CLYCbCr-4:2:0`
    ClYCbCr420,
    /// `ICtCp-4:4:4`
    ICtCp444,
    /// `ICtCp-4:2:2`
    ICtCp422,
    /// `ICtCp-4:2:0`
    ICtCp420,
    /// `RGB`
    Rgb,
    /// `XYZ`
    Xyz,
    /// `KEY`
    Key,
}

impl Sampling {
    /// Every value, in the order ST 2110-20 lists them.
    pub const ALL: [Self; 12] = [
        Self::YCbCr444,
        Self::YCbCr422,
        Self::YCbCr420,
        Self::ClYCbCr444,
        Self::ClYCbCr422,
        Self::ClYCbCr420,
        Self::ICtCp444,
        Self::ICtCp422,
        Self::ICtCp420,
        Self::Rgb,
        Self::Xyz,
        Self::Key,
    ];

    /// The SDP spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::YCbCr444 => "YCbCr-4:4:4",
            Self::YCbCr422 => "YCbCr-4:2:2",
            Self::YCbCr420 => "YCbCr-4:2:0",
            Self::ClYCbCr444 => "CLYCbCr-4:4:4",
            Self::ClYCbCr422 => "CLYCbCr-4:2:2",
            Self::ClYCbCr420 => "CLYCbCr-4:2:0",
            Self::ICtCp444 => "ICtCp-4:4:4",
            Self::ICtCp422 => "ICtCp-4:2:2",
            Self::ICtCp420 => "ICtCp-4:2:0",
            Self::Rgb => "RGB",
            Self::Xyz => "XYZ",
            Self::Key => "KEY",
        }
    }

    fn chroma(self) -> Chroma {
        match self {
            Self::YCbCr444 | Self::ClYCbCr444 | Self::ICtCp444 | Self::Rgb | Self::Xyz => Chroma::Full,
            Self::YCbCr422 | Self::ClYCbCr422 | Self::ICtCp422 => Chroma::Half,
            Self::YCbCr420 | Self::ClYCbCr420 | Self::ICtCp420 => Chroma::Quarter,
            Self::Key => Chroma::Key,
        }
    }
}

impl FromStr for Sampling {
    type Err = ();

    /// Parses the exact SDP spelling.
    fn from_str(text: &str) -> Result<Self, ()> {
        Self::ALL.into_iter().find(|s| s.as_str() == text).ok_or(())
    }
}

impl fmt::Display for Sampling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy)]
enum Chroma {
    Full,
    Half,
    Quarter,
    Key,
}

/// A `depth` value: bits per sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Depth {
    /// `8`
    Bits8,
    /// `10`
    Bits10,
    /// `12`
    Bits12,
    /// `16`
    Bits16,
    /// `16f`: 16-bit floating point.
    Bits16Float,
}

impl Depth {
    /// Every value.
    pub const ALL: [Self; 5] = [Self::Bits8, Self::Bits10, Self::Bits12, Self::Bits16, Self::Bits16Float];

    /// The SDP spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bits8 => "8",
            Self::Bits10 => "10",
            Self::Bits12 => "12",
            Self::Bits16 => "16",
            Self::Bits16Float => "16f",
        }
    }
}

impl FromStr for Depth {
    type Err = ();

    /// Parses the exact SDP spelling.
    fn from_str(text: &str) -> Result<Self, ()> {
        Self::ALL.into_iter().find(|d| d.as_str() == text).ok_or(())
    }
}

impl fmt::Display for Depth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The smallest unit ST 2110-20 packs samples in: `octets` bytes carry `pixels` pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelGroup {
    /// Bytes per pixel group.
    pub octets: u32,
    /// Pixels per pixel group.
    pub pixels: u32,
}

/// The pixel group for a sampling and depth (ST 2110-20 Tables 1 to 4); `None`
/// where the standard defines none (4:2:0 at 16 bits).
pub fn pixel_group(sampling: Sampling, depth: Depth) -> Option<PixelGroup> {
    use Chroma::*;
    use Depth::*;
    let (octets, pixels) = match (sampling.chroma(), depth) {
        (Half, Bits8) => (4, 2),
        (Half, Bits10) => (5, 2),
        (Half, Bits12) => (6, 2),
        (Half, Bits16 | Bits16Float) => (8, 2),
        (Full, Bits8) => (3, 1),
        (Full, Bits10) => (15, 4),
        (Full, Bits12) => (9, 2),
        (Full, Bits16 | Bits16Float) => (6, 1),
        (Quarter, Bits8) => (6, 4),
        (Quarter, Bits10) => (15, 8),
        (Quarter, Bits12) => (9, 4),
        (Quarter, Bits16 | Bits16Float) => return None,
        (Key, Bits8) => (1, 1),
        (Key, Bits10) => (5, 4),
        (Key, Bits12) => (3, 2),
        (Key, Bits16 | Bits16Float) => (2, 1),
    };
    Some(PixelGroup { octets, pixels })
}

/// Bits per second of picture data, before RTP, UDP and IP headers.
///
/// `height` is the frame height and `frame_rate` the frame rate, as in the SDP,
/// so the result is right for interlaced video too.
pub fn payload_bitrate(sampling: Sampling, depth: Depth, width: u32, height: u32, frame_rate: Rational) -> Option<f64> {
    let group = pixel_group(sampling, depth)?;
    let bits_per_frame = f64::from(width) * f64::from(height) * f64::from(group.octets * 8) / f64::from(group.pixels);
    Some(bits_per_frame * frame_rate.to_f64())
}

/// The ST 2110-21 default read offset (TRO_DEFAULT) for progressive video, in seconds:
/// 43/1125 of a frame for 1080 lines and more, 28/750 of a frame below (§6.3.2).
pub fn tro_default_progressive(height: u32, frame_rate: Rational) -> f64 {
    let frame = 1.0 / frame_rate.to_f64();
    if height >= 1080 { 43.0 / 1125.0 * frame } else { 28.0 / 750.0 * frame }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_round_trip() {
        for s in Sampling::ALL {
            assert_eq!(s.as_str().parse(), Ok(s));
        }
        for d in Depth::ALL {
            assert_eq!(d.as_str().parse(), Ok(d));
        }
        assert!("ycbcr-4:2:2".parse::<Sampling>().is_err());
    }

    #[test]
    fn bitrates() {
        let r50 = Rational::new(50, 1).unwrap();
        // 1080p50 4:2:2 10-bit: 1920 × 1080 × 20 bits × 50.
        let rate = payload_bitrate(Sampling::YCbCr422, Depth::Bits10, 1920, 1080, r50).unwrap();
        assert_eq!(rate, 2_073_600_000.0);
        let rate = payload_bitrate(Sampling::YCbCr420, Depth::Bits10, 1920, 1080, r50).unwrap();
        assert_eq!(rate, 1_555_200_000.0);
        assert!(payload_bitrate(Sampling::YCbCr420, Depth::Bits16, 1920, 1080, r50).is_none());
    }

    #[test]
    fn read_offsets() {
        let r5994 = Rational::new(60000, 1001).unwrap();
        let tro = tro_default_progressive(1080, r5994) * 1e6;
        assert!((tro - 637.7).abs() < 0.05, "{tro}");
        let tro = tro_default_progressive(720, r5994) * 1e6;
        assert!((tro - 622.8).abs() < 0.05, "{tro}");
    }
}
