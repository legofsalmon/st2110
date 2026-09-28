//! Pixels: 8-bit R'G'B' pictures to and from ST 2110-20 pixel groups.
//!
//! A frame is its rows of pixel groups one after another, as the packets carry them.
//! Samples sit in each group most significant bit first, in the order ST 2110-20 gives:
//! C'B, Y'0, C'R, Y'1 for 4:2:2; C'B, Y', C'R or R', G', B' for each pixel of 4:4:4; one
//! key sample per pixel for KEY.
//!
//! Conversions use the luma coefficients of the colorimetry (BT.601, BT.709, or
//! BT.2020 and BT.2100; BT.709 when it is unspecified) and the code values of the range.
//! 4:2:2 chroma is co-sited with the even pixels and filtered 1-2-1 on the way in, and
//! interpolated between them on the way out.

use st2110_sdp::video::{PixelGroup, Sampling};

use crate::format::{Range, VideoFormat};

/// What each pixel's samples are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ycc422,
    Ycc444,
    Rgb,
    Key,
}

/// Converts rows of 8-bit R'G'B' to and from one format's pixel groups.
#[derive(Clone, Debug)]
pub struct Converter {
    kind: Kind,
    bits: u32,
    group: PixelGroup,
    width: usize,
    /// Luma coefficients K_R and K_B.
    kr: f32,
    kb: f32,
    range: Range,
}

impl Converter {
    /// A converter for a format, or why there is none: this crate draws and reads
    /// YCbCr-4:2:2, YCbCr-4:4:4, RGB and KEY.
    pub fn new(format: &VideoFormat) -> Result<Self, String> {
        format.check()?;
        let kind = match format.sampling {
            Sampling::YCbCr422 => Kind::Ycc422,
            Sampling::YCbCr444 => Kind::Ycc444,
            Sampling::Rgb => Kind::Rgb,
            Sampling::Key => Kind::Key,
            other => return Err(format!("pictures cannot be converted to or from {other} yet")),
        };
        let (kr, kb) = match format.colorimetry.as_str() {
            "BT601" => (0.299, 0.114),
            "BT2020" | "BT2100" => (0.2627, 0.0593),
            _ => (0.2126, 0.0722),
        };
        let bits = format.depth.as_str().parse().expect("a whole number of bits");
        let group = format.pixel_group().expect("checked");
        Ok(Self { kind, bits, group, width: format.width as usize, kr, kb, range: format.range })
    }

    /// Octets of one row of pixel groups.
    pub fn row_bytes(&self) -> usize {
        self.width / self.group.pixels as usize * self.group.octets as usize
    }

    /// Packs one row of R'G'B' triplets, `3 × width` octets, into `out`.
    pub fn pack_row(&self, rgb: &[u8], out: &mut [u8]) {
        let samples = self.samples(rgb);
        let per_group = samples.len() / (self.width / self.group.pixels as usize);
        for (group, chunk) in out.chunks_exact_mut(self.group.octets as usize).zip(samples.chunks_exact(per_group)) {
            write_group(group, chunk, self.bits);
        }
    }

    /// Unpacks one row of pixel groups into R'G'B' triplets, `3 × width` octets.
    pub fn unpack_row(&self, row: &[u8], rgb: &mut [u8]) {
        let per_group = self.samples_per_group();
        let mut samples = vec![0u16; self.width / self.group.pixels as usize * per_group];
        for (group, chunk) in row.chunks_exact(self.group.octets as usize).zip(samples.chunks_exact_mut(per_group)) {
            read_group(group, chunk, self.bits);
        }
        self.to_rgb(&samples, rgb);
    }

    fn samples_per_group(&self) -> usize {
        let pixels = self.group.pixels as usize;
        match self.kind {
            Kind::Ycc422 => 4,
            Kind::Ycc444 | Kind::Rgb => 3 * pixels,
            Kind::Key => pixels,
        }
    }

    /// The code values for a row, in pixel group order.
    fn samples(&self, rgb: &[u8]) -> Vec<u16> {
        let w = self.width;
        let pixel = |x: usize| {
            let p = &rgb[3 * x..3 * x + 3];
            (f32::from(p[0]) / 255.0, f32::from(p[1]) / 255.0, f32::from(p[2]) / 255.0)
        };
        match self.kind {
            Kind::Rgb => (0..w)
                .flat_map(|x| {
                    let (r, g, b) = pixel(x);
                    [self.code(r), self.code(g), self.code(b)]
                })
                .collect(),
            Kind::Key => (0..w).map(|x| self.code(self.ycc(pixel(x)).0)).collect(),
            Kind::Ycc444 => (0..w)
                .flat_map(|x| {
                    let (y, cb, cr) = self.ycc(pixel(x));
                    [self.chroma(cb), self.code(y), self.chroma(cr)]
                })
                .collect(),
            Kind::Ycc422 => {
                let ycc: Vec<(f32, f32, f32)> = (0..w).map(|x| self.ycc(pixel(x))).collect();
                let mut out = Vec::with_capacity(2 * w);
                for x in (0..w).step_by(2) {
                    // Co-sited with pixel x, filtered 1-2-1 across its neighbours.
                    let (before, after) = (ycc[x.saturating_sub(1)], ycc[(x + 1).min(w - 1)]);
                    let cb = (before.1 + 2.0 * ycc[x].1 + after.1) / 4.0;
                    let cr = (before.2 + 2.0 * ycc[x].2 + after.2) / 4.0;
                    out.extend([self.chroma(cb), self.code(ycc[x].0), self.chroma(cr), self.code(ycc[x + 1].0)]);
                }
                out
            }
        }
    }

    fn to_rgb(&self, samples: &[u16], rgb: &mut [u8]) {
        let w = self.width;
        let mut put = |x: usize, (r, g, b): (f32, f32, f32)| {
            rgb[3 * x] = to_u8(r);
            rgb[3 * x + 1] = to_u8(g);
            rgb[3 * x + 2] = to_u8(b);
        };
        match self.kind {
            Kind::Rgb => {
                for x in 0..w {
                    let s = &samples[3 * x..3 * x + 3];
                    put(x, (self.value(s[0]), self.value(s[1]), self.value(s[2])));
                }
            }
            Kind::Key => {
                for (x, &sample) in samples.iter().enumerate().take(w) {
                    let k = self.value(sample);
                    put(x, (k, k, k));
                }
            }
            Kind::Ycc444 => {
                for x in 0..w {
                    let s = &samples[3 * x..3 * x + 3];
                    put(x, self.rgb(self.value(s[1]), self.chroma_value(s[0]), self.chroma_value(s[2])));
                }
            }
            Kind::Ycc422 => {
                let pairs = w / 2;
                let chroma = |i: usize| {
                    let s = &samples[4 * i..4 * i + 4];
                    (self.chroma_value(s[0]), self.chroma_value(s[2]))
                };
                for i in 0..pairs {
                    let s = &samples[4 * i..4 * i + 4];
                    let (cb, cr) = chroma(i);
                    put(2 * i, self.rgb(self.value(s[1]), cb, cr));
                    // The odd pixel's chroma lies halfway to the next pair's.
                    let (cb2, cr2) = if i + 1 < pairs { chroma(i + 1) } else { (cb, cr) };
                    put(2 * i + 1, self.rgb(self.value(s[3]), (cb + cb2) / 2.0, (cr + cr2) / 2.0));
                }
            }
        }
    }

    /// Y', C'B and C'R, with Y' from 0 to 1 and the colour differences from −½ to ½.
    fn ycc(&self, (r, g, b): (f32, f32, f32)) -> (f32, f32, f32) {
        let y = self.kr * r + (1.0 - self.kr - self.kb) * g + self.kb * b;
        (y, (b - y) / (2.0 * (1.0 - self.kb)), (r - y) / (2.0 * (1.0 - self.kr)))
    }

    fn rgb(&self, y: f32, cb: f32, cr: f32) -> (f32, f32, f32) {
        let r = y + 2.0 * (1.0 - self.kr) * cr;
        let b = y + 2.0 * (1.0 - self.kb) * cb;
        let g = (y - self.kr * r - self.kb * b) / (1.0 - self.kr - self.kb);
        (r, g, b)
    }

    /// The code value of a luma or R'G'B' value from 0 to 1.
    fn code(&self, v: f32) -> u16 {
        let top = ((1u32 << self.bits) - 1) as f32;
        let scale = (1u32 << (self.bits - 8)) as f32;
        let code = match self.range {
            Range::Narrow => (219.0 * v + 16.0) * scale,
            Range::Full | Range::FullProtect => v * top,
        };
        self.clamp(code.round())
    }

    /// The code value of a colour difference from −½ to ½.
    fn chroma(&self, c: f32) -> u16 {
        let top = ((1u32 << self.bits) - 1) as f32;
        let scale = (1u32 << (self.bits - 8)) as f32;
        let code = match self.range {
            Range::Narrow => (224.0 * c + 128.0) * scale,
            Range::Full | Range::FullProtect => c * top + (1u32 << (self.bits - 1)) as f32,
        };
        self.clamp(code.round())
    }

    fn value(&self, code: u16) -> f32 {
        let code = f32::from(code);
        let top = ((1u32 << self.bits) - 1) as f32;
        let scale = (1u32 << (self.bits - 8)) as f32;
        match self.range {
            Range::Narrow => (code / scale - 16.0) / 219.0,
            Range::Full | Range::FullProtect => code / top,
        }
    }

    fn chroma_value(&self, code: u16) -> f32 {
        let code = f32::from(code);
        let top = ((1u32 << self.bits) - 1) as f32;
        let scale = (1u32 << (self.bits - 8)) as f32;
        match self.range {
            Range::Narrow => (code / scale - 128.0) / 224.0,
            Range::Full | Range::FullProtect => (code - (1u32 << (self.bits - 1)) as f32) / top,
        }
    }

    /// Keeps a code value within the depth, and out of the codes SDI reserves: 0 and
    /// the top code at 8 bits, the four at each end at 10 bits, and so on. Only the
    /// full range may use them.
    fn clamp(&self, code: f32) -> u16 {
        let top = (1u32 << self.bits) - 1;
        let reserved = if self.range == Range::Full { 0 } else { 1u32 << (self.bits - 8) };
        code.clamp(reserved as f32, (top - reserved) as f32) as u16
    }
}

fn to_u8(v: f32) -> u8 {
    (v * 255.0).round().clamp(0.0, 255.0) as u8
}

/// Writes samples of `bits` each into a pixel group, most significant bit first.
fn write_group(group: &mut [u8], samples: &[u16], bits: u32) {
    let mut acc: u128 = 0;
    for &s in samples {
        acc = (acc << bits) | u128::from(s);
    }
    let bytes = acc.to_be_bytes();
    group.copy_from_slice(&bytes[16 - group.len()..]);
}

/// Reads samples of `bits` each from a pixel group, most significant bit first.
fn read_group(group: &[u8], samples: &mut [u16], bits: u32) {
    let mut bytes = [0u8; 16];
    bytes[16 - group.len()..].copy_from_slice(group);
    let acc = u128::from_be_bytes(bytes);
    let mask = (1u128 << bits) - 1;
    let n = samples.len();
    for (i, s) in samples.iter_mut().enumerate() {
        *s = ((acc >> (bits as usize * (n - 1 - i))) & mask) as u16;
    }
}

/// Packs a picture of `width × height` R'G'B' triplets into a frame of pixel groups.
pub fn from_rgb(format: &VideoFormat, rgb: &[u8]) -> Result<Vec<u8>, String> {
    let converter = Converter::new(format)?;
    let (w, h) = (format.width as usize, format.height as usize);
    if rgb.len() != 3 * w * h {
        return Err(format!("{} octets is not a {w}x{h} R'G'B' picture of {} octets", rgb.len(), 3 * w * h));
    }
    let row = converter.row_bytes();
    let mut frame = vec![0; row * h];
    for (out, input) in frame.chunks_exact_mut(row).zip(rgb.chunks_exact(3 * w)) {
        converter.pack_row(input, out);
    }
    Ok(frame)
}

/// Unpacks a frame of pixel groups into `width × height` R'G'B' triplets.
pub fn to_rgb(format: &VideoFormat, frame: &[u8]) -> Result<Vec<u8>, String> {
    let converter = Converter::new(format)?;
    let (w, h) = (format.width as usize, format.height as usize);
    let row = converter.row_bytes();
    if frame.len() != row * h {
        return Err(format!("{} octets is not a frame of {} octets", frame.len(), row * h));
    }
    let mut rgb = vec![0; 3 * w * h];
    for (input, out) in frame.chunks_exact(row).zip(rgb.chunks_exact_mut(3 * w)) {
        converter.unpack_row(input, out);
    }
    Ok(rgb)
}

#[cfg(test)]
mod tests {
    use st2110_sdp::Rational;
    use st2110_sdp::video::Depth;

    use super::*;

    fn format(sampling: Sampling, depth: Depth) -> VideoFormat {
        let mut f = VideoFormat::new(16, 2, Rational::new(25, 1).unwrap());
        f.sampling = sampling;
        f.depth = depth;
        f
    }

    #[test]
    fn packs_bits_most_significant_first() {
        let mut group = [0u8; 5];
        write_group(&mut group, &[0x200, 0x040, 0x3AC, 0x3FF], 10);
        assert_eq!(group, [0x80, 0x04, 0x0E, 0xB3, 0xFF]);
        let mut back = [0u16; 4];
        read_group(&group, &mut back, 10);
        assert_eq!(back, [0x200, 0x040, 0x3AC, 0x3FF]);
    }

    #[test]
    fn narrow_range_code_values() {
        // 75% yellow, R'G'B' 191 191 0, in BT.709 10-bit 4:2:2: Y' = 0.9278 × 191/255 gives
        // (219 Y' + 16) × 4 = 673, C'B = −Y'/1.8556 gives 176 and C'R = (R' − Y')/1.5748 gives
        // 543, the values of RP 219's 75% bars to within a code.
        let f = format(Sampling::YCbCr422, Depth::Bits10);
        let c = Converter::new(&f).unwrap();
        let rgb: Vec<u8> = (0..16).flat_map(|_| [191, 191, 0]).collect();
        let mut row = vec![0; c.row_bytes()];
        c.pack_row(&rgb, &mut row);
        let mut samples = [0u16; 4];
        read_group(&row[..5], &mut samples, 10);
        assert_eq!(samples, [176, 673, 543, 673]);
        // White and black.
        let mut white = vec![0; c.row_bytes()];
        c.pack_row(&[255; 48], &mut white);
        read_group(&white[..5], &mut samples, 10);
        assert_eq!(samples, [512, 940, 512, 940]);
    }

    #[test]
    fn round_trips_within_a_code() {
        let rgb: Vec<u8> = (0..32).flat_map(|i| [(i * 8) as u8, 255 - (i * 5) as u8, (i * 3) as u8]).collect();
        for (sampling, depth) in [
            (Sampling::YCbCr444, Depth::Bits8),
            (Sampling::YCbCr444, Depth::Bits10),
            (Sampling::YCbCr444, Depth::Bits12),
            (Sampling::Rgb, Depth::Bits8),
            (Sampling::Rgb, Depth::Bits10),
            (Sampling::Rgb, Depth::Bits16),
        ] {
            let f = format(sampling, depth);
            let frame = from_rgb(&f, &rgb).unwrap();
            assert_eq!(frame.len(), f.frame_bytes(), "{sampling} {depth}");
            let back = to_rgb(&f, &frame).unwrap();
            for (a, b) in rgb.iter().zip(&back) {
                assert!(a.abs_diff(*b) <= 1, "{sampling} {depth}: {a} came back as {b}");
            }
        }
    }

    #[test]
    fn flat_colours_survive_4_2_2_and_key() {
        let rgb: Vec<u8> = (0..32).flat_map(|_| [16, 200, 99]).collect();
        let f = format(Sampling::YCbCr422, Depth::Bits12);
        let back = to_rgb(&f, &from_rgb(&f, &rgb).unwrap()).unwrap();
        assert!(rgb.iter().zip(&back).all(|(a, b)| a.abs_diff(*b) <= 1), "{back:?}");
        let mut f = format(Sampling::Key, Depth::Bits10);
        f.range = Range::Full;
        let grey: Vec<u8> = (0..32).flat_map(|_| [128, 128, 128]).collect();
        let back = to_rgb(&f, &from_rgb(&f, &grey).unwrap()).unwrap();
        assert!(back.iter().all(|&v| v == 128), "{back:?}");
    }

    #[test]
    fn protected_codes_stay_out_of_the_narrow_range() {
        let f = format(Sampling::Rgb, Depth::Bits10);
        let c = Converter::new(&f).unwrap();
        assert_eq!((c.clamp(-3.0), c.clamp(2000.0)), (4, 1019));
        let mut full = f.clone();
        full.range = Range::Full;
        let c = Converter::new(&full).unwrap();
        assert_eq!((c.clamp(-3.0), c.clamp(2000.0)), (0, 1023));
    }

    #[test]
    fn refuses_what_it_cannot_draw() {
        let f = format(Sampling::ICtCp422, Depth::Bits10);
        assert!(Converter::new(&f).unwrap_err().contains("ICtCp-4:2:2"));
        assert!(from_rgb(&format(Sampling::Rgb, Depth::Bits8), &[0; 5]).unwrap_err().contains("16x2"));
    }
}
