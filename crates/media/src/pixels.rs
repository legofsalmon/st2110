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
//!
//! Packing adds up what tables say each 8-bit value of R', G' and B' gives each sample,
//! in fixed point, which is fast enough to send a renderer's pictures live. Pictures may
//! come with their octets in another [`Order`], and with their rows padded, as GPUs read
//! them back.

use std::fmt;

use st2110_sdp::video::{PixelGroup, Sampling};

use crate::format::{Range, VideoFormat};

/// Fraction bits of the packing tables' fixed-point values.
const FRACTION: u32 = 24;

/// What each pixel's samples are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ycc422,
    Ycc444,
    Rgb,
    Key,
}

/// Where R', G' and B' sit among each pixel's octets, in the rows of an 8-bit picture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    step: usize,
    r: usize,
    g: usize,
    b: usize,
}

impl Order {
    /// R', G', B'.
    pub const RGB: Self = Self { step: 3, r: 0, g: 1, b: 2 };
    /// B', G', R'.
    pub const BGR: Self = Self { step: 3, r: 2, g: 1, b: 0 };
    /// R', G', B' and an octet that is not read, such as alpha.
    pub const RGBA: Self = Self { step: 4, r: 0, g: 1, b: 2 };
    /// B', G', R' and an octet that is not read, as GPUs often keep 8-bit pictures and NDI
    /// sends them.
    pub const BGRA: Self = Self { step: 4, r: 2, g: 1, b: 0 };

    /// Octets from one pixel to the next.
    pub fn step(self) -> usize {
        self.step
    }
}

/// What each 8-bit value of R', G' and B' adds to a pixel's samples, as code values with
/// [`FRACTION`] bits of fraction, so that packing a pixel takes additions and no more.
#[derive(Clone)]
struct Tables {
    /// Y', or for R'G'B' each value's own code.
    y: [[i64; 256]; 3],
    cb: [[i64; 256]; 3],
    cr: [[i64; 256]; 3],
    /// The code of black, and a half to round with.
    y_base: i64,
    /// The code of no colour difference, and a half to round with.
    c_base: i64,
    /// The lowest and highest codes the range allows.
    lo: i64,
    hi: i64,
}

impl Tables {
    fn new(kind: Kind, bits: u32, range: Range, kr: f64, kb: f64) -> Self {
        let top = f64::from((1u32 << bits) - 1);
        let scale = f64::from(1u32 << (bits - 8));
        // Each code is a × value + b, for Y' and R'G'B' from 0 to 1 and the colour
        // differences from −½ to ½.
        let ((ay, by), (ac, bc)) = match range {
            Range::Narrow => ((219.0 * scale, 16.0 * scale), (224.0 * scale, 128.0 * scale)),
            Range::Full | Range::FullProtect => ((top, 0.0), (top, f64::from(1u32 << (bits - 1)))),
        };
        let kg = 1.0 - kr - kb;
        let luma = if kind == Kind::Rgb { [1.0; 3] } else { [kr, kg, kb] };
        // C'B = (B' − Y') ÷ 2(1 − K_B) and C'R = (R' − Y') ÷ 2(1 − K_R), in R', G' and B'.
        let cb = [-kr / (2.0 * (1.0 - kb)), -kg / (2.0 * (1.0 - kb)), 0.5];
        let cr = [0.5, -kg / (2.0 * (1.0 - kr)), -kb / (2.0 * (1.0 - kr))];
        let one = f64::from(1u32 << FRACTION);
        let table = |a: f64, k: f64| std::array::from_fn(|v| (a * k * v as f64 / 255.0 * one).round() as i64);
        // Only the full range may use the codes SDI reserves: 0 and the top code at 8
        // bits, the four at each end at 10 bits, and so on.
        let reserved = if range == Range::Full { 0 } else { 1 << (bits - 8) };
        Self {
            y: std::array::from_fn(|c| table(ay, luma[c])),
            cb: std::array::from_fn(|c| table(ac, cb[c])),
            cr: std::array::from_fn(|c| table(ac, cr[c])),
            y_base: ((by + 0.5) * one) as i64,
            c_base: ((bc + 0.5) * one) as i64,
            lo: reserved,
            hi: (1 << bits) - 1 - reserved,
        }
    }

    fn y(&self, [r, g, b]: [usize; 3]) -> i64 {
        self.y[0][r] + self.y[1][g] + self.y[2][b]
    }

    fn cb(&self, [r, g, b]: [usize; 3]) -> i64 {
        self.cb[0][r] + self.cb[1][g] + self.cb[2][b]
    }

    fn cr(&self, [r, g, b]: [usize; 3]) -> i64 {
        self.cr[0][r] + self.cr[1][g] + self.cr[2][b]
    }

    /// The code of Y', or of an R'G'B' value, from its table values.
    fn y_code(&self, sum: i64) -> u16 {
        ((sum + self.y_base) >> FRACTION).clamp(self.lo, self.hi) as u16
    }

    /// The code of a colour difference from its table values.
    fn c_code(&self, sum: i64) -> u16 {
        ((sum + self.c_base) >> FRACTION).clamp(self.lo, self.hi) as u16
    }

    /// The code of a colour difference from four times its table values, filtered.
    fn c_code_of_four(&self, sum: i64) -> u16 {
        ((sum + 4 * self.c_base) >> (FRACTION + 2)).clamp(self.lo, self.hi) as u16
    }
}

impl fmt::Debug for Tables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tables").field("lo", &self.lo).field("hi", &self.hi).finish_non_exhaustive()
    }
}

/// Converts rows of 8-bit R'G'B' to and from one format's pixel groups.
#[derive(Clone, Debug)]
pub struct Converter {
    kind: Kind,
    bits: u32,
    group: PixelGroup,
    width: usize,
    height: usize,
    /// Luma coefficients K_R and K_B.
    kr: f32,
    kb: f32,
    range: Range,
    tables: Box<Tables>,
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
        Ok(Self {
            kind,
            bits,
            group,
            width: format.width as usize,
            height: format.height as usize,
            kr: kr as f32,
            kb: kb as f32,
            range: format.range,
            tables: Box::new(Tables::new(kind, bits, format.range, kr, kb)),
        })
    }

    /// Octets of one row of pixel groups.
    pub fn row_bytes(&self) -> usize {
        self.width / self.group.pixels as usize * self.group.octets as usize
    }

    /// Packs one row of R'G'B' triplets, `3 × width` octets, into `out`.
    pub fn pack_row(&self, rgb: &[u8], out: &mut [u8]) {
        self.pack_row_in(rgb, Order::RGB, out);
    }

    /// Packs one row of `width` pixels, their octets in `order`, into the first
    /// [`Converter::row_bytes`] octets of `out`.
    ///
    /// # Panics
    ///
    /// If `row` is shorter than `width` pixels or `out` than a row of pixel groups.
    pub fn pack_row_in(&self, row: &[u8], order: Order, out: &mut [u8]) {
        let w = self.width;
        assert!(row.len() >= w * order.step, "{} octets is not a row of {w} pixels", row.len());
        let (row, out) = (&row[..w * order.step], &mut out[..self.row_bytes()]);
        // A loop for each order, so that where each octet sits is known when compiling.
        match order {
            Order::RGB => self.pack::<3, 0, 1, 2>(row, out),
            Order::BGR => self.pack::<3, 2, 1, 0>(row, out),
            Order::RGBA => self.pack::<4, 0, 1, 2>(row, out),
            Order::BGRA => self.pack::<4, 2, 1, 0>(row, out),
            _ => unreachable!("every order is one of the constants"),
        }
    }

    /// Packs a row of pixels `STEP` octets apart, with R', G' and B' at `R`, `G` and `B`.
    fn pack<const STEP: usize, const R: usize, const G: usize, const B: usize>(&self, row: &[u8], out: &mut [u8]) {
        let t = &*self.tables;
        let (pixels, octets) = (self.group.pixels as usize, self.group.octets as usize);
        let pixel = |p: &[u8; STEP]| [usize::from(p[R]), usize::from(p[G]), usize::from(p[B])];
        let (row, _) = row.as_chunks::<STEP>();
        match self.kind {
            Kind::Ycc422 => {
                // Chroma co-sited with each pair's first pixel, filtered 1-2-1 across its
                // neighbours; the first pixel stands in for the one before it.
                let first = pixel(&row[0]);
                let (mut cb_before, mut cr_before) = (t.cb(first), t.cr(first));
                for ([p0, p1], group) in row.as_chunks::<2>().0.iter().zip(out.chunks_exact_mut(octets)) {
                    let (p0, p1) = (pixel(p0), pixel(p1));
                    let (cb1, cr1) = (t.cb(p1), t.cr(p1));
                    let cb = t.c_code_of_four(cb_before + 2 * t.cb(p0) + cb1);
                    let cr = t.c_code_of_four(cr_before + 2 * t.cr(p0) + cr1);
                    write_group(group, &[cb, t.y_code(t.y(p0)), cr, t.y_code(t.y(p1))], self.bits);
                    (cb_before, cr_before) = (cb1, cr1);
                }
            }
            kind => {
                let per_pixel = if kind == Kind::Key { 1 } else { 3 };
                let mut samples = [0u16; 12];
                let samples = &mut samples[..per_pixel * pixels];
                for (run, group) in row.chunks_exact(pixels).zip(out.chunks_exact_mut(octets)) {
                    for (p, s) in run.iter().zip(samples.chunks_exact_mut(per_pixel)) {
                        let p = pixel(p);
                        match kind {
                            Kind::Rgb => s.copy_from_slice(&[0, 1, 2].map(|c| t.y_code(t.y[c][p[c]]))),
                            Kind::Ycc444 => {
                                s.copy_from_slice(&[t.c_code(t.cb(p)), t.y_code(t.y(p)), t.c_code(t.cr(p))])
                            }
                            Kind::Key | Kind::Ycc422 => s[0] = t.y_code(t.y(p)),
                        }
                    }
                    write_group(group, samples, self.bits);
                }
            }
        }
    }

    /// Packs a picture of `width × height` pixels, their octets in `order` and each row
    /// `stride` octets after the one before, as GPUs pad them, into a frame of pixel
    /// groups: the first [`VideoFormat::frame_bytes`] octets of `frame`.
    ///
    /// # Panics
    ///
    /// If the picture or the frame is too short, or `stride` shorter than a row.
    pub fn pack_frame(&self, picture: &[u8], stride: usize, order: Order, frame: &mut [u8]) {
        let (w, h) = (self.width, self.height);
        assert!(stride >= w * order.step, "a stride of {stride} octets is shorter than a row of {w} pixels");
        assert!(
            picture.len() >= stride * (h - 1) + w * order.step,
            "{} octets is not a picture of {h} rows {stride} octets apart",
            picture.len()
        );
        let row = self.row_bytes();
        assert!(frame.len() >= row * h, "{} octets is not a frame of {} octets", frame.len(), row * h);
        for (y, out) in frame.chunks_exact_mut(row).take(h).enumerate() {
            self.pack_row_in(&picture[y * stride..], order, out);
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

    fn rgb(&self, y: f32, cb: f32, cr: f32) -> (f32, f32, f32) {
        let r = y + 2.0 * (1.0 - self.kr) * cr;
        let b = y + 2.0 * (1.0 - self.kb) * cb;
        let g = (y - self.kr * r - self.kb * b) / (1.0 - self.kr - self.kb);
        (r, g, b)
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
}

fn to_u8(v: f32) -> u8 {
    (v * 255.0).round().clamp(0.0, 255.0) as u8
}

/// Writes samples of `bits` each into a pixel group, most significant bit first.
fn write_group(group: &mut [u8], samples: &[u16], bits: u32) {
    // Most groups fit in 64 bits, and those go faster so.
    if group.len() <= 8 {
        let mut acc: u64 = 0;
        for &s in samples {
            acc = (acc << bits) | u64::from(s);
        }
        group.copy_from_slice(&acc.to_be_bytes()[8 - group.len()..]);
    } else {
        let mut acc: u128 = 0;
        for &s in samples {
            acc = (acc << bits) | u128::from(s);
        }
        group.copy_from_slice(&acc.to_be_bytes()[16 - group.len()..]);
    }
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
    let mut frame = vec![0; format.frame_bytes()];
    converter.pack_frame(rgb, 3 * w, Order::RGB, &mut frame);
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
    fn protected_codes_stay_out_of_all_but_the_full_range() {
        // Full-scale white and black in 10-bit R'G'B': the full range uses every code,
        // and the others leave out the four at each end that SDI reserves.
        let white_and_black = [255, 255, 255, 0, 0, 0, 255, 255, 255, 0, 0, 0];
        for (range, codes) in [(Range::Full, [1023, 0]), (Range::FullProtect, [1019, 4]), (Range::Narrow, [940, 64])] {
            let mut f = VideoFormat::new(4, 1, Rational::new(25, 1).unwrap());
            (f.sampling, f.depth, f.range) = (Sampling::Rgb, Depth::Bits10, range);
            let frame = from_rgb(&f, &white_and_black).unwrap();
            let mut samples = [0u16; 12];
            read_group(&frame, &mut samples, 10);
            assert_eq!(samples[..6], [codes[0]; 3].into_iter().chain([codes[1]; 3]).collect::<Vec<_>>()[..]);
        }
    }

    /// The code values the formulas give, before rounding, worked out in double
    /// precision from R'G'B' each time: how this crate packed pictures before the tables.
    fn by_formula(c: &Converter, rgb: &[u8], (kr, kb): (f64, f64)) -> Vec<f64> {
        let (bits, w) = (c.bits, c.width);
        let top = f64::from((1u32 << bits) - 1);
        let scale = f64::from(1u32 << (bits - 8));
        let reserved = if c.range == Range::Full { 0.0 } else { scale };
        let clamp = |code: f64| code.clamp(reserved, top - reserved);
        let code = |v: f64| match c.range {
            Range::Narrow => clamp((219.0 * v + 16.0) * scale),
            _ => clamp(v * top),
        };
        let chroma = |v: f64| match c.range {
            Range::Narrow => clamp((224.0 * v + 128.0) * scale),
            _ => clamp(v * top + f64::from(1u32 << (bits - 1))),
        };
        let ycc = |x: usize| {
            let [r, g, b] = [0, 1, 2].map(|i| f64::from(rgb[3 * x + i]) / 255.0);
            let y = kr * r + (1.0 - kr - kb) * g + kb * b;
            (y, (b - y) / (2.0 * (1.0 - kb)), (r - y) / (2.0 * (1.0 - kr)))
        };
        match c.kind {
            Kind::Rgb => rgb[..3 * w].iter().map(|&v| code(f64::from(v) / 255.0)).collect(),
            Kind::Key => (0..w).map(|x| code(ycc(x).0)).collect(),
            Kind::Ycc444 => (0..w)
                .flat_map(|x| {
                    let (y, cb, cr) = ycc(x);
                    [chroma(cb), code(y), chroma(cr)]
                })
                .collect(),
            Kind::Ycc422 => (0..w)
                .step_by(2)
                .flat_map(|x| {
                    let (before, here, after) = (ycc(x.saturating_sub(1)), ycc(x), ycc((x + 1).min(w - 1)));
                    let cb = (before.1 + 2.0 * here.1 + after.1) / 4.0;
                    let cr = (before.2 + 2.0 * here.2 + after.2) / 4.0;
                    [chroma(cb), code(here.0), chroma(cr), code(ycc(x + 1).0)]
                })
                .collect(),
        }
    }

    #[test]
    fn packs_the_code_values_the_formulas_give() {
        // Every sampling, depth, range and set of luma coefficients this crate packs, on
        // pixels from an xorshift, against the formulas: each code is the value rounded,
        // or for a value that lies on a half, either code beside it.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let rgb: Vec<u8> = (0..3 * 480)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .chain([0, 0, 0, 255, 255, 255, 191, 191, 0, 0, 0, 191])
            .collect();
        let (mut samples, mut halves) = (0, 0);
        for sampling in [Sampling::YCbCr422, Sampling::YCbCr444, Sampling::Rgb, Sampling::Key] {
            for depth in [Depth::Bits8, Depth::Bits10, Depth::Bits12, Depth::Bits16] {
                for range in [Range::Narrow, Range::FullProtect, Range::Full] {
                    for (colorimetry, k) in
                        [("BT601", (0.299, 0.114)), ("BT709", (0.2126, 0.0722)), ("BT2020", (0.2627, 0.0593))]
                    {
                        let mut f = VideoFormat::new(484, 1, Rational::new(25, 1).unwrap());
                        (f.sampling, f.depth, f.range, f.colorimetry) = (sampling, depth, range, colorimetry.into());
                        let Ok(c) = Converter::new(&f) else { continue };
                        let mut row = vec![0; c.row_bytes()];
                        c.pack_row(&rgb, &mut row);
                        let values = by_formula(&c, &rgb, k);
                        let mut packed = vec![0u16; values.len()];
                        let per_group = packed.len() / (row.len() / c.group.octets as usize);
                        for (group, chunk) in
                            row.chunks_exact(c.group.octets as usize).zip(packed.chunks_exact_mut(per_group))
                        {
                            read_group(group, chunk, c.bits);
                        }
                        for (i, (&code, value)) in packed.iter().zip(values).enumerate() {
                            let half = (value - value.floor() - 0.5).abs() < 1e-9 * value.max(1.0);
                            let fits = if half {
                                value.floor() <= code.into() && value.ceil() >= code.into()
                            } else {
                                f64::from(code) == value.round()
                            };
                            assert!(fits, "{f}: sample {i} is {code}, and {value} by the formulas");
                            halves += usize::from(half);
                        }
                        samples += packed.len();
                    }
                }
            }
        }
        assert!(samples > 100_000 && halves < samples / 1000, "{halves} of {samples} samples on halves");
    }

    #[test]
    fn packs_other_orders_and_padded_rows() {
        let f = VideoFormat::from_name("64x3p50").unwrap();
        let c = Converter::new(&f).unwrap();
        let rgb: Vec<u8> = (0..64 * 3 * 3).map(|i| (i * 37 % 256) as u8).collect();
        let expected = from_rgb(&f, &rgb).unwrap();
        // B', G', R' and a junk octet, in rows padded to 512 octets, the padding junk too.
        let stride = 512;
        let mut bgra = vec![0xA5; stride * 3];
        for (i, p) in rgb.as_chunks::<3>().0.iter().enumerate() {
            let at = i / 64 * stride + i % 64 * 4;
            bgra[at..at + 3].copy_from_slice(&[p[2], p[1], p[0]]);
        }
        let mut frame = vec![0; f.frame_bytes()];
        c.pack_frame(&bgra, stride, Order::BGRA, &mut frame);
        assert_eq!(frame, expected);
        let bgr: Vec<u8> = rgb.as_chunks::<3>().0.iter().flat_map(|p| [p[2], p[1], p[0]]).collect();
        let mut frame = vec![0; f.frame_bytes()];
        c.pack_frame(&bgr, 64 * 3, Order::BGR, &mut frame);
        assert_eq!(frame, expected);
    }

    #[test]
    fn refuses_what_it_cannot_draw() {
        let f = format(Sampling::ICtCp422, Depth::Bits10);
        assert!(Converter::new(&f).unwrap_err().contains("ICtCp-4:2:2"));
        assert!(from_rgb(&format(Sampling::Rgb, Depth::Bits8), &[0; 5]).unwrap_err().contains("16x2"));
    }
}
