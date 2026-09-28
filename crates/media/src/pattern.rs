//! Test signals: colour bars with a moving box, and a tone.

use crate::format::{AudioFormat, Packing, VideoFormat};
use crate::pixels::Converter;

/// EBU colour bars, 100/0/75/0: white at 100%, then yellow, cyan, green, magenta, red
/// and blue at 75%, then black (EBU Tech 3325 §2.2, ITU-R BT.471).
const BARS: [[u8; 3]; 8] =
    [[255, 255, 255], [191, 191, 0], [0, 191, 191], [0, 191, 0], [191, 0, 191], [191, 0, 0], [0, 0, 191], [0, 0, 0]];

/// Colour bars over the top two thirds of the picture, and below them a black strip
/// in which a white box steps across, a little each frame, so that a frozen picture
/// shows.
#[derive(Clone, Debug)]
pub struct Bars {
    base: Vec<u8>,
    frame: Vec<u8>,
    row_bytes: usize,
    group_octets: usize,
    group_pixels: usize,
    /// Rows the box covers.
    box_rows: std::ops::Range<usize>,
    /// The box's pixel groups for one row.
    box_row: Vec<u8>,
    box_pixels: usize,
    step: usize,
    positions: usize,
    /// Where the box is drawn now: its first pixel group's octet in the row.
    drawn: Option<usize>,
}

impl Bars {
    /// The pattern for a format.
    pub fn new(format: &VideoFormat) -> Result<Self, String> {
        let converter = Converter::new(format)?;
        let group = format.pixel_group().expect("checked");
        let (w, h) = (format.width as usize, format.height as usize);
        let row_bytes = converter.row_bytes();
        let bar_rows = (h * 2).div_ceil(3);
        let mut row = vec![0; row_bytes];
        let rgb: Vec<u8> = (0..w).flat_map(|x| BARS[x * 8 / w]).collect();
        converter.pack_row(&rgb, &mut row);
        let mut base = Vec::with_capacity(row_bytes * h);
        for _ in 0..bar_rows {
            base.extend_from_slice(&row);
        }
        converter.pack_row(&vec![0; 3 * w], &mut row);
        for _ in bar_rows..h {
            base.extend_from_slice(&row);
        }

        let pixels = group.pixels as usize;
        let strip = h - bar_rows;
        let box_pixels = ((strip / 2).max(1).div_ceil(pixels) * pixels).min(w);
        let box_top = bar_rows + strip / 4;
        let box_rows = box_top..(box_top + strip / 2).min(h);
        let mut box_format = VideoFormat { width: box_pixels as u32, packing: Packing::General, ..format.clone() };
        box_format.height = 1;
        let box_converter = Converter::new(&box_format)?;
        let mut box_row = vec![0; box_converter.row_bytes()];
        box_converter.pack_row(&vec![255; 3 * box_pixels], &mut box_row);
        let groups = (w - box_pixels) / pixels + 1;
        Ok(Self {
            frame: base.clone(),
            base,
            row_bytes,
            group_octets: group.octets as usize,
            group_pixels: pixels,
            box_rows,
            box_row,
            box_pixels,
            // Across the picture in about four seconds at 50 frames a second.
            step: (groups / 200).max(1),
            positions: groups,
            drawn: None,
        })
    }

    /// Frame `n`, with the box where it is at that frame.
    pub fn frame(&mut self, n: u64) -> &[u8] {
        let at = (n % self.positions as u64) as usize * self.step % self.positions * self.group_octets;
        if self.drawn != Some(at) {
            let len = self.box_row.len();
            for r in self.box_rows.clone() {
                let row = r * self.row_bytes;
                if let Some(old) = self.drawn {
                    self.frame[row + old..row + old + len].copy_from_slice(&self.base[row + old..row + old + len]);
                }
                self.frame[row + at..row + at + len].copy_from_slice(&self.box_row);
            }
            self.drawn = Some(at);
        }
        &self.frame
    }

    /// The pixel the box starts at in frame `n`, and its width.
    pub fn box_at(&self, n: u64) -> (usize, usize) {
        let group = (n % self.positions as u64) as usize * self.step % self.positions;
        (group * self.group_pixels, self.box_pixels)
    }
}

/// A sine wave on every channel, at the same level.
#[derive(Clone, Debug)]
pub struct Tone {
    channels: usize,
    rate: u64,
    frequency: u64,
    amplitude: f64,
}

impl Tone {
    /// A tone of `frequency` Hz, below the sampling rate's half, at `level` dB below full
    /// scale: EBU R 68 lines up at −18 dBFS.
    pub fn new(format: &AudioFormat, frequency: u32, level: f64) -> Result<Self, String> {
        format.check()?;
        if frequency == 0 || 2 * u64::from(frequency) >= u64::from(format.sample_rate) {
            return Err(format!("{frequency} Hz is not a tone below {} Hz", format.sample_rate / 2));
        }
        if level.is_nan() || level > 0.0 {
            return Err(format!("{level} dBFS is not a level at or below full scale"));
        }
        let full = f64::from((1u32 << (format.bits - 1)) - 1);
        Ok(Self {
            channels: usize::from(format.channels),
            rate: u64::from(format.sample_rate),
            frequency: u64::from(frequency),
            amplitude: full * 10f64.powf(level / 20.0),
        })
    }

    /// Fills `out` with `count` sampling instants of every channel, from instant `first`
    /// counted from the epoch, so that the phase follows the time alone.
    pub fn fill(&self, first: u64, count: usize, out: &mut Vec<i32>) {
        out.clear();
        for i in 0..count as u64 {
            // Whole cycles drop out exactly, whatever the time.
            let phase = (first + i) % self.rate * self.frequency % self.rate;
            let value = (self.amplitude * (std::f64::consts::TAU * phase as f64 / self.rate as f64).sin()).round();
            out.extend(std::iter::repeat_n(value as i32, self.channels));
        }
    }
}

#[cfg(test)]
mod tests {
    use st2110_sdp::Rational;
    use st2110_sdp::video::{Depth, Sampling};

    use super::*;
    use crate::pixels::to_rgb;

    #[test]
    fn bars_and_a_moving_box() {
        let format = VideoFormat::new(1920, 1080, Rational::new(50, 1).unwrap());
        let mut bars = Bars::new(&format).unwrap();
        let rgb = to_rgb(&format, bars.frame(0)).unwrap();
        let pixel = |x: usize, y: usize| &rgb[3 * (1920 * y + x)..3 * (1920 * y + x) + 3];
        // The middle of each bar, within a code or two of 8-bit R'G'B'.
        for (i, want) in BARS.iter().enumerate() {
            let got = pixel(i * 240 + 120, 100);
            assert!(got.iter().zip(want).all(|(g, w)| g.abs_diff(*w) <= 2), "bar {i}: {got:?}");
        }
        let (x, width) = bars.box_at(0);
        assert_eq!((x, width), (0, 180));
        assert_eq!(pixel(10, 900), [255, 255, 255]);
        assert_eq!(pixel(1000, 900), [0, 0, 0]);
        let (x, _) = bars.box_at(1);
        assert_eq!(x, 8);
        let rgb = to_rgb(&format, bars.frame(1)).unwrap();
        let pixel = |x: usize, y: usize| &rgb[3 * (1920 * y + x)..3 * (1920 * y + x) + 3];
        assert_eq!((pixel(7, 900), pixel(8, 900)), (&[0, 0, 0][..], &[255, 255, 255][..]));
        // Back to frame 0 draws the same frame again.
        let again = bars.frame(0).to_vec();
        assert_eq!(again, Bars::new(&format).unwrap().frame(0));
    }

    #[test]
    fn bars_in_other_samplings() {
        for (sampling, depth) in
            [(Sampling::Rgb, Depth::Bits10), (Sampling::YCbCr444, Depth::Bits12), (Sampling::Key, Depth::Bits8)]
        {
            let mut format = VideoFormat::new(640, 360, Rational::new(25, 1).unwrap());
            (format.sampling, format.depth) = (sampling, depth);
            let mut bars = Bars::new(&format).unwrap();
            assert_eq!(bars.frame(3).len(), format.frame_bytes());
        }
    }

    #[test]
    fn tone_is_continuous_across_packets() {
        let format = AudioFormat::new(2);
        let tone = Tone::new(&format, 1000, -18.0).unwrap();
        let mut a = Vec::new();
        tone.fill(1_790_510_437 * 48_000, 96, &mut a);
        let mut b = Vec::new();
        tone.fill(1_790_510_437 * 48_000 + 48, 48, &mut b);
        assert_eq!(a[96..], b[..]);
        // −18 dBFS peaks at 8 388 607 × 10^(−18/20), which 48 samples a cycle reach.
        let peak = a.iter().map(|s| s.unsigned_abs()).max().unwrap();
        assert_eq!(peak, 1_056_063);
        assert_eq!(a[0], a[1]);
        assert!(Tone::new(&format, 24_000, -18.0).is_err());
        assert!(Tone::new(&format, 1 << 31, -18.0).is_err());
        assert!(Tone::new(&format, 1000, 3.0).is_err());
    }
}
