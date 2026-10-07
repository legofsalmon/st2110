//! What the demo facility sends: each demo Sender's stream, from this machine on the
//! loopback interface, so that the router has something to show. Each camera's picture
//! carries its name, a moving box and a frame count over colour bars, in a colour of
//! its own, and each camera's sound is a tone at a level of its own.
//!
//! The packets of a frame go out a millisecond's worth at a time rather than each at its
//! ST 2110-21 time: the demo is for looking at, and a sender that spins to keep exact
//! time would keep a whole processor core busy for each stream.

use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use st2110_media::describe::{Description, Media};
use st2110_media::format::VideoFormat;
use st2110_media::net::{Transmitter, tai_now};
use st2110_media::pixels::{Converter, Order};
use st2110_media::send::{FrameSource, Output, Sender, VideoSender};

/// Packets due sooner than this go at once.
const BURST_NS: i128 = 1_000_000;

/// Starts sending each stream on its own thread, from the loopback interface, until the
/// program ends. Fails, sending nothing, when a stream's sockets cannot be opened.
pub(crate) fn start(streams: &[(String, Description)], tai_utc: i32) -> io::Result<()> {
    let mut ready = Vec::new();
    for (label, description) in streams {
        let interfaces = vec![Some(Ipv4Addr::LOCALHOST); description.legs.len()];
        let transmitter = Transmitter::new(&description.legs, &interfaces, description.ttl, 0, tai_utc)?;
        ready.push((label.clone(), description.clone(), transmitter));
    }
    let (mut pictures, mut tones) = (0, 0);
    for (i, (label, description, transmitter)) in ready.into_iter().enumerate() {
        let ssrc = 0x5354_0000 | i as u32;
        let mut output = Bursts { transmitter, tai_utc };
        let start = tai_now(tai_utc);
        let sending = match &description.media {
            Media::Video(format) => {
                let mut picture = Picture::new(format, &label, pictures)?;
                pictures += 1;
                let mut sender = VideoSender::new(&description, ssrc, 0).map_err(io::Error::other)?;
                thread::spawn(move || sender.run(&mut output, start, i128::MAX, &mut picture).map(|_| ()))
            }
            Media::Audio(_) => {
                let (tone, level) = TONES[tones % TONES.len()];
                tones += 1;
                let mut sender = Sender::new(&description, tone, level, ssrc, 0).map_err(io::Error::other)?;
                thread::spawn(move || sender.run(&mut output, start, i128::MAX).map(|_| ()))
            }
        };
        thread::spawn(move || {
            if let Ok(Err(e)) = sending.join() {
                eprintln!("st2110: the demo stopped sending {label}: {e}");
            }
        });
    }
    Ok(())
}

/// Each camera's tone, in Hz, and its level, in dBFS.
const TONES: [(u32, f64); 4] = [(440, -18.0), (660, -12.0), (880, -24.0), (1000, -6.0)];

/// Sends packets a millisecond's worth at a time, sleeping between.
struct Bursts {
    transmitter: Transmitter,
    tai_utc: i32,
}

impl Output for Bursts {
    fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()> {
        let mut now = tai_now(self.tai_utc);
        if at - now > BURST_NS {
            thread::sleep(Duration::from_nanos((at - now) as u64));
            now = tai_now(self.tai_utc);
        }
        // A time that has passed sends at once.
        self.transmitter.send(packet, at.min(now))
    }

    fn now(&self) -> Option<i128> {
        Some(tai_now(self.tai_utc))
    }
}

/// Hues of the cameras' pictures, from 0 to 1.
const HUES: [f32; 5] = [0.0, 0.33, 0.6, 0.1, 0.8];

/// A camera's picture: its name, a box that moves, the frame count and colour bars.
struct Picture {
    converter: Converter,
    width: usize,
    height: usize,
    rate: f64,
    name: String,
    hue: f32,
    rgb: Vec<u8>,
    frame: Vec<u8>,
}

impl Picture {
    fn new(format: &VideoFormat, label: &str, index: usize) -> io::Result<Self> {
        let converter = Converter::new(format).map_err(io::Error::other)?;
        let (width, height) = (format.width as usize, format.height as usize);
        Ok(Self {
            converter,
            width,
            height,
            rate: format.rate.to_f64(),
            name: label.trim_end_matches(" video").to_ascii_uppercase(),
            hue: HUES[index % HUES.len()],
            rgb: vec![0; width * height * 3],
            frame: vec![0; format.frame_bytes()],
        })
    }

    fn fill(&mut self, x0: usize, y0: usize, w: usize, h: usize, colour: [u8; 3]) {
        for y in y0.min(self.height)..(y0 + h).min(self.height) {
            for x in x0.min(self.width)..(x0 + w).min(self.width) {
                let at = (y * self.width + x) * 3;
                self.rgb[at..at + 3].copy_from_slice(&colour);
            }
        }
    }

    /// Writes `text` with its top left at `(x, y)`, each dot of the font `scale` pixels.
    fn text(&mut self, text: &str, x: usize, y: usize, scale: usize, colour: [u8; 3]) {
        for (i, c) in text.chars().enumerate() {
            let rows = glyph(c);
            for (row, bits) in rows.iter().enumerate() {
                for column in 0..5 {
                    if bits & (0x10 >> column) != 0 {
                        let (px, py) = (x + (i * 6 + column) * scale, y + row * scale);
                        self.fill(px, py, scale, scale, colour);
                    }
                }
            }
        }
    }

    /// Writes `text` centred across the picture, its top at `y`, as large as fits in
    /// `height` rows and nine tenths of the width.
    fn centred(&mut self, text: &str, y: usize, height: usize, colour: [u8; 3]) {
        let columns = text.chars().count() * 6 - 1;
        let scale = (height / 7).min(self.width * 9 / 10 / columns.max(1)).max(1);
        let x = self.width.saturating_sub(columns * scale) / 2;
        self.text(text, x, y, scale, colour);
    }

    fn draw(&mut self, n: u64) {
        let (w, h) = (self.width, self.height);
        for x in 0..w {
            let colour = hsv(self.hue, 0.65, 0.2 + 0.45 * x as f32 / w as f32);
            for y in 0..h {
                let at = (y * w + x) * 3;
                self.rgb[at..at + 3].copy_from_slice(&colour);
            }
        }
        // 75% bars along the bottom quarter.
        const BARS: [[u8; 3]; 7] =
            [[191, 191, 191], [191, 191, 0], [0, 191, 191], [0, 191, 0], [191, 0, 191], [191, 0, 0], [0, 0, 191]];
        let top = h * 3 / 4;
        for (i, colour) in BARS.iter().enumerate() {
            let (x0, x1) = (i * w / 7, (i + 1) * w / 7);
            self.fill(x0, top, x1 - x0, h - top, *colour);
        }
        let name = self.name.clone();
        self.centred(&name, h / 10, h / 5, [255, 255, 255]);
        // A box that crosses the picture and back every four seconds.
        let size = (h / 9).max(2);
        let period = (self.rate * 4.0).max(2.0) as u64;
        let phase = (n % period) as f64 / period as f64;
        let travel = (w - size) as f64;
        let x = if phase < 0.5 { phase * 2.0 * travel } else { (1.0 - phase) * 2.0 * travel };
        self.fill(x as usize, h * 2 / 5, size, size, [255, 255, 255]);
        // The time of day by the frame count, in TAI, and the frame.
        let rate = self.rate.round().max(1.0) as u64;
        let seconds = n / rate;
        let count = format!("{:02}:{:02}:{:02}:{:02}", seconds / 3600 % 24, seconds / 60 % 60, seconds % 60, n % rate);
        self.centred(&count, h * 3 / 5 - h / 40, h / 10, [255, 255, 255]);
    }
}

impl FrameSource for Picture {
    fn frame(&mut self, n: u64) -> Option<&[u8]> {
        self.draw(n);
        self.converter.pack_frame(&self.rgb, self.width * 3, Order::RGB, &mut self.frame);
        Some(&self.frame)
    }
}

/// An 8-bit R'G'B' colour from hue, saturation and value, each 0 to 1.
fn hsv(hue: f32, saturation: f32, value: f32) -> [u8; 3] {
    let h = (hue.rem_euclid(1.0)) * 6.0;
    let c = value * saturation;
    let x = c * (1.0 - (h % 2.0 - 1.0).abs());
    let (r, g, b) = match h as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = value - c;
    [r, g, b].map(|v| ((v + m) * 255.0).round().clamp(0.0, 255.0) as u8)
}

/// A character of a 5 × 7 font, a row a byte, the leftmost dot the highest of five bits.
/// Characters it lacks are blank.
fn glyph(c: char) -> [u8; 7] {
    match c {
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        '3' => [0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        ':' => [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
        _ => [0; 7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use st2110_sdp::Rational;

    #[test]
    fn draws_a_picture_of_the_right_size() {
        let format = VideoFormat::new(320, 180, Rational::new(25, 1).unwrap());
        let mut picture = Picture::new(&format, "GFX 1 video", 4).unwrap();
        assert_eq!(picture.name, "GFX 1");
        let frame = picture.frame(1234).unwrap().to_vec();
        assert_eq!(frame.len(), format.frame_bytes());
        // The box moves.
        assert_ne!(picture.frame(1240).unwrap(), &frame[..]);
    }

    #[test]
    fn colours() {
        assert_eq!(hsv(0.0, 1.0, 1.0), [255, 0, 0]);
        assert_eq!(hsv(1.0 / 3.0, 1.0, 1.0), [0, 255, 0]);
        assert_eq!(hsv(0.5, 0.0, 0.5), [128, 128, 128]);
    }
}
