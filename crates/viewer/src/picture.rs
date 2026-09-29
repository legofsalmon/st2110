//! The picture: the newest frame unpacked into a texture, drawn as large as its space
//! allows at the stream's shape.

use std::num::NonZero;
use std::thread;

use eframe::egui::{self, Color32, ColorImage, Rect, TextureHandle, TextureOptions, pos2, vec2};
use st2110_media::pixels::Converter;

/// A stream's frames, shown one at a time.
pub(crate) struct Picture {
    width: usize,
    height: usize,
    /// The newest frame's pixel groups, swapped out of the monitor.
    pub(crate) frame: Vec<u8>,
    texture: Option<TextureHandle>,
    cores: usize,
}

impl Picture {
    pub(crate) fn new(width: usize, height: usize) -> Self {
        let cores = thread::available_parallelism().map_or(1, NonZero::get);
        Self { width, height, frame: Vec::new(), texture: None, cores }
    }

    /// Whether a frame has been shown.
    pub(crate) fn shown(&self) -> bool {
        self.texture.is_some()
    }

    /// Unpacks [`Self::frame`] into the texture that [`Self::paint`] draws.
    pub(crate) fn update(&mut self, ctx: &egui::Context, converter: &Converter) {
        let mut pixels = vec![Color32::BLACK; self.width * self.height];
        unpack(converter, &self.frame, bytemuck::cast_slice_mut(&mut pixels), self.width, self.cores);
        let image = ColorImage::new([self.width, self.height], pixels);
        match &mut self.texture {
            Some(texture) => texture.set(image, TextureOptions::LINEAR),
            None => self.texture = Some(ctx.load_texture("picture", image, TextureOptions::LINEAR)),
        }
    }

    /// Draws the picture as large as fits in `space`, and gives where it went.
    pub(crate) fn paint(&self, painter: &egui::Painter, space: Rect) -> Rect {
        let at = fit(space, self.width, self.height);
        if let Some(texture) = &self.texture {
            let whole = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
            painter.image(texture.id(), at, whole, Color32::WHITE);
        }
        at
    }
}

/// Unpacks a frame into RGBA pixels, in bands of rows across `cores` threads.
fn unpack(converter: &Converter, frame: &[u8], pixels: &mut [[u8; 4]], width: usize, cores: usize) {
    let row = converter.row_bytes();
    let band = (pixels.len() / width).div_ceil(cores).max(1);
    thread::scope(|scope| {
        for (groups, out) in frame.chunks(band * row).zip(pixels.chunks_mut(band * width)) {
            scope.spawn(move || {
                for (groups, out) in groups.chunks_exact(row).zip(out.chunks_exact_mut(width)) {
                    converter.unpack_row_rgba(groups, out);
                }
            });
        }
    });
}

/// The largest rectangle of a `width` by `height` picture's shape that fits in `space`,
/// in its middle, on whole points.
pub(crate) fn fit(space: Rect, width: usize, height: usize) -> Rect {
    let scale = (space.width() / width as f32).min(space.height() / height as f32).max(0.0);
    let size = (vec2(width as f32, height as f32) * scale).round().min(space.size());
    Rect::from_min_size((space.center() - size / 2.0).round(), size)
}

#[cfg(test)]
mod tests {
    use st2110_media::format::VideoFormat;
    use st2110_media::pattern::Bars;

    use super::*;

    #[test]
    fn unpacks_bands_of_rows_as_one_row_at_a_time_does() {
        let format = VideoFormat::from_name("1280x720p50").unwrap();
        let (width, height) = (format.width as usize, format.height as usize);
        let frame = Bars::new(&format).unwrap().frame(3).to_vec();
        let converter = Converter::new(&format).unwrap();
        let mut one = vec![[0; 4]; width * height];
        for (groups, out) in frame.chunks_exact(converter.row_bytes()).zip(one.chunks_exact_mut(width)) {
            converter.unpack_row_rgba(groups, out);
        }
        for cores in [1, 3, 7, 16] {
            let mut pixels = vec![[0; 4]; width * height];
            unpack(&converter, &frame, &mut pixels, width, cores);
            assert!(pixels == one, "{cores} cores");
        }
        // 75% yellow, the second of eight bars, in a row near the top.
        assert_eq!(one[width * 100 + width * 3 / 16], [0xBF, 0xBF, 0, 255]);
    }

    #[test]
    fn fits_the_picture_in_the_middle_of_its_space() {
        let space = Rect::from_min_size(pos2(10.0, 20.0), vec2(1000.0, 1000.0));
        // Wider than tall: bars above and below.
        let at = fit(space, 1920, 1080);
        assert_eq!((at.min, at.size()), (pos2(10.0, 239.0), vec2(1000.0, 563.0)));
        // Taller than wide: bars either side.
        let at = fit(Rect::from_min_size(pos2(0.0, 0.0), vec2(1600.0, 450.0)), 1920, 1080);
        assert_eq!((at.min, at.size()), (pos2(400.0, 0.0), vec2(800.0, 450.0)));
        // No room at all.
        assert_eq!(fit(Rect::from_min_size(pos2(5.0, 5.0), vec2(0.0, 0.0)), 1920, 1080).size(), vec2(0.0, 0.0));
    }
}
