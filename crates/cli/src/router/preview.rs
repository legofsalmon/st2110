//! Live previews for the router page: receives the streams of the Senders the page is
//! showing, from their SDP files, and keeps a small picture of each video stream's
//! latest frame, each audio stream's levels, and what the receiver found.
//!
//! A stream is received only while the page asks for it, and stopped ten seconds after
//! it last did; at most a set number are received at once, since each takes the
//! stream's full bandwidth, whatever the size of its picture on the page.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use st2110_media::describe::{Description, Media};
use st2110_media::format::VideoFormat;
use st2110_media::net::{self, listen};
use st2110_media::pixels::Converter;
use st2110_media::receive::{Report, Session, Sink};
use st2110_media::video::FrameInfo;

/// How long a stream is received after the page last asked for it.
const KEEP: Duration = Duration::from_secs(10);

/// The widest a preview picture is.
const WIDTH: usize = 320;

/// The least time between preview pictures.
const PICTURE_EVERY: Duration = Duration::from_millis(200);

/// Samples a channel's level is the peak of: a tenth of a second at 48 kHz.
const LEVEL_SAMPLES: usize = 4800;

/// A preview picture: 8-bit R'G'B'.
#[derive(Clone)]
pub(crate) struct Picture {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

/// What has arrived of one stream.
#[derive(Default, Serialize)]
pub(crate) struct Status {
    /// Pictures made so far, so the page fetches a new one only when there is one.
    pub pictures: u64,
    /// The width and height of the stream's pictures.
    pub size: Option<(u32, u32)>,
    /// Each audio channel's peak over the last tenth of a second, in dB below full
    /// scale; `None` for silence.
    pub levels: Vec<Option<f64>>,
    /// What the receiver found, every half second.
    pub report: Option<Report>,
    /// Why the stream cannot be received, or stopped being.
    pub error: Option<String>,
    #[serde(skip)]
    pub picture: Option<Picture>,
}

/// One stream being received.
struct Live {
    sdp: String,
    stop: Arc<AtomicBool>,
    wanted: Instant,
    status: Arc<Mutex<Status>>,
}

/// The streams being received for the page.
pub(crate) struct Previews {
    /// The address of the network interface to receive on; the system's choice when `None`.
    interface: Option<Ipv4Addr>,
    tai_utc: i32,
    /// The most streams received at once.
    most: usize,
    live: Mutex<HashMap<String, Live>>,
}

impl Previews {
    pub(crate) fn new(interface: Option<Ipv4Addr>, tai_utc: i32, most: usize) -> Arc<Self> {
        let previews = Arc::new(Self { interface, tai_utc, most, live: Mutex::default() });
        let weak = Arc::downgrade(&previews);
        thread::spawn(move || {
            while let Some(previews) = weak.upgrade() {
                previews.expire();
                drop(previews);
                thread::sleep(Duration::from_secs(1));
            }
        });
        previews
    }

    /// The most streams received at once.
    pub(crate) fn most(&self) -> usize {
        self.most
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops receiving the streams the page has not asked for lately.
    fn expire(&self) {
        self.lock().retain(|_, live| {
            let keep = live.wanted.elapsed() < KEEP;
            if !keep {
                live.stop.store(true, Ordering::Relaxed);
            }
            keep
        });
    }

    /// Receives the stream `sdp` describes for the Sender `id`, or goes on receiving it,
    /// for another ten seconds. Fails when as many streams as allowed are being received.
    pub(crate) fn watch(&self, id: &str, sdp: &str) -> Result<(), String> {
        let mut live = self.lock();
        if let Some(existing) = live.get_mut(id) {
            if existing.sdp == sdp {
                existing.wanted = Instant::now();
                return Ok(());
            }
            // The Sender changed its stream: receive the new one.
            existing.stop.store(true, Ordering::Relaxed);
            live.remove(id);
        }
        if live.len() >= self.most {
            return Err(format!("at most {} streams are previewed at once", self.most));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(Status::default()));
        if let Err(e) = self.start(sdp, &stop, &status) {
            status.lock().unwrap_or_else(PoisonError::into_inner).error = Some(e);
        }
        live.insert(id.to_string(), Live { sdp: sdp.to_string(), stop, wanted: Instant::now(), status });
        Ok(())
    }

    fn start(&self, sdp: &str, stop: &Arc<AtomicBool>, status: &Arc<Mutex<Status>>) -> Result<(), String> {
        let (description, _) = Description::parse(sdp)?;
        let mut session = Session::new(&description)?;
        let sockets = description
            .legs
            .iter()
            .map(|leg| listen(leg, self.interface).map(|(socket, _)| socket))
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| format!("joining the stream: {e}"))?;
        let mut sink = Preview::new(&description, Arc::clone(status))?;
        let (stop, status, tai_utc) = (Arc::clone(stop), Arc::clone(status), self.tai_utc);
        thread::spawn(move || {
            let result = net::receive_until_stopped(&mut session, sockets, &stop, tai_utc, &mut sink);
            let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
            if let Err(e) = result {
                status.error = Some(format!("receiving stopped: {e}"));
            }
        });
        Ok(())
    }

    /// What has arrived of each stream being received, keyed by Sender `id`, with
    /// `f` making what is sent of each.
    pub(crate) fn each<T>(&self, mut f: impl FnMut(&str, &Status) -> T) -> Vec<(String, T)> {
        self.lock()
            .iter()
            .map(|(id, live)| (id.clone(), f(id, &live.status.lock().unwrap_or_else(PoisonError::into_inner))))
            .collect()
    }

    /// The latest picture of a stream being received.
    pub(crate) fn picture(&self, id: &str) -> Option<Picture> {
        let live = self.lock();
        let status = live.get(id)?.status.lock().unwrap_or_else(PoisonError::into_inner);
        status.picture.clone()
    }
}

/// Takes what arrives of a stream, for [`Status`].
struct Preview {
    status: Arc<Mutex<Status>>,
    video: Option<(VideoFormat, Converter)>,
    /// Audio channels, and the full scale of a sample.
    audio: Option<(usize, f64)>,
    last_picture: Option<Instant>,
    row: Vec<u8>,
    peaks: Vec<i32>,
    counted: usize,
}

impl Preview {
    fn new(description: &Description, status: Arc<Mutex<Status>>) -> Result<Self, String> {
        let (video, audio) = match &description.media {
            Media::Video(format) => (Some((format.clone(), Converter::new(format)?)), None),
            Media::Audio(format) => {
                let full = f64::from((1u32 << (format.bits - 1)) - 1);
                (None, Some((usize::from(format.channels), full)))
            }
        };
        let channels = audio.map_or(0, |(channels, _)| channels);
        Ok(Self { status, video, audio, last_picture: None, row: Vec::new(), peaks: vec![0; channels], counted: 0 })
    }

    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A picture of a frame of pixel groups, every `step`th pixel of every `step`th row.
fn shrink(format: &VideoFormat, converter: &Converter, pixels: &[u8], row: &mut Vec<u8>) -> Picture {
    let (width, height) = (format.width as usize, format.height as usize);
    let step = width.div_ceil(WIDTH).max(1);
    let (w, h) = (width / step, height / step);
    let bytes = converter.row_bytes();
    row.resize(width * 3, 0);
    let mut rgb = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        let start = y * step * bytes;
        let Some(source) = pixels.get(start..start + bytes) else { break };
        converter.unpack_row(source, row);
        for x in 0..w {
            rgb.extend_from_slice(&row[x * step * 3..x * step * 3 + 3]);
        }
    }
    let h = rgb.len() / (w * 3).max(1);
    Picture { width: w as u32, height: h as u32, rgb }
}

impl Sink for Preview {
    fn frame(&mut self, info: &FrameInfo, pixels: &[u8]) {
        if info.cut || self.last_picture.is_some_and(|last| last.elapsed() < PICTURE_EVERY) {
            return;
        }
        let Some((format, converter)) = &self.video else { return };
        if pixels.len() < format.frame_bytes() {
            return;
        }
        let picture = shrink(format, converter, pixels, &mut self.row);
        let size = (format.width, format.height);
        self.last_picture = Some(Instant::now());
        let mut status = self.status();
        status.picture = Some(picture);
        status.size = Some(size);
        status.pictures += 1;
    }

    fn samples(&mut self, samples: &[i32]) {
        let Some((channels, full)) = self.audio else { return };
        if channels == 0 {
            return;
        }
        for frame in samples.chunks_exact(channels) {
            for (peak, &sample) in self.peaks.iter_mut().zip(frame) {
                *peak = (*peak).max(sample.saturating_abs());
            }
            self.counted += 1;
            if self.counted >= LEVEL_SAMPLES {
                let levels =
                    self.peaks.iter().map(|&p| (p > 0).then(|| 20.0 * (f64::from(p) / full).log10())).collect();
                self.status().levels = levels;
                self.peaks.fill(0);
                self.counted = 0;
            }
        }
    }

    fn progress(&mut self, report: &Report) {
        self.status().report = Some(report.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use st2110_media::pixels::{Order, from_rgb};
    use st2110_sdp::Rational;

    #[test]
    fn shrinks_a_frame_to_preview_width() {
        let format = VideoFormat::new(640, 360, Rational::new(25, 1).unwrap());
        let converter = Converter::new(&format).unwrap();
        // Left half red, right half blue.
        let mut rgb = Vec::new();
        for _ in 0..360 {
            for x in 0..640 {
                rgb.extend_from_slice(if x < 320 { &[200, 0, 0] } else { &[0, 0, 200] });
            }
        }
        let frame = from_rgb(&format, &rgb).unwrap();
        let picture = shrink(&format, &converter, &frame, &mut Vec::new());
        assert_eq!((picture.width, picture.height), (320, 180));
        let at = |x: usize, y: usize| &picture.rgb[(y * 320 + x) * 3..(y * 320 + x) * 3 + 3];
        assert!(at(10, 90)[0] > 150 && at(10, 90)[2] < 50, "{:?}", at(10, 90));
        assert!(at(300, 90)[2] > 150 && at(300, 90)[0] < 50, "{:?}", at(300, 90));
        let _ = Order::RGB;
    }

    #[test]
    fn measures_each_channels_peak() {
        let description = Description::parse(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=tone\r\nt=0 0\r\nm=audio 5006 RTP/AVP 97\r\n\
             c=IN IP4 239.10.1.2/32\r\na=source-filter: incl IN IP4 239.10.1.2 127.0.0.1\r\n\
             a=rtpmap:97 L24/48000/2\r\na=ptime:1\r\na=ts-refclk:ptp=IEEE1588-2008:traceable\r\na=mediaclk:direct=0\r\n",
        )
        .unwrap()
        .0;
        let status = Arc::new(Mutex::new(Status::default()));
        let mut preview = Preview::new(&description, Arc::clone(&status)).unwrap();
        let half = (1 << 22) - 1;
        let samples: Vec<i32> = (0..LEVEL_SAMPLES).flat_map(|_| [half, 0]).collect();
        preview.samples(&samples);
        let levels = status.lock().unwrap().levels.clone();
        assert_eq!(levels.len(), 2);
        assert!((levels[0].unwrap() + 6.02).abs() < 0.01, "{levels:?}");
        assert_eq!(levels[1], None);
    }
}
