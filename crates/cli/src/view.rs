//! `st2110 view`: a window that shows a video stream as it arrives.
//!
//! One thread receives the stream, from the network or from a capture played at the
//! pace it was captured, and hands each frame over. The window runs on the main thread,
//! as macOS requires, and draws the newest frame each time round, unpacking it across
//! the machine's cores, so that a slow screen skips frames rather than falling behind.

use std::io::{self, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::num::NonZero;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use minifb::{Key, ScaleMode, Window, WindowOptions};
use st2110_media::describe::Media;
use st2110_media::net;
use st2110_media::pixels::Converter;
use st2110_media::receive::{DEFAULT_MAX_SKEW_NS, Sink};
use st2110_media::video::FrameInfo;

use crate::Style;
use crate::stream::{self, CaptureReader, Opened, Received};

#[derive(Args)]
pub(crate) struct ViewArgs {
    /// The stream's SDP file; `-` reads standard input.
    sdp: PathBuf,
    /// The address of the network interface to receive on; the one the system picks
    /// when omitted. Give it once for every leg, or twice to receive each leg on its
    /// own.
    #[arg(long, value_name = "ADDRESS")]
    interface: Vec<Ipv4Addr>,
    /// Play a capture file instead of receiving from the network, at the pace its
    /// packets were captured.
    #[arg(long, value_name = "FILE")]
    pcap: Option<PathBuf>,
    /// How long to wait for a missing packet, for its copy on a leg that runs behind or
    /// for one that comes out of order, in milliseconds: up to 1000. The default allows
    /// what ST 2022-7 class B receivers do.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_MAX_SKEW_NS as f64 / 1e6)]
    max_skew: f64,
    /// TAI − UTC in seconds: how far the system clock, or a capture's, is behind PTP time.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = st2110_ptp::TAI_UTC_2017,
        allow_negative_numbers = true,
        value_parser = crate::offset()
    )]
    tai_utc: i32,
}

/// Where the packets come from.
enum Input {
    Network(Vec<UdpSocket>),
    Capture(CaptureReader),
}

/// What the receiving thread hands the window.
#[derive(Default)]
struct Latest {
    /// The newest frame to show, and whether the window has yet to show it.
    frame: Vec<u8>,
    fresh: bool,
    /// Frames that arrived; those of them that arrived incomplete, not counting any that
    /// the start or end of receiving cut off; and the packets those were missing.
    frames: u64,
    incomplete: u64,
    missing: u64,
    /// Whether a frame has arrived whole.
    whole: bool,
    /// When the last frame arrived.
    last: Option<Instant>,
    /// Whether receiving has stopped, at the end of a capture or on an error.
    ended: bool,
}

#[derive(Default)]
struct Handoff {
    latest: Mutex<Latest>,
    arrived: Condvar,
}

impl Handoff {
    fn lock(&self) -> MutexGuard<'_, Latest> {
        self.latest.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hands each frame to the window, whole or with packets missing, where the frames
/// before it show through, but not those the start or end of receiving cut off.
struct Viewer(Arc<Handoff>);

impl Sink for Viewer {
    fn frame(&mut self, info: &FrameInfo, pixels: &[u8]) {
        let mut latest = self.0.lock();
        latest.frames += 1;
        latest.last = Some(Instant::now());
        latest.whole |= info.whole;
        if info.cut {
            return;
        }
        if !info.whole {
            latest.incomplete += 1;
            latest.missing += u64::from(info.missing);
        }
        latest.frame.clear();
        latest.frame.extend_from_slice(pixels);
        latest.fresh = true;
        drop(latest);
        self.0.arrived.notify_one();
    }
}

pub(crate) fn view(args: &ViewArgs) -> io::Result<ExitCode> {
    let Opened { file, description, sdp_notes, mut session } =
        match stream::open(&args.sdp, args.max_skew, &args.interface) {
            Ok(opened) => opened,
            Err(code) => return Ok(code),
        };
    let Media::Video(format) = &description.media else {
        eprintln!("st2110: {file} describes audio, and view shows video; `st2110 receive --wav` saves audio");
        return Ok(ExitCode::from(2));
    };
    let converter = match Converter::new(format) {
        Ok(converter) => converter,
        Err(e) => {
            eprintln!("st2110: {file}: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    // Before the window opens, so that a stream it cannot receive fails first.
    let (input, from) = match &args.pcap {
        Some(path) => (Input::Capture(stream::capture(path)?), format!("capture {}", path.display())),
        None => match stream::sockets(&description, &args.interface) {
            Ok(sockets) => (Input::Network(sockets), "network".to_string()),
            Err(code) => return Ok(code),
        },
    };
    let name = if description.name.trim().is_empty() { file.clone() } else { description.name.clone() };
    let (width, height) = (format.width as usize, format.height as usize);
    let picture = Picture { name, format: format.to_string(), width, height };
    // Made before the window and dropped after it, for macOS draws from it whenever the
    // window needs drawing.
    let mut pixels = vec![0u32; width * height];
    let mut window = match picture.open() {
        Ok(window) => window,
        Err(e) => {
            eprintln!("st2110: cannot open a window: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let (handoff, stop) = (Arc::new(Handoff::default()), Arc::new(AtomicBool::new(false)));
    let receiver = {
        let (handoff, stop, pcap, tai_utc) = (Arc::clone(&handoff), Arc::clone(&stop), args.pcap.clone(), args.tai_utc);
        thread::Builder::new().name("receive".into()).spawn(move || {
            let mut viewer = Viewer(handoff);
            let result = match input {
                Input::Network(sockets) => {
                    net::receive_until_stopped(&mut session, sockets, &stop, tai_utc, &mut viewer).map(|()| None)
                }
                Input::Capture(reader) => {
                    let path = pcap.unwrap_or_default();
                    stream::from_capture(&mut session, reader, &path, tai_utc, &mut viewer, as_captured(&stop))
                }
            };
            viewer.0.lock().ended = true;
            (session, result)
        })?
    };
    let shown = picture.show(&mut window, &mut pixels, &handoff, &converter, args.pcap.is_some());
    stop.store(true, Ordering::Relaxed);
    drop(window);
    let (session, received) = receiver.join().map_err(|_| io::Error::other("the receiving thread panicked"))?;
    let capture_shift = received?;
    if let Err(e) = shown {
        eprintln!("st2110: the window failed: {e}");
    }
    let report = session.report();
    let failed = !report.problems.is_empty();
    let received = Received { file, sdp_notes, input: from, capture_shift, report };
    let mut out = io::stdout().lock();
    stream::write_text(&mut out, &received, &description, Style::detect())?;
    out.flush()?;
    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// Paces a capture as it was captured: lets each packet go at its time in the capture,
/// counting from when the first went, a millisecond early at most, and stops once
/// `stop` is set.
fn as_captured(stop: &AtomicBool) -> impl FnMut(i128) -> bool + '_ {
    let mut first = None;
    move |time| {
        let (start, at) = *first.get_or_insert((time, Instant::now()));
        let due = at + Duration::from_nanos(u64::try_from(time - start).unwrap_or(0));
        loop {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            let now = Instant::now();
            if due <= now + Duration::from_millis(1) {
                return true;
            }
            thread::sleep((due - now).min(Duration::from_millis(50)));
        }
    }
}

/// The stream the window shows.
struct Picture {
    name: String,
    format: String,
    width: usize,
    height: usize,
}

impl Picture {
    /// Opens the window: the picture's shape, fitted to 1280 by 720, and free to resize,
    /// keeping the shape.
    fn open(&self) -> minifb::Result<Window> {
        let (w, h) = (self.width as f64, self.height as f64);
        let scale = (1280.0 / w).min(720.0 / h);
        let size = |n: f64| ((n * scale).round() as usize).max(1);
        let options = WindowOptions { resize: true, scale_mode: ScaleMode::AspectRatioStretch, ..Default::default() };
        let mut window =
            Window::new(&self.title(&Latest::default(), Instant::now(), false), size(w), size(h), options)?;
        // Paced by the frames as they arrive, rather than a rate of its own.
        window.set_target_fps(0);
        Ok(window)
    }

    /// Shows the newest frame each time round, unpacked into `pixels`, until the window
    /// closes, or Escape or Q is pressed.
    fn show(
        &self,
        window: &mut Window,
        pixels: &mut [u32],
        handoff: &Handoff,
        converter: &Converter,
        capture: bool,
    ) -> minifb::Result<()> {
        let cores = thread::available_parallelism().map_or(1, NonZero::get);
        let mut frame = Vec::new();
        let mut titled: Option<Instant> = None;
        while window.is_open() && !window.is_key_down(Key::Escape) && !window.is_key_down(Key::Q) {
            let (fresh, title) = {
                let mut latest = handoff.lock();
                if !latest.fresh {
                    let waited = handoff.arrived.wait_timeout(latest, Duration::from_millis(20));
                    latest = waited.unwrap_or_else(PoisonError::into_inner).0;
                }
                let fresh = std::mem::take(&mut latest.fresh);
                if fresh {
                    std::mem::swap(&mut latest.frame, &mut frame);
                }
                // The counts twice a second.
                let now = Instant::now();
                let due = titled.is_none_or(|at| now - at >= Duration::from_millis(500));
                (fresh, due.then(|| self.title(&latest, now, capture)))
            };
            if fresh {
                draw(converter, &frame, pixels, self.width, cores);
            }
            if let Some(title) = title {
                window.set_title(&title);
                titled = Some(Instant::now());
            }
            window.update_with_buffer(pixels, self.width, self.height)?;
        }
        Ok(())
    }

    /// The window's title: the stream, and what has arrived by `now`.
    fn title(&self, latest: &Latest, now: Instant, capture: bool) -> String {
        // Senders often name a stream by its format, as `st2110 send` does.
        let mut title = if self.name.contains(&self.format) {
            self.name.clone()
        } else {
            format!("{}: {}", self.name, self.format)
        };
        if latest.frames == 0 {
            title.push_str(", waiting for the first frame");
        } else {
            title.push_str(&format!(", {}", crate::plural(latest.frames as usize, "frame")));
            if latest.incomplete > 0 {
                let missing = crate::plural(latest.missing as usize, "packet");
                title.push_str(&format!(", {} incomplete ({missing} missing)", latest.incomplete));
            }
            if !latest.whole {
                title.push_str(", none whole yet");
            }
        }
        if latest.ended {
            title.push_str(if capture { "; the capture has ended" } else { "; receiving stopped" });
        } else if let Some(quiet) = latest.last.map(|last| now.saturating_duration_since(last))
            && quiet >= Duration::from_secs(1)
        {
            title.push_str(&format!("; nothing for {} s", quiet.as_secs()));
        }
        title
    }
}

/// Unpacks a frame into 0RGB pixels, in bands of rows across `cores` threads.
fn draw(converter: &Converter, frame: &[u8], pixels: &mut [u32], width: usize, cores: usize) {
    let row = converter.row_bytes();
    let band = (pixels.len() / width).div_ceil(cores).max(1);
    thread::scope(|scope| {
        for (groups, out) in frame.chunks(band * row).zip(pixels.chunks_mut(band * width)) {
            scope.spawn(move || {
                for (groups, out) in groups.chunks_exact(row).zip(out.chunks_exact_mut(width)) {
                    converter.unpack_row_0rgb(groups, out);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use st2110_media::format::VideoFormat;
    use st2110_media::pattern::Bars;

    use super::*;

    fn info(whole: bool, cut: bool, missing: u32) -> FrameInfo {
        FrameInfo {
            timestamp: 0,
            packets: 10 - missing,
            missing,
            filled: 0,
            whole,
            cut,
            first_arrival: 0,
            last_arrival: 0,
            first_sequence: 0,
            last_sequence: 0,
        }
    }

    #[test]
    fn hands_over_each_frame_that_receiving_did_not_cut_off() {
        let handoff = Arc::new(Handoff::default());
        let mut viewer = Viewer(Arc::clone(&handoff));
        // Cut off by the start of receiving, which leaves the top of the picture unsent.
        viewer.frame(&info(false, true, 4), &[1; 8]);
        assert!(!handoff.lock().fresh);
        // Incomplete, and shown all the same, for a stream that always loses a packet
        // or two would otherwise show nothing.
        viewer.frame(&info(false, false, 2), &[2; 8]);
        let latest = handoff.lock();
        assert_eq!((latest.fresh, &latest.frame[..], latest.whole), (true, &[2; 8][..], false));
        drop(latest);
        viewer.frame(&info(true, false, 0), &[3; 8]);
        // Cut off by the end: the window keeps the frame before it.
        viewer.frame(&info(false, true, 5), &[4; 8]);
        let latest = handoff.lock();
        assert_eq!((&latest.frame[..], latest.whole), (&[3; 8][..], true));
        assert_eq!((latest.frames, latest.incomplete, latest.missing), (4, 1, 2));
    }

    #[test]
    fn titles_say_what_has_arrived() {
        let picture = Picture {
            name: "Bars".into(),
            format: "1920x1080p50 YCbCr-4:2:2 10-bit".into(),
            width: 1920,
            height: 1080,
        };
        let now = Instant::now();
        let mut latest = Latest::default();
        assert_eq!(
            picture.title(&latest, now, false),
            "Bars: 1920x1080p50 YCbCr-4:2:2 10-bit, waiting for the first frame"
        );
        (latest.frames, latest.incomplete, latest.missing, latest.last) = (2, 2, 7, Some(now));
        assert_eq!(
            picture.title(&latest, now, false),
            "Bars: 1920x1080p50 YCbCr-4:2:2 10-bit, 2 frames, 2 incomplete (7 packets missing), none whole yet"
        );
        (latest.frames, latest.whole) = (1250, true);
        let later = now + Duration::from_millis(3500);
        assert_eq!(
            picture.title(&latest, later, false),
            "Bars: 1920x1080p50 YCbCr-4:2:2 10-bit, 1250 frames, 2 incomplete (7 packets missing); nothing for 3 s"
        );
        (latest.incomplete, latest.ended) = (0, true);
        assert_eq!(
            picture.title(&latest, later, true),
            "Bars: 1920x1080p50 YCbCr-4:2:2 10-bit, 1250 frames; the capture has ended"
        );
        let named = Picture { name: "st2110 bars 1920x1080p50 YCbCr-4:2:2 10-bit".into(), ..picture };
        assert_eq!(
            named.title(&latest, later, false),
            "st2110 bars 1920x1080p50 YCbCr-4:2:2 10-bit, 1250 frames; receiving stopped"
        );
    }

    #[test]
    fn draws_bands_of_rows_as_one_row_at_a_time_does() {
        let format = VideoFormat::from_name("1280x720p50").unwrap();
        let (width, height) = (format.width as usize, format.height as usize);
        let frame = Bars::new(&format).unwrap().frame(3).to_vec();
        let converter = Converter::new(&format).unwrap();
        let mut one = vec![0; width * height];
        for (groups, out) in frame.chunks_exact(converter.row_bytes()).zip(one.chunks_exact_mut(width)) {
            converter.unpack_row_0rgb(groups, out);
        }
        for cores in [1, 3, 7, 16] {
            let mut pixels = vec![0; width * height];
            draw(&converter, &frame, &mut pixels, width, cores);
            assert!(pixels == one, "{cores} cores");
        }
        // 75% yellow, the second of eight bars, in a row near the top.
        assert_eq!(one[width * 100 + width * 3 / 16], 0x00BF_BF00);
    }

    #[test]
    fn plays_a_capture_at_its_pace_until_stopped() {
        let stop = AtomicBool::new(false);
        let mut pace = as_captured(&stop);
        let started = Instant::now();
        // Times in nanoseconds, 30 ms apart: the second waits for its turn.
        assert!(pace(1_000_000_000));
        assert!(pace(1_030_000_000));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(28) && waited < Duration::from_millis(500), "{waited:?}");
        // A packet from before the first goes at once.
        assert!(pace(999_000_000));
        stop.store(true, Ordering::Relaxed);
        assert!(!pace(1_031_000_000));
    }
}
