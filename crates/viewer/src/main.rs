//! ST 2110 Viewer: a desktop app that plays an ST 2110-20 video stream as it arrives,
//! from the network or from a capture, with what has arrived beside the picture.
//!
//! It receives as `st2110 view` does, counts what `st2110 receive` counts, and keeps
//! going: pick a stream found on the network, as `st2110 discover` finds them, or open
//! an SDP file or drop one on the window, and pick the port.

mod app;
mod health;
mod network;
mod picture;
mod receiving;

use std::cell::Cell;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;

use clap::Parser;
use eframe::egui;

/// Plays an ST 2110-20 video stream as it arrives, with what has arrived beside it.
#[derive(Parser)]
#[command(name = "st2110-viewer", version)]
struct Args {
    /// An SDP file to open, receiving its stream at once.
    sdp: Option<PathBuf>,
    /// A capture to play with the SDP file, at the pace it was captured, rather than
    /// receive from the network.
    #[arg(long, value_name = "FILE", requires = "sdp")]
    pcap: Option<PathBuf>,
    /// Close once this many frames have arrived, and say whether they arrived whole:
    /// to test that the app runs.
    #[arg(long, value_name = "FRAMES")]
    exit_after_frames: Option<u64>,
    /// Save a picture of the window as a PNG file before closing, after
    /// --exit-after-frames.
    #[arg(long, value_name = "FILE", requires = "exit_after_frames")]
    screenshot: Option<PathBuf>,
}

fn main() -> ExitCode {
    // Finder gave apps a process serial number on older versions of macOS.
    let args = Args::parse_from(std::env::args_os().filter(|a| !a.to_string_lossy().starts_with("-psn_")));
    let passed = Rc::new(Cell::new(None));
    let check = args.exit_after_frames.map(|frames| app::Check::new(frames, args.screenshot, Rc::clone(&passed)));
    let testing = check.is_some();
    let start = app::Start { sdp: args.sdp, pcap: args.pcap, check };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ST 2110 Viewer")
            .with_app_id("st2110-viewer")
            .with_inner_size([1180.0, 660.0])
            .with_min_inner_size([560.0, 360.0])
            .with_drag_and_drop(true),
        // A test leaves the window where it was.
        persist_window: !testing,
        ..Default::default()
    };
    let ran =
        eframe::run_native("ST 2110 Viewer", options, Box::new(move |cc| Ok(Box::new(app::Viewer::new(cc, start)))));
    if let Err(e) = ran {
        eprintln!("st2110-viewer: {e}");
        return ExitCode::from(2);
    }
    match (testing, passed.get()) {
        (false, _) | (true, Some(true)) => ExitCode::SUCCESS,
        (true, Some(false)) => ExitCode::from(1),
        (true, None) => {
            eprintln!("st2110-viewer: the window closed before enough frames arrived");
            ExitCode::from(1)
        }
    }
}
