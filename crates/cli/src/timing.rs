//! `st2110 time`: where a PTP time falls for video, audio and time code, by ST 2059-1.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use st2110_ptp::PtpTime;
use st2110_ptp::timecode::TimecodeRate;
use st2110_ptp::timing::{self, Options, Timing};
use st2110_sdp::Rational;

use crate::{Format, Style};

/// The command's arguments, as given.
pub(crate) struct Args {
    pub at: Option<String>,
    pub tai_utc: i32,
    pub local_offset: Option<i32>,
    pub video: Vec<String>,
    pub audio: Vec<u32>,
    pub jam: Option<String>,
    pub jam_local_offset: Option<i32>,
    pub non_drop: bool,
}

pub(crate) fn run(args: &Args, format: Format) -> io::Result<ExitCode> {
    let timing = match work_out(args) {
        Ok(timing) => timing,
        Err(message) => {
            eprintln!("st2110: {message}");
            return Ok(ExitCode::from(2));
        }
    };
    let mut out = io::stdout().lock();
    match format {
        Format::Text => write_text(&mut out, &timing, Style::detect())?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &timing)?;
            writeln!(out)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn work_out(args: &Args) -> Result<Timing, String> {
    let time = |option: &str, text: &str| {
        timing::read_time(text, args.tai_utc).ok_or_else(|| {
            format!("{option} {text}: not a PTP time, such as 1790510437.123456789, or a UTC time, such as 2026-09-27T12:00:00Z")
        })
    };
    let t = match &args.at {
        Some(text) => time("--at", text)?,
        None => now(args.tai_utc)?,
    };
    let jam = args.jam.as_deref().map(|text| time("--jam", text)).transpose()?;
    if let (Some(text), Some(jam)) = (&args.jam, jam) {
        if jam.subsec_nanos() != 0 {
            return Err(format!("--jam {text}: a daily jam falls on a whole second, as timeOfPreviousJam counts"));
        }
        if jam > t {
            return Err("--jam is later than the time asked about; time code counts from a jam before it".into());
        }
    }
    let mut video = args
        .video
        .iter()
        .map(|text| {
            timing::read_frame_rate(text)
                .ok_or_else(|| format!("--video {text}: not a frame rate, such as 50 or 60000/1001"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut audio = args.audio.clone();
    if video.is_empty() && audio.is_empty() {
        video = [(50, 1), (60000, 1001)].iter().filter_map(|&(num, den)| Rational::new(num, den)).collect();
        audio = vec![48_000];
    }
    let options = Options {
        tai_utc: args.tai_utc,
        local_offset: args.local_offset.unwrap_or(-args.tai_utc),
        video,
        audio,
        jam,
        jam_local_offset: args.jam_local_offset,
        drop_frame: !args.non_drop,
    };
    timing::at(t, &options).map_err(|e| e.to_string())
}

/// PTP time from the system clock, taking it to keep UTC.
fn now(tai_utc: i32) -> Result<PtpTime, String> {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "the system clock is before 1970")?;
    let nanos = i128::try_from(unix.as_nanos()).map_err(|_| "the system clock is out of range")?;
    PtpTime::from_utc(nanos, tai_utc).ok_or_else(|| "the system clock is out of range".into())
}

/// `60000/1001 (59.94 fps)`, or `50 fps`.
fn frame_rate(rate: Rational) -> String {
    if rate.is_integer() { format!("{rate} fps") } else { format!("{rate} ({:.2} fps)", rate.to_f64()) }
}

fn write_text(out: &mut impl Write, t: &Timing, style: Style) -> io::Result<()> {
    writeln!(out, "{:<11} {}", "PTP time", t.ptp)?;
    writeln!(out, "{:<11} {} (TAI − UTC {} s)", "UTC", t.utc, t.tai_utc)?;
    writeln!(out, "{:<11} {} (offset {} s)", "Local Time", t.local, t.local_offset)?;
    for v in &t.video {
        writeln!(out)?;
        writeln!(out, "{}", style.paint("1", &format!("video {}", frame_rate(v.rate))))?;
        writeln!(out, "  {:<11} {} since the SMPTE Epoch", "frame", v.frame)?;
        writeln!(out, "  {:<11} {}, RTP {} at 90 kHz", "began", v.frame_start, v.rtp)?;
        writeln!(out, "  {:<11} {}, RTP {}", "next", v.next_frame, v.next_rtp)?;
        match &v.timecode {
            Some(tc) => writeln!(
                out,
                "  {:<11} {} ({} fps{}, from the jam at {:.0} Local Time)",
                "time code",
                tc.address,
                tc.rate,
                if tc.drop_frame { " drop-frame" } else { "" },
                tc.jam_local
            )?,
            None => {
                let why = match TimecodeRate::for_frame_rate(v.rate, false) {
                    None => "ST 12-1 has no time code at this rate",
                    Some(_) => "no daily jam before the codeword in progress began",
                };
                writeln!(out, "  {:<11} none: {why}", "time code")?;
            }
        }
    }
    for a in &t.audio {
        writeln!(out)?;
        writeln!(out, "{}", style.paint("1", &format!("audio {} Hz", a.rate)))?;
        writeln!(out, "  {:<11} {} for a sample taken now", "RTP", a.rtp)?;
        writeln!(out, "  {:<11} {} of 192 samples, began {}", "AES3 block", a.block, a.block_start)?;
        writeln!(out, "  {:<11} {}", "next block", a.next_block)?;
    }
    Ok(())
}
