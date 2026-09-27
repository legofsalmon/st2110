//! `st2110 pcap`: measure the ST 2110 streams and PTP messages in packet captures, as
//! RP 2110-25 describes.

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use st2110_pcap::{
    AudioReport, CinstReport, Clock, FLOW_LIMIT, Finding, FlowReport, Options, PORT_LIMIT, PtpDomainReport, Report,
    SdpFile, Stats, Timescale, VideoReport, VrxReport,
};
use st2110_sdp::{Essence, Severity};

use crate::{Format, Style, plural, read};

/// What to analyse, and how.
pub(crate) struct Args {
    pub(crate) files: Vec<PathBuf>,
    pub(crate) sdp: Vec<PathBuf>,
    pub(crate) timescale: Timescale,
    pub(crate) tai_utc: i32,
}

/// One analysed capture.
#[derive(Serialize)]
struct Analysed {
    file: String,
    #[serde(flatten)]
    report: Report,
}

impl Analysed {
    /// Errors, counting a capture that could not be read to the end as one.
    fn errors(&self) -> usize {
        self.report.count(Severity::Error) + usize::from(self.report.capture.error.is_some())
    }
}

pub(crate) fn run(args: &Args, format: Format, quiet: bool, deny_warnings: bool) -> io::Result<ExitCode> {
    let mut sdp = Vec::new();
    for path in &args.sdp {
        let name = path.display().to_string();
        match read(path) {
            Ok(text) => sdp.push(SdpFile { name, text }),
            Err(e) => {
                // Without it, its flows would be measured against no SDP stream at all.
                eprintln!("st2110: {name}: {e}");
                return Ok(ExitCode::from(2));
            }
        }
    }
    let options = Options { sdp, timescale: args.timescale, tai_utc: args.tai_utc };
    let mut analysed = Vec::new();
    let mut unreadable = false;
    for path in &args.files {
        let file = path.display().to_string();
        match analyse(path, &options) {
            Ok(report) => analysed.push(Analysed { file, report }),
            Err(e) => {
                eprintln!("st2110: {file}: {e}");
                unreadable = true;
            }
        }
    }
    let mut out = io::stdout().lock();
    match format {
        Format::Text => {
            let style = Style::detect();
            for a in &analysed {
                write_text(&mut out, a, quiet, style)?;
            }
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &analysed)?;
            writeln!(out)?;
        }
    }
    let failed = analysed.iter().any(|a| a.errors() > 0 || (deny_warnings && a.report.count(Severity::Warning) > 0));
    Ok(match (unreadable, failed) {
        (true, _) => ExitCode::from(2),
        (false, true) => ExitCode::from(1),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// Analyses a capture file, or standard input for `-`, reading it as it goes.
fn analyse(path: &Path, options: &Options) -> Result<Report, String> {
    let report = if path.as_os_str() == "-" {
        st2110_pcap::analyse(BufReader::new(io::stdin().lock()), options)
    } else {
        let file = File::open(path).map_err(|e| e.to_string())?;
        st2110_pcap::analyse(BufReader::new(file), options)
    };
    report.map_err(|e| e.to_string())
}

fn write_text(out: &mut impl Write, a: &Analysed, quiet: bool, style: Style) -> io::Result<()> {
    let report = &a.report;
    let capture = &report.capture;
    let flows = plural(report.flows.len(), "flow");
    if !quiet {
        writeln!(
            out,
            "{}: {}, {} in {:.3} s: {} in {flows}, {}",
            style.paint("1", &a.file),
            capture.format,
            count(capture.frames, "frame"),
            capture.duration,
            count(capture.rtp, "RTP packet"),
            count(capture.ptp, "PTP message")
        )?;
        let timescale = &report.timescale;
        let clock = match timescale.clock {
            Clock::Ptp => "PTP time".to_string(),
            Clock::Utc => format!("UTC, moved {} s onto PTP time", seconds(timescale.shift)),
            Clock::Unknown => "unknown".to_string(),
        };
        writeln!(out, "  clock: {clock}: {}", timescale.basis)?;
        if let Some(note) = &timescale.note {
            writeln!(out, "    {note}")?;
        }
        for flow in &report.flows {
            write_flow(out, flow)?;
        }
        if capture.rtp_untracked > 0 {
            writeln!(
                out,
                "  {} in flows past the first {FLOW_LIMIT} were counted but not measured",
                count(capture.rtp_untracked, "RTP packet")
            )?;
        }
        for domain in &report.ptp.domains {
            write_domain(out, domain)?;
        }
        if report.ptp.untracked > 0 {
            writeln!(
                out,
                "  {} from ports past the first {PORT_LIMIT} were counted but not followed",
                count(report.ptp.untracked, "PTP message")
            )?;
        }
        if report.ptp.undecodable > 0 {
            writeln!(out, "  {} could not be decoded", count(report.ptp.undecodable, "PTP message"))?;
        }
        for missing in &report.missing {
            writeln!(out, "  not in the capture: {missing}")?;
        }
    }
    if let Some(error) = &capture.error {
        writeln!(out, "{}: {}: {error}; the analysis stops there", a.file, style.severity(Severity::Error))?;
    }
    for f in report.findings.iter().filter(|f| !quiet || f.severity != Severity::Info) {
        writeln!(
            out,
            "{}: {}[{}]: {} ({})",
            location(&a.file, f),
            style.severity(f.severity),
            f.rule,
            f.message,
            f.reference
        )?;
    }
    let (errors, warnings, notes) = (a.errors(), report.count(Severity::Warning), report.count(Severity::Info));
    if errors + warnings + notes == 0 {
        if !quiet {
            writeln!(out, "{}: {flows}, no problems found", a.file)?;
        }
    } else if !quiet || errors + warnings > 0 {
        writeln!(
            out,
            "{}: {flows}, {}, {}, {}",
            a.file,
            plural(errors, "error"),
            plural(warnings, "warning"),
            plural(notes, "note")
        )?;
    }
    if !quiet {
        writeln!(out)?;
    }
    Ok(())
}

/// Where a finding is: the file, then its flow or PTP domain and when it first happened.
fn location(file: &str, f: &Finding) -> String {
    let mut location = file.to_string();
    match (f.flow, f.domain) {
        (Some(flow), _) => location.push_str(&format!(": flow {flow}")),
        (None, Some(domain)) => location.push_str(&format!(": PTP domain {domain}")),
        (None, None) => {}
    }
    if let Some(at) = f.at {
        location.push_str(&format!(" at {at:.3} s"));
    }
    location
}

fn write_flow(out: &mut impl Write, flow: &FlowReport) -> io::Result<()> {
    let what = match (&flow.sdp, flow.essence) {
        (Some(sdp), essence) => format!("{}, {sdp}", essence.standard()),
        (None, Essence::Unknown) => "not recognised as ST 2110".to_string(),
        (None, essence) => format!("{} by its packets", essence.standard()),
    };
    writeln!(out, "  flow {}: {} to {}, {what}", flow.index, flow.source, flow.destination)?;
    let mut line =
        format!("    {} (payload type {}, SSRC {})", count(flow.packets, "packet"), flow.payload_type, flow.ssrc);
    if let Some(mbps) = flow.mbps {
        line.push_str(&format!(" at {mbps:.1} Mb/s"));
    }
    for (n, what) in [(flow.lost, "lost"), (flow.out_of_order, "out of order"), (flow.duplicates, "duplicated")] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    writeln!(out, "{line}")?;
    if let Some(video) = &flow.video {
        write_video(out, flow.essence, video)?;
    }
    if let Some(audio) = &flow.audio {
        write_audio(out, audio)?;
    }
    Ok(())
}

fn write_video(out: &mut impl Write, essence: Essence, video: &VideoReport) -> io::Result<()> {
    let mut parts = Vec::new();
    if essence != Essence::Ancillary {
        parts.push(match video.height {
            Some(height) => format!("{height} lines"),
            None => "lines unknown".to_string(),
        });
        parts.push(
            match (video.interlaced, video.segmented) {
                (_, true) => "segmented frames",
                (true, false) => "interlaced",
                (false, false) => "progressive",
            }
            .to_string(),
        );
    }
    if let Some(rate) = &video.frame_rate {
        parts.push(format!("{rate} frames a second"));
    }
    let unit = if video.interlaced && !video.segmented { "field" } else { "frame" };
    parts.push(count(video.units, unit));
    if let Some(packets) = &video.packets_per_frame {
        parts.push(if packets.min == packets.max {
            format!("{} packets a frame", packets.min)
        } else {
            format!("{} to {} packets a frame", packets.min, packets.max)
        });
    }
    writeln!(
        out,
        "    {}: {}",
        if essence == Essence::Ancillary { "ancillary data" } else { "video" },
        parts.join(", ")
    )?;
    let measured: Vec<String> = [
        ("first packet time", video.fpt, " µs"),
        ("RTP offset", video.rtp_offset, " ticks"),
        ("latency", video.latency, " µs"),
    ]
    .into_iter()
    .filter_map(|(name, stats, unit)| stats.map(|s| format!("{name} {}", range(&s, unit))))
    .collect();
    if !measured.is_empty() {
        writeln!(out, "    {}", measured.join(", "))?;
    }
    if let Some(cinst) = &video.cinst {
        writeln!(out, "    {}", describe_cinst(cinst))?;
    }
    if let Some(vrx) = &video.vrx {
        writeln!(out, "    {}", describe_vrx(vrx))?;
    }
    if let Some(reason) = &video.models_skipped {
        writeln!(out, "    ST 2110-21 models not run: {reason}")?;
    }
    if let Some(reason) = &video.vrx_skipped {
        writeln!(out, "    virtual receiver buffer not modelled: {reason}")?;
    }
    Ok(())
}

fn describe_cinst(cinst: &CinstReport) -> String {
    let mut text = format!("CINST peaked at {}", cinst.peak);
    match (cinst.cmax, &cinst.sender_type, cinst.signalled_cmax) {
        (Some(cmax), _, Some(_)) => text.push_str(&format!(", CMAX {cmax} as the SDP file signals")),
        (Some(cmax), Some(sender), None) => text.push_str(&format!(", CMAX {cmax} for {sender}")),
        (None, Some(sender), None) => text.push_str(&format!(", no CMAX for {sender} at this packet rate")),
        _ => {}
    }
    let fits = if cinst.fits.is_empty() { "no sender type".to_string() } else { cinst.fits.join(", ") };
    text.push_str(&format!("; fits {fits}"));
    text
}

fn describe_vrx(vrx: &VrxReport) -> String {
    let mut text = format!(
        "virtual receiver buffer peaked at {} of VRXFULL {}, {} reads from TROFFSET {:.1} µs{}",
        vrx.peak,
        vrx.vrxfull,
        vrx.schedule,
        vrx.troffset_us,
        if vrx.troffset_signalled { " as signalled" } else { "" }
    );
    match &vrx.margin_us {
        Some(margin) if margin.min < 0.0 => {
            text.push_str(&format!("; packets arrived as much as {:.1} µs after their reads", -margin.min));
        }
        Some(margin) => text.push_str(&format!("; packets arrived {:.1} µs or more before their reads", margin.min)),
        None => {}
    }
    for (n, what) in [(vrx.underflows, "underflow"), (vrx.overflows, "overflow")] {
        if n > 0 {
            text.push_str(&format!(", {}", count(n, what)));
        }
    }
    text
}

fn write_audio(out: &mut impl Write, audio: &AudioReport) -> io::Result<()> {
    let mut parts = vec![audio.encoding.clone(), format!("{} Hz", audio.sample_rate)];
    if let Some(channels) = audio.channels {
        parts.push(count(u64::from(channels), "channel"));
    }
    if let Some(samples) = audio.samples_per_packet {
        let time = audio.packet_time_us.map(|us| format!(" ({us:.1} µs)")).unwrap_or_default();
        parts.push(format!("{} a packet{time}", count(u64::from(samples), "sample")));
    }
    writeln!(out, "    audio: {}", parts.join(", "))?;
    let mut measured: Vec<String> = [("latency", audio.latency), ("packet interval", audio.interval)]
        .into_iter()
        .filter_map(|(name, stats)| stats.map(|s| format!("{name} {}", range(&s, " µs"))))
        .collect();
    if let Some(ts_df) = &audio.ts_df {
        measured.push(format!("TS-DF at most {:.1} µs", ts_df.max));
    }
    if !measured.is_empty() {
        writeln!(out, "    {}", measured.join(", "))?;
    }
    Ok(())
}

fn write_domain(out: &mut impl Write, domain: &PtpDomainReport) -> io::Result<()> {
    let grandmasters = match domain.grandmasters.as_slice() {
        [] => "no Announce messages".to_string(),
        [one] => format!("grandmaster {one}"),
        many => format!("grandmasters {}", many.join(", ")),
    };
    writeln!(out, "  PTP domain {}: {grandmasters}", domain.domain)?;
    for port in &domain.ports {
        let messages: Vec<String> = port
            .messages
            .iter()
            .map(|m| match &m.interval_ms {
                Some(interval) => format!("{} {} every {:.1} ms", m.count, m.kind, interval.mean),
                None => format!("{} {}", m.count, m.kind),
            })
            .collect();
        writeln!(out, "    {} at {}: {}", port.port, port.address, messages.join(", "))?;
    }
    if let Some(offset) = &domain.sync_offset_us {
        writeln!(out, "    Sync arrival less departure {}", range(offset, " µs"))?;
    }
    Ok(())
}

/// A measurement's mean, then its range.
fn range(stats: &Stats, unit: &str) -> String {
    format!("{:.1}{unit} ({:.1} to {:.1})", stats.mean, stats.min, stats.max)
}

/// Whole seconds of a shift in nanoseconds.
fn seconds(nanos: i64) -> i64 {
    nanos / 1_000_000_000
}

fn count(n: u64, noun: &str) -> String {
    plural(usize::try_from(n).unwrap_or(usize::MAX), noun)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_models() {
        let mut cinst = CinstReport {
            peak: 40,
            sender_type: Some("2110TPN".into()),
            cmax: Some(4),
            signalled_cmax: None,
            cmax_narrow: 4,
            cmax_narrow_linear: 4,
            cmax_wide: Some(16),
            fits: Vec::new(),
            drain_us: 18.5,
        };
        assert_eq!(describe_cinst(&cinst), "CINST peaked at 40, CMAX 4 for 2110TPN; fits no sender type");
        (cinst.peak, cinst.cmax, cinst.signalled_cmax, cinst.fits) = (3, Some(3), Some(3), vec!["2110TPN".into()]);
        assert_eq!(describe_cinst(&cinst), "CINST peaked at 3, CMAX 3 as the SDP file signals; fits 2110TPN");
        (cinst.sender_type, cinst.cmax, cinst.signalled_cmax, cinst.cmax_wide) =
            (Some("2110TPW".into()), None, None, None);
        assert_eq!(describe_cinst(&cinst), "CINST peaked at 3, no CMAX for 2110TPW at this packet rate; fits 2110TPN");
        let stats = Stats { count: 2, min: 20.0, max: 30.0, mean: 25.0 };
        let mut vrx = VrxReport {
            schedule: "gapped".into(),
            troffset_us: 764.444,
            troffset_signalled: false,
            vrxfull: 8,
            peak: 9,
            underflows: 0,
            overflows: 1,
            margin_us: Some(stats),
            method: String::new(),
        };
        assert_eq!(
            describe_vrx(&vrx),
            "virtual receiver buffer peaked at 9 of VRXFULL 8, gapped reads from TROFFSET 764.4 µs; \
             packets arrived 20.0 µs or more before their reads, 1 overflow"
        );
        assert_eq!(range(&stats, " µs"), "25.0 µs (20.0 to 30.0)");
        (vrx.margin_us, vrx.underflows, vrx.overflows) = (Some(Stats { min: -12.25, ..stats }), 3, 0);
        assert_eq!(
            describe_vrx(&vrx),
            "virtual receiver buffer peaked at 9 of VRXFULL 8, gapped reads from TROFFSET 764.4 µs; \
             packets arrived as much as 12.2 µs after their reads, 3 underflows"
        );
    }
}
