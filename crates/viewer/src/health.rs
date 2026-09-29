//! What has arrived, in words: the rows of the panel beside the picture, and the line
//! that says what receiving is doing.

use std::time::Duration;

use st2110_media::live::Latest;
use st2110_media::receive::Report;

/// How a row should look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Plain,
    /// Worth a look, and not wrong in itself: a leg's loss that the other made good.
    Warn,
    /// Wrong: packets or frames lost.
    Bad,
}

/// One line of the panel: `Frames  1,250`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Row {
    pub(crate) label: String,
    pub(crate) value: String,
    pub(crate) tone: Tone,
}

fn row(label: impl Into<String>, value: impl Into<String>, tone: Tone) -> Row {
    Row { label: label.into(), value: value.into(), tone }
}

/// What has arrived, copied out of the monitor to draw.
#[derive(Clone, Debug, Default)]
pub(crate) struct Seen {
    pub(crate) frames: u64,
    pub(crate) incomplete: u64,
    pub(crate) missing: u64,
    pub(crate) whole: bool,
    /// How long since the last frame arrived.
    pub(crate) quiet: Option<Duration>,
    pub(crate) report: Option<Report>,
}

impl Seen {
    /// What `latest` holds, `quiet` since its last frame.
    pub(crate) fn from(latest: &Latest, quiet: Option<Duration>) -> Self {
        Self {
            frames: latest.frames,
            incomplete: latest.incomplete,
            missing: latest.missing,
            whole: latest.whole,
            quiet,
            report: latest.report.clone(),
        }
    }

    /// Whether packets have arrived.
    pub(crate) fn anything(&self) -> bool {
        self.frames > 0 || self.report.as_ref().is_some_and(|r| r.passed > 0)
    }
}

/// `1,234,567`.
pub(crate) fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `1 frame`, `2 frames`.
fn plural(n: u64, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{} {noun}s", count(n)) }
}

/// `12.3 s`, `4 min 05 s`, `1 h 02 min`.
fn span(seconds: f64) -> String {
    let whole = seconds.max(0.0) as u64;
    if whole < 60 {
        format!("{seconds:.1} s")
    } else if whole < 3600 {
        format!("{} min {:02} s", whole / 60, whole % 60)
    } else {
        format!("{} h {:02} min", whole / 3600, whole / 60 % 60)
    }
}

/// The panel's rows: frames, packets and each leg, then what the report measured.
pub(crate) fn rows(seen: &Seen) -> Vec<Row> {
    let mut rows = Vec::new();
    let report = seen.report.as_ref();
    let video = report.and_then(|r| r.video.as_ref());
    if video.is_some() || seen.frames > 0 {
        let (value, tone) = if seen.incomplete > 0 {
            let missing = plural(seen.missing, "packet");
            (format!("{}, {} incomplete ({missing} missing)", count(seen.frames), count(seen.incomplete)), Tone::Bad)
        } else if seen.frames > 0 && !seen.whole {
            (format!("{}, none whole yet", count(seen.frames)), Tone::Warn)
        } else {
            (count(seen.frames), Tone::Plain)
        };
        rows.push(row("Frames", value, tone));
    }
    if let Some(rate) = video.and_then(|v| v.frame_rate) {
        rows.push(row("Frame rate", format!("{rate:.3} a second"), Tone::Plain));
    }
    let Some(report) = report else {
        return rows;
    };
    let mut lost = if report.lost == 0 { "none lost".to_string() } else { format!("{} lost", count(report.lost)) };
    if report.too_late > 0 {
        lost.push_str(&format!(", {} too late", count(report.too_late)));
    }
    let tone = if report.lost > 0 || report.too_late > 0 { Tone::Bad } else { Tone::Plain };
    let merged = if report.legs.len() > 1 { "Merged" } else { "Packets" };
    rows.push(row(merged, format!("{}, {lost}", count(report.passed)), tone));
    if report.legs.len() > 1 {
        for (i, leg) in report.legs.iter().enumerate() {
            let rtp = &leg.rtp;
            let mut value = plural(rtp.received, "packet");
            for (n, what) in [(rtp.lost, "lost"), (rtp.too_late, "too late to merge")] {
                if n > 0 {
                    value.push_str(&format!(", {} {what}", count(n)));
                }
            }
            let tone = if rtp.received == 0 || rtp.lost > 0 || rtp.too_late > 0 { Tone::Warn } else { Tone::Plain };
            rows.push(row(format!("Leg {}", i + 1), value, tone));
        }
    }
    rows.push(row("Data rate", format!("{:.1} Mb/s", report.megabits_per_second), Tone::Plain));
    if let Some(skew) = &report.skew {
        let (value, tone) = match &report.class {
            Some(class) => {
                (format!("at most {:.1} µs: ST 2022-7 class {class}", skew.max_ns as f64 / 1000.0), Tone::Plain)
            }
            None => (format!("at most {:.1} µs: beyond every ST 2022-7 class", skew.max_ns as f64 / 1000.0), Tone::Bad),
        };
        rows.push(row("Legs apart", value, tone));
    }
    if let Some(latency) = &report.latency {
        rows.push(row(
            "Latency",
            format!("{:.1} to {:.1} µs, mean {:.1} µs", latency.min, latency.max, latency.mean),
            Tone::Plain,
        ));
    }
    if let Some(audio) = &report.audio {
        let peaks: Vec<String> =
            audio.peaks.iter().map(|p| p.map_or("silent".into(), |db| format!("{db:.1}"))).collect();
        rows.push(row("Loudest", format!("{} dBFS", peaks.join(", ")), Tone::Plain));
    }
    if report.restarts > 0 {
        rows.push(row("Restarts", count(report.restarts), Tone::Warn));
    }
    rows.push(row("Time", span(report.seconds), Tone::Plain));
    rows
}

/// What receiving is doing, in a line.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Doing<'a> {
    /// Where the packets come from: `en0 (192.168.1.20)`, or a capture's file name.
    pub(crate) from: &'a str,
    pub(crate) capture: bool,
    /// Whether receiving goes on.
    pub(crate) running: bool,
    /// Whether the person stopped it.
    pub(crate) stopped: bool,
    /// How long since receiving started.
    pub(crate) since: Duration,
}

/// The line that says what receiving is doing, and how it should look.
pub(crate) fn state(doing: &Doing, seen: &Seen) -> (String, Tone) {
    let from = doing.from;
    if !doing.running {
        return if doing.stopped {
            ("Stopped".into(), Tone::Plain)
        } else if doing.capture {
            (format!("The capture {from} has ended"), Tone::Plain)
        } else {
            ("Receiving stopped".into(), Tone::Plain)
        };
    }
    let quiet = seen.quiet.filter(|q| *q >= Duration::from_secs(1));
    match quiet {
        Some(quiet) => (format!("Nothing for {} s from {from}", quiet.as_secs()), Tone::Bad),
        None if seen.anything() => {
            if doing.capture {
                (format!("Playing {from}"), Tone::Plain)
            } else {
                (format!("Receiving on {from}"), Tone::Plain)
            }
        }
        // Local network privacy on macOS drops what arrives, rather than failing, until
        // the person allows it.
        None if !doing.capture && doing.since >= Duration::from_secs(3) && cfg!(target_os = "macos") => (
            format!(
                "Nothing has arrived on {from}. Check the port, and that ST 2110 Viewer may use the local \
                 network in System Settings, Privacy & Security, Local Network."
            ),
            Tone::Warn,
        ),
        None if !doing.capture && doing.since >= Duration::from_secs(3) => {
            (format!("Nothing has arrived on {from}. Check the port."), Tone::Warn)
        }
        None if doing.capture => (format!("Playing {from}"), Tone::Plain),
        None => (format!("Waiting for packets on {from}"), Tone::Plain),
    }
}

#[cfg(test)]
mod tests {
    use st2110_media::merge::{LegCounts, Skew};
    use st2110_media::receive::{LegReport, Spread, VideoReport};

    use super::*;

    fn values(rows: &[Row]) -> Vec<(String, String, Tone)> {
        rows.iter().map(|r| (r.label.clone(), r.value.clone(), r.tone)).collect()
    }

    fn plain(label: &str, value: &str) -> (String, String, Tone) {
        (label.into(), value.into(), Tone::Plain)
    }

    #[test]
    fn counts_in_thousands() {
        let got: Vec<String> = [0, 7, 999, 1000, 12_345, 1_234_567].into_iter().map(count).collect();
        assert_eq!(got, ["0", "7", "999", "1,000", "12,345", "1,234,567"]);
        assert_eq!(
            (span(12.34), span(245.0), span(3725.0)),
            ("12.3 s".into(), "4 min 05 s".into(), "1 h 02 min".into())
        );
    }

    #[test]
    fn says_what_a_clean_stream_brought() {
        let mut report = Report {
            legs: vec![LegReport::default()],
            passed: 1_234_567,
            megabits_per_second: 2478.34,
            seconds: 12.34,
            video: Some(VideoReport { frame_rate: Some(50.0), ..VideoReport::default() }),
            ..Report::default()
        };
        report.latency = Some(Spread { min: 12.0, mean: 80.04, max: 250.06, count: 600 });
        let seen = Seen { frames: 1250, whole: true, report: Some(report), ..Seen::default() };
        assert_eq!(
            values(&rows(&seen)),
            [
                plain("Frames", "1,250"),
                plain("Frame rate", "50.000 a second"),
                plain("Packets", "1,234,567, none lost"),
                plain("Data rate", "2478.3 Mb/s"),
                plain("Latency", "12.0 to 250.1 µs, mean 80.0 µs"),
                plain("Time", "12.3 s"),
            ]
        );
    }

    #[test]
    fn marks_what_went_wrong() {
        let leg = |received, lost| LegReport {
            rtp: LegCounts { received, lost, ..LegCounts::default() },
            ..LegReport::default()
        };
        let report = Report {
            legs: vec![leg(1000, 0), leg(990, 10)],
            passed: 1000,
            lost: 3,
            too_late: 2,
            skew: Some(Skew { pairs: 990, max_ns: 12_345, mean_ns: 800.0 }),
            class: Some("B".into()),
            seconds: 2.0,
            ..Report::default()
        };
        let seen =
            Seen { frames: 100, incomplete: 2, missing: 3, whole: true, report: Some(report), ..Seen::default() };
        let rows = values(&rows(&seen));
        assert_eq!(rows[0], ("Frames".into(), "100, 2 incomplete (3 packets missing)".into(), Tone::Bad));
        assert_eq!(rows[1], ("Merged".into(), "1,000, 3 lost, 2 too late".into(), Tone::Bad));
        assert_eq!(rows[2], plain("Leg 1", "1,000 packets"));
        assert_eq!(rows[3], ("Leg 2".into(), "990 packets, 10 lost".into(), Tone::Warn));
        assert_eq!(rows[5], plain("Legs apart", "at most 12.3 µs: ST 2022-7 class B"));
        // Before any report, only what the frames say.
        let early = Seen { frames: 3, ..Seen::default() };
        assert_eq!(values(&super::rows(&early)), [("Frames".into(), "3, none whole yet".into(), Tone::Warn)]);
    }

    #[test]
    fn says_what_receiving_is_doing() {
        let doing =
            Doing { from: "en7 (192.168.10.20)", capture: false, running: true, stopped: false, since: Duration::ZERO };
        let waiting = Seen::default();
        assert_eq!(state(&doing, &waiting), ("Waiting for packets on en7 (192.168.10.20)".into(), Tone::Plain));
        let later = Doing { since: Duration::from_secs(4), ..doing };
        let (text, tone) = state(&later, &waiting);
        assert!(text.starts_with("Nothing has arrived on en7 (192.168.10.20). Check the port"), "{text}");
        assert_eq!(tone, Tone::Warn);
        let flowing = Seen { frames: 10, quiet: Some(Duration::from_millis(20)), ..Seen::default() };
        assert_eq!(state(&later, &flowing), ("Receiving on en7 (192.168.10.20)".into(), Tone::Plain));
        let quiet = Seen { quiet: Some(Duration::from_millis(5300)), ..flowing.clone() };
        assert_eq!(state(&later, &quiet), ("Nothing for 5 s from en7 (192.168.10.20)".into(), Tone::Bad));
        let capture = Doing { from: "bars.pcap", capture: true, ..later };
        assert_eq!(state(&capture, &waiting), ("Playing bars.pcap".into(), Tone::Plain));
        let ended = Doing { running: false, ..capture };
        assert_eq!(state(&ended, &flowing), ("The capture bars.pcap has ended".into(), Tone::Plain));
        let stopped = Doing { stopped: true, ..ended };
        assert_eq!(state(&stopped, &flowing), ("Stopped".into(), Tone::Plain));
    }
}
