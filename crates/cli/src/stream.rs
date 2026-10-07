//! `st2110 send` and `st2110 receive`: send colour bars or a tone as an ST 2110 stream,
//! and receive a stream and report what arrived.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use st2110_discover::Announcer;
use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::files::{Capture, UNKNOWN_SOURCE, WavWriter, write_png};
use st2110_media::format::{AudioFormat, Packing, Range, SenderType, VideoFormat};
use st2110_media::net::{self, Transmitter};
use st2110_media::receive::{DEFAULT_MAX_SKEW_NS, Report, Session, Sink};
use st2110_media::replay;
use st2110_media::send::{SendCounts, Sender, default_sender_type};
use st2110_media::video::FrameInfo;

use crate::{Format, Style, read, seconds};

const NANOS: i128 = 1_000_000_000;

/// How often the stream is announced by SAP: as AES67 devices do, rather than the five
/// minutes RFC 2974 suggests, for listeners to see soon that a sender has stopped.
const SAP_EVERY: Duration = Duration::from_secs(30);

/// What to send.
#[derive(Subcommand)]
pub(crate) enum Signal {
    /// Colour bars, EBU 100/0/75/0, over a black strip in which a white box steps
    /// across a little each frame.
    Video {
        #[command(flatten)]
        video: VideoArgs,
        #[command(flatten)]
        send: SendArgs,
    },
    /// A tone, the same on every channel.
    Audio {
        #[command(flatten)]
        audio: AudioArgs,
        #[command(flatten)]
        send: SendArgs,
    },
}

#[derive(Args)]
pub(crate) struct VideoArgs {
    /// The picture: 1080p50, 2160p59.94, 720p60000/1001, or any size, such as
    /// 1280x720p25. Progressive only.
    #[arg(value_name = "FORMAT", default_value = "1080p50")]
    format: String,
    /// The sampling: YCbCr-4:2:2, YCbCr-4:4:4, RGB or KEY.
    #[arg(long, default_value = "YCbCr-4:2:2")]
    sampling: String,
    /// Bits a sample: 8, 10, 12 or 16.
    #[arg(long, default_value = "10")]
    depth: String,
    /// The colorimetry, such as BT709 or BT2020.
    #[arg(long, default_value = "BT709")]
    colorimetry: String,
    /// The transfer characteristic, such as SDR, PQ or HLG.
    #[arg(long, default_value = "SDR")]
    tcs: String,
    /// The range of code values.
    #[arg(long, value_enum, default_value_t = RangeArg::Narrow)]
    range: RangeArg,
    /// How pixel groups are packed into packets: general (2110GPM) or block (2110BPM).
    #[arg(long, value_enum, default_value_t = PackingArg::Gpm)]
    packing: PackingArg,
    /// The ST 2110-21 sender type the SDP file declares. Pacing on ordinary sockets
    /// can keep to wide at best, which it declares below 900 000 packets a second;
    /// ST 2110-21 defines no wide sender from there, so it declares narrow-linear.
    #[arg(long, value_enum)]
    sender_type: Option<SenderArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum RangeArg {
    Narrow,
    Fullprotect,
    Full,
}

#[derive(Clone, Copy, ValueEnum)]
enum PackingArg {
    Gpm,
    Bpm,
}

#[derive(Clone, Copy, ValueEnum)]
enum SenderArg {
    Narrow,
    NarrowLinear,
    Wide,
}

#[derive(Args)]
pub(crate) struct AudioArgs {
    /// Channels, 1 to 64.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=64))]
    channels: u16,
    /// Samples a second: 48000, 96000 or 44100.
    #[arg(long, value_name = "HZ", default_value_t = 48_000)]
    sample_rate: u32,
    /// Bits a sample: 24 (L24) or 16 (L16).
    #[arg(long, default_value_t = 24)]
    bits: u8,
    /// Milliseconds of audio in each packet: 1, or 0.125 as levels B and C have. At
    /// 44.1 kHz, the nearest whole number of samples: 1 ms is 44 of them.
    #[arg(long, value_name = "MS", default_value_t = 1.0)]
    packet_time: f64,
    /// The tone's frequency in Hz.
    #[arg(long, value_name = "HZ", default_value_t = 1000)]
    tone: u32,
    /// The tone's level in dB below full scale; EBU R 68 lines up at −18.
    #[arg(long, value_name = "DBFS", default_value_t = -18.0, allow_negative_numbers = true)]
    level: f64,
}

#[derive(Args)]
pub(crate) struct SendArgs {
    /// Where to send: a multicast group or a unicast address, and a port, such as
    /// 239.1.1.1:5004. Give it twice for the two legs of an ST 2022-7 pair.
    #[arg(long, value_name = "ADDRESS:PORT", required = true)]
    to: Vec<SocketAddrV4>,
    /// The address of the network interface to send from; the one the routing table
    /// picks when omitted. Give it once for every leg, or twice to send each leg from
    /// its own.
    #[arg(long, value_name = "ADDRESS")]
    interface: Vec<Ipv4Addr>,
    /// The RTP payload type: 96 for video and 97 for audio when omitted.
    #[arg(long, value_parser = clap::value_parser!(u8).range(96..=127))]
    payload_type: Option<u8>,
    /// The time to live of multicast packets.
    #[arg(long, default_value_t = 32)]
    ttl: u8,
    /// The DSCP value to mark packets with: AF41, as AES67 marks media, by default.
    #[arg(long, default_value_t = 34, value_parser = clap::value_parser!(u8).range(0..=63))]
    dscp: u8,
    /// The reference clock to name in the SDP file: traceable, <grandmaster>:<domain>
    /// such as 08-00-11-FF-FE-21-E1-B0:127, or localmac=<MAC address>. Name the
    /// grandmaster when the system clock follows PTP; localmac with this machine's MAC
    /// address, which only Linux can find, when omitted.
    #[arg(long, value_name = "CLOCK")]
    clock: Option<String>,
    /// The session name in the SDP file.
    #[arg(long)]
    name: Option<String>,
    /// Seconds to send for; until stopped when omitted.
    #[arg(long, value_name = "SECONDS")]
    duration: Option<f64>,
    /// Write the SDP file here, rather than to standard output.
    #[arg(long, value_name = "FILE")]
    sdp: Option<PathBuf>,
    /// Announce the stream by SAP, as AES67 devices do, for `st2110 discover` and ST
    /// 2110 Viewer to find: to 239.255.255.255:9875, or --sap=ADDRESS:PORT, every 30
    /// seconds, and withdrawn when --duration ends.
    #[arg(
        long,
        value_name = "ADDRESS:PORT",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "239.255.255.255:9875",
        conflicts_with = "pcap"
    )]
    sap: Option<SocketAddrV4>,
    /// Write the packets into a capture file, each stamped with its time, instead of
    /// sending them. Needs --duration.
    #[arg(long, value_name = "FILE", requires = "duration")]
    pcap: Option<PathBuf>,
    /// TAI − UTC in seconds.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = st2110_ptp::TAI_UTC_2017,
        allow_negative_numbers = true,
        value_parser = crate::offset()
    )]
    tai_utc: i32,
}

/// A number that differs from run to run, for SSRCs and sequence numbers: RFC 3550
/// asks for random ones, and this need not be unpredictable, only different.
fn scramble(salt: u64) -> u64 {
    let mut x = (net::tai_now(0) as u64) ^ (u64::from(std::process::id()) << 32) ^ salt;
    // SplitMix64's finaliser.
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// One of this machine's MAC addresses, written as `localmac=` wants it, from Linux's
/// `/sys/class/net`.
fn local_mac() -> Option<String> {
    let mut names: Vec<_> =
        fs::read_dir("/sys/class/net").ok()?.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
    names.sort();
    names.iter().filter(|name| *name != "lo").find_map(|name| {
        let address = fs::read_to_string(Path::new("/sys/class/net").join(name).join("address")).ok()?;
        let address = address.trim();
        (address.len() == 17 && address != "00:00:00:00:00:00").then(|| address.replace(':', "-").to_ascii_uppercase())
    })
}

fn video_format(args: &VideoArgs) -> Result<VideoFormat, String> {
    let mut format = VideoFormat::from_name(&args.format)?;
    format.sampling = args.sampling.parse().map_err(|()| format!("{} is not an ST 2110-20 sampling", args.sampling))?;
    format.depth = args.depth.parse().map_err(|()| format!("{} is not an ST 2110-20 depth", args.depth))?;
    format.colorimetry = args.colorimetry.clone();
    format.transfer = args.tcs.clone();
    format.range = match args.range {
        RangeArg::Narrow => Range::Narrow,
        RangeArg::Fullprotect => Range::FullProtect,
        RangeArg::Full => Range::Full,
    };
    format.packing = match args.packing {
        PackingArg::Gpm => Packing::General,
        PackingArg::Bpm => Packing::Block,
    };
    format.check()?;
    format.sender_type = match args.sender_type {
        Some(SenderArg::Narrow) => SenderType::Narrow,
        Some(SenderArg::NarrowLinear) => SenderType::NarrowLinear,
        Some(SenderArg::Wide) => SenderType::Wide,
        None => default_sender_type(&format)?,
    };
    Ok(format)
}

fn audio_format(args: &AudioArgs) -> Result<AudioFormat, String> {
    let format =
        AudioFormat { channels: args.channels, sample_rate: args.sample_rate, bits: args.bits, ..AudioFormat::new(1) }
            .with_packet_time(args.packet_time)?;
    format.check()?;
    Ok(format)
}

pub(crate) fn send(signal: &Signal) -> io::Result<ExitCode> {
    match prepare(signal) {
        Ok(ready) => ready.run(),
        Err(e) => {
            eprintln!("st2110: {e}");
            Ok(ExitCode::from(2))
        }
    }
}

/// A stream ready to send, its SDP file written.
struct Ready<'a> {
    args: &'a SendArgs,
    description: Description,
    sender: Sender,
    transmitter: Option<Transmitter>,
    /// What announces it by SAP, having announced it once.
    announcer: Option<Announcer>,
}

/// Announces a stream by SAP every 30 seconds on a thread of its own, until dropped,
/// which withdraws the announcement.
struct Announcing {
    stop: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Announcing {
    fn start(announcer: Announcer) -> Self {
        let (stop, stopped) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(SAP_EVERY) {
                let _ = announcer.announce();
            }
            let _ = announcer.delete();
        });
        Self { stop, thread: Some(thread) }
    }
}

impl Drop for Announcing {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn prepare(signal: &Signal) -> Result<Ready<'_>, String> {
    let (media, args, tone, level) = match signal {
        Signal::Video { video, send } => (Media::Video(video_format(video)?), send, 1000, -18.0),
        Signal::Audio { audio, send } => (Media::Audio(audio_format(audio)?), send, audio.tone, audio.level),
    };
    if args.to.len() > 2 {
        return Err("give --to once, or twice for an ST 2022-7 pair".into());
    }
    if args.interface.len() > args.to.len() {
        return Err("give --interface no more times than --to".into());
    }
    args.duration.map(|d| seconds("--duration", d)).transpose()?;
    let clock = match &args.clock {
        Some(text) => Clock::parse(text)?,
        None => Clock::LocalMac(local_mac().ok_or(
            "this machine's MAC address cannot be found for the SDP file's reference clock: \
             give --clock localmac=<its MAC address>, or --clock <grandmaster>:<domain> when \
             the system clock follows PTP",
        )?),
    };
    let video = matches!(media, Media::Video(_));
    let name = args.name.clone().unwrap_or_else(|| {
        format!("st2110 {} {}", if video { "bars" } else { "tone" }, media).replace(['\r', '\n'], " ")
    });
    let interfaces: Vec<Option<Ipv4Addr>> =
        (0..args.to.len()).map(|i| args.interface.get(i).or(args.interface.last()).copied()).collect();
    let mut description = Description {
        name,
        media,
        payload_type: args.payload_type.unwrap_or(if video { 96 } else { 97 }),
        legs: args.to.iter().map(|&destination| Leg { destination, source: None }).collect(),
        clock: Some(clock),
        ttl: args.ttl,
    };
    let transmitter = if args.pcap.is_some() {
        for (leg, interface) in description.legs.iter_mut().zip(&interfaces) {
            leg.source = Some(interface.unwrap_or(UNKNOWN_SOURCE));
        }
        None
    } else {
        let t = Transmitter::new(&description.legs, &interfaces, args.ttl, args.dscp, args.tai_utc)
            .map_err(|e| format!("cannot open a socket to send from: {e}"))?;
        for (leg, &source) in description.legs.iter_mut().zip(t.sources()) {
            leg.source = (!source.is_unspecified()).then_some(source);
        }
        Some(t)
    };
    description.check()?;
    let ssrc = scramble(1) as u32;
    let sender = Sender::new(&description, tone, level, ssrc, scramble(2) as u32)?;
    let sdp = description.sdp(u64::try_from(net::tai_now(0) / NANOS).unwrap_or(0));
    let announcer = match args.sap {
        Some(to) => Some(
            Announcer::new(&sdp, to, interfaces[0], args.ttl)
                .and_then(|announcer| announcer.announce().map(|()| announcer))
                .map_err(|e| format!("cannot announce the stream by SAP to {to}: {e}"))?,
        ),
        None => None,
    };
    match &args.sdp {
        Some(path) => fs::write(path, &sdp).map_err(|e| format!("{}: {e}", path.display()))?,
        None => {
            let mut out = io::stdout().lock();
            out.write_all(sdp.as_bytes()).and_then(|()| out.flush()).map_err(|e| e.to_string())?;
        }
    }
    Ok(Ready { args, description, sender, transmitter, announcer })
}

impl Ready<'_> {
    fn run(mut self) -> io::Result<ExitCode> {
        let args = self.args;
        let duration = args.duration.map_or(i128::MAX / 4, |d| (d * 1e9) as i128);
        // A moment's grace, for whoever reads the SDP file to join.
        let start = net::tai_now(args.tai_utc) + NANOS / 10;
        let legs = self.description.legs.len();
        let summary = |counts: SendCounts| {
            let (sent, skipped) = match &self.description.media {
                Media::Video(_) => (plural(counts.frames, "frame"), plural(counts.skipped, "frame")),
                Media::Audio(a) => {
                    let time = |n: u64| format!("{:.3} s", n as f64 * a.packet_time());
                    (time(counts.frames), time(counts.skipped))
                }
            };
            let mut line = format!(
                "sent {sent} of {} ({}) on {}",
                self.description.media,
                plural(counts.packets, "packet"),
                plural(legs as u64, "leg")
            );
            if counts.skipped > 0 {
                line.push_str(&format!("; left out {skipped} whose time had passed"));
            }
            line
        };
        let announcing = self.announcer.take().map(Announcing::start);
        match (&args.pcap, self.transmitter.take()) {
            (Some(path), _) => {
                let file =
                    File::create(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
                let ports: Vec<(SocketAddrV4, SocketAddrV4)> = self
                    .description
                    .legs
                    .iter()
                    .map(|l| {
                        (SocketAddrV4::new(l.source.unwrap_or(UNKNOWN_SOURCE), l.destination.port()), l.destination)
                    })
                    .collect();
                let mut capture = Capture::new(BufWriter::new(file), ports, args.ttl, args.tai_utc)?;
                let counts = self.sender.run(&mut capture, start, start + duration)?;
                capture.into_inner().flush()?;
                eprintln!("st2110: {} into {}", summary(counts), path.display());
            }
            (None, Some(mut transmitter)) => {
                let counts = self.sender.run(&mut transmitter, start, start + duration)?;
                let t = transmitter.counts();
                let mut line = summary(counts);
                if t.late > 0 {
                    let went = if t.late == 1 { "packet went" } else { "packets went" };
                    line.push_str(&format!(
                        "; {} {went} more than 100 µs late, the latest by {:.0} µs",
                        t.late,
                        t.latest_ns as f64 / 1000.0
                    ));
                }
                if t.refused > 0 {
                    line.push_str(&format!("; the system's buffers had no room for {}", plural(t.refused, "packet")));
                }
                if let Some(to) = args.sap {
                    drop(announcing);
                    line.push_str(&format!("; announced it by SAP to {to}, and withdrew it"));
                }
                eprintln!("st2110: {line}");
            }
            (None, None) => unreachable!("a transmitter unless writing a capture"),
        }
        Ok(ExitCode::SUCCESS)
    }
}

fn plural(count: u64, noun: &str) -> String {
    crate::plural(count as usize, noun)
}

#[derive(Args)]
pub(crate) struct ReceiveArgs {
    /// The stream's SDP file; `-` reads standard input.
    sdp: PathBuf,
    /// The address of the network interface to receive on; the one the system picks
    /// when omitted. Give it once for every leg, or twice to receive each leg on its
    /// own.
    #[arg(long, value_name = "ADDRESS")]
    interface: Vec<Ipv4Addr>,
    /// Seconds to receive for.
    #[arg(long, value_name = "SECONDS", default_value_t = 5.0)]
    duration: f64,
    /// Read the packets from a capture file instead of the network; `-` reads standard
    /// input.
    #[arg(long, value_name = "FILE")]
    pcap: Option<PathBuf>,
    /// Save the last frame that arrived whole as a PNG picture.
    #[arg(long, value_name = "FILE")]
    png: Option<PathBuf>,
    /// Save the audio as a WAV file, with silence where packets were missing.
    #[arg(long, value_name = "FILE")]
    wav: Option<PathBuf>,
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

/// Where received audio goes, when it is saved.
struct Saver {
    wav: Option<WavWriter<BufWriter<File>>>,
    error: Option<io::Error>,
}

impl Sink for Saver {
    fn frame(&mut self, _: &FrameInfo, _: &[u8]) {}

    fn samples(&mut self, samples: &[i32]) {
        if let (Some(wav), None) = (&mut self.wav, &self.error)
            && let Err(e) = wav.write(samples)
        {
            self.error = Some(e);
        }
    }
}

/// What `st2110 receive` found.
#[derive(Serialize)]
pub(crate) struct Received {
    pub(crate) file: String,
    /// How the SDP file's legs were read.
    pub(crate) sdp_notes: Vec<String>,
    /// Where the packets came from: the network or a capture.
    pub(crate) input: String,
    /// When reading a capture: how its clock was moved onto PTP time, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) capture_shift: Option<i32>,
    #[serde(flatten)]
    pub(crate) report: Report,
}

/// A stream to receive: its SDP file read, and a session that receives it.
pub(crate) struct Opened {
    pub(crate) file: String,
    pub(crate) description: Description,
    pub(crate) sdp_notes: Vec<String>,
    pub(crate) session: Session,
}

/// Reads a stream's SDP file and makes a session that waits up to `max_skew`
/// milliseconds for a missing packet, to receive on `interfaces`, or says why not and
/// gives the exit code.
pub(crate) fn open(sdp: &Path, max_skew: f64, interfaces: &[Ipv4Addr]) -> Result<Opened, ExitCode> {
    let file = sdp.display().to_string();
    let failed = |e: &dyn std::fmt::Display| {
        eprintln!("st2110: {file}: {e}");
        ExitCode::from(2)
    };
    let text = read(sdp).map_err(|e| failed(&e))?;
    let (description, sdp_notes) = Description::parse(&text).map_err(|e| failed(&e))?;
    if !(0.0..=1000.0).contains(&max_skew) {
        eprintln!("st2110: --max-skew {max_skew} is not 0 to 1000 ms");
        return Err(ExitCode::from(2));
    }
    let session = Session::with_max_skew(&description, (max_skew * 1e6).round() as i64).map_err(|e| failed(&e))?;
    if interfaces.len() > description.legs.len() {
        eprintln!("st2110: give --interface no more times than the stream has legs ({})", description.legs.len());
        return Err(ExitCode::from(2));
    }
    Ok(Opened { file, description, sdp_notes, session })
}

/// Opens a socket for each of the stream's legs on `interfaces`, once for every leg or
/// once for each, or says why not and gives the exit code.
pub(crate) fn sockets(description: &Description, interfaces: &[Ipv4Addr]) -> Result<Vec<UdpSocket>, ExitCode> {
    let mut sockets = Vec::new();
    for (i, leg) in description.legs.iter().enumerate() {
        match net::listen(leg, interfaces.get(i).or(interfaces.last()).copied()) {
            Ok((socket, buffer)) => {
                if matches!(description.media, Media::Video(_)) && buffer < 4 << 20 {
                    eprintln!(
                        "st2110: the system gave leg {} a receive buffer of {} KiB, which a burst of video \
                         overflows; raise {}",
                        i + 1,
                        buffer / 1024,
                        net::buffer_limit()
                    );
                }
                sockets.push(socket);
            }
            Err(e) => {
                eprintln!("st2110: cannot receive {leg}: {e}");
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(sockets)
}

pub(crate) fn receive(args: &ReceiveArgs) -> io::Result<ExitCode> {
    let Opened { file, description, sdp_notes, mut session } = match open(&args.sdp, args.max_skew, &args.interface) {
        Ok(opened) => opened,
        Err(code) => return Ok(code),
    };
    let mut saver = Saver { wav: None, error: None };
    if let Some(path) = &args.wav {
        let Media::Audio(format) = &description.media else {
            eprintln!("st2110: --wav is for audio streams, and {file} describes video");
            return Ok(ExitCode::from(2));
        };
        let file = File::create(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        saver.wav = Some(WavWriter::new(BufWriter::new(file), format.channels, format.sample_rate, format.bits)?);
    }
    let mut png = None;
    if let Some(path) = &args.png {
        if !matches!(description.media, Media::Video(_)) {
            eprintln!("st2110: --png is for video streams, and {file} describes audio");
            return Ok(ExitCode::from(2));
        }
        // Now, so that a file it cannot write fails before receiving rather than after.
        png = Some(File::create(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?);
    }
    let mut capture_shift = None;
    let input = match &args.pcap {
        Some(path) => {
            let shift = from_capture(&mut session, capture(path)?, path, args.tai_utc, &mut saver, |_| true)?;
            capture_shift = shift;
            format!("capture {}", path.display())
        }
        None => {
            let duration = match seconds("--duration", args.duration) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("st2110: {e}");
                    return Ok(ExitCode::from(2));
                }
            };
            let sockets = match sockets(&description, &args.interface) {
                Ok(sockets) => sockets,
                Err(code) => return Ok(code),
            };
            let until = net::tai_now(args.tai_utc) + duration.as_nanos() as i128;
            net::receive(&mut session, sockets, until, args.tai_utc, &mut saver)?;
            "network".to_string()
        }
    };
    if let Some(e) = saver.error.take() {
        eprintln!("st2110: {}: {e}", args.wav.as_deref().unwrap_or(Path::new("")).display());
        return Ok(ExitCode::from(2));
    }
    if let Some(wav) = saver.wav.take() {
        wav.finish()?.flush()?;
    }
    let report = session.report();
    let failed = !report.problems.is_empty();
    let received = Received { file, sdp_notes, input, capture_shift, report };
    {
        let mut out = io::stdout().lock();
        match args.format {
            Format::Text => write_text(&mut out, &received, &description, Style::detect())?,
            Format::Json => {
                serde_json::to_writer_pretty(&mut out, &received)?;
                writeln!(out)?;
            }
        }
        out.flush()?;
    }
    if let (Some(path), Some(file)) = (&args.png, png) {
        match (session.last_whole_frame(), &description.media) {
            (Some(frame), Media::Video(format)) => {
                let rgb = st2110_media::pixels::to_rgb(format, frame).map_err(io::Error::other)?;
                let mut out = BufWriter::new(file);
                write_png(&mut out, format.width, format.height, &rgb)
                    .and_then(|()| out.flush())
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
            }
            _ => {
                drop(file);
                let _ = fs::remove_file(path);
                eprintln!("st2110: no frame arrived whole, so {} was not written", path.display());
            }
        }
    }
    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// A capture being read.
pub(crate) type CaptureReader = st2110_pcap::Reader<BufReader<Box<dyn io::Read + Send>>>;

/// Opens a capture file, or standard input for `-`, and reads its header.
pub(crate) fn capture(path: &Path) -> io::Result<CaptureReader> {
    let input: Box<dyn io::Read + Send> = if path.as_os_str() == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?)
    };
    st2110_pcap::Reader::new(BufReader::new(input))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
}

/// Feeds a capture's datagrams to the session, as [`replay::replay`] does, and says
/// which file it could not read.
pub(crate) fn from_capture(
    session: &mut Session,
    reader: CaptureReader,
    path: &Path,
    tai_utc: i32,
    sink: &mut impl Sink,
    pace: impl FnMut(i128) -> bool,
) -> io::Result<Option<i32>> {
    replay::replay(session, reader, tai_utc, sink, pace)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
}

pub(crate) fn write_text(
    out: &mut impl Write,
    r: &Received,
    description: &Description,
    style: Style,
) -> io::Result<()> {
    let report = &r.report;
    writeln!(out, "{}: {}, from the {}", style.paint("1", &r.file), report.stream, r.input)?;
    if let Some(shift) = r.capture_shift.filter(|&s| s != 0) {
        writeln!(out, "  the capture's clock is taken as UTC, and moved {shift} s onto PTP time")?;
    }
    for (i, leg) in report.legs.iter().enumerate() {
        let mut line = format!("  leg {} {}: {}", i + 1, leg.leg, plural(leg.rtp.received, "packet"));
        for (n, what) in [
            (leg.rtp.lost, "lost"),
            (leg.rtp.reordered, "out of order"),
            (leg.rtp.duplicates, "twice"),
            (leg.rtp.too_late, "too late to merge"),
        ] {
            if n > 0 {
                line.push_str(&format!(", {n} {what}"));
            }
        }
        writeln!(out, "{line}")?;
    }
    let mut lost = if report.lost == 0 { "none lost".to_string() } else { format!("{} lost", report.lost) };
    if report.too_late > 0 {
        lost.push_str(&format!(", {} too late", report.too_late));
    }
    let merged = if report.legs.len() > 1 { "merged: " } else { "" };
    writeln!(
        out,
        "  {merged}{} in {:.3} s, {:.1} Mb/s of RTP, {lost}",
        plural(report.passed, "packet"),
        report.seconds,
        report.megabits_per_second
    )?;
    if let Some(skew) = &report.skew {
        let class = match &report.class {
            Some(class) => format!("ST 2022-7 class {class}"),
            None => "beyond every ST 2022-7 class".into(),
        };
        let (behind, ahead) = if skew.mean_ns < 0.0 { (1, 2) } else { (2, 1) };
        writeln!(
            out,
            "  legs apart: at most {:.1} µs, leg {behind} behind leg {ahead} by {:.1} µs on average: {class}",
            skew.max_ns as f64 / 1000.0,
            skew.mean_ns.abs() / 1000.0
        )?;
    }
    if let Some(video) = &report.video {
        let c = video.counts;
        let mut whole = if c.whole == c.frames { "all whole".to_string() } else { format!("{} whole", c.whole) };
        if c.cut > 0 {
            whole.push_str(&format!(" and {} cut off by the start or end of receiving", c.cut));
        }
        let packets = video.packets_per_frame.map(|p| format!(", {p} packets a frame")).unwrap_or_default();
        let rate = video.frame_rate.map(|r| format!(", {r:.3} frames a second")).unwrap_or_default();
        writeln!(out, "  video: {}, {whole}{packets}{rate}", plural(c.frames, "frame"))?;
    }
    if let Some(audio) = &report.audio {
        let peaks: Vec<String> =
            audio.peaks.iter().map(|p| p.map_or("silent".into(), |db| format!("{db:.1}"))).collect();
        let samples = if let Media::Audio(f) = &description.media {
            format!("{:.3} s", audio.counts.samples as f64 / f64::from(f.sample_rate))
        } else {
            String::new()
        };
        writeln!(
            out,
            "  audio: {samples} in {}, peaks {} dBFS",
            plural(audio.counts.packets, "packet"),
            peaks.join(", ")
        )?;
    }
    if let Some(latency) = &report.latency {
        writeln!(
            out,
            "  latency from RTP timestamp: {:.1} to {:.1} µs, mean {:.1} µs",
            latency.min, latency.max, latency.mean
        )?;
    }
    for note in r.sdp_notes.iter().chain(&report.notes) {
        writeln!(out, "  {}: {note}", style.paint("1;36", "note"))?;
    }
    for problem in &report.problems {
        writeln!(out, "  {}: {problem}", style.paint("1;31", "problem"))?;
    }
    if report.problems.is_empty() {
        writeln!(out, "{}: arrived whole", r.file)?;
    } else {
        writeln!(out, "{}: {}", r.file, plural(report.problems.len() as u64, "problem"))?;
    }
    Ok(())
}
