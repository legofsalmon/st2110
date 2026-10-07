//! Receiving a stream on a thread of its own, from the network or from a capture played
//! at the pace it was captured, into a [`Monitor`] that the window reads.

use std::fmt;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use st2110_media::describe::{Description, Media};
use st2110_media::format::VideoFormat;
use st2110_media::live::Monitor;
use st2110_media::net::{self, TAI_UTC_2017};
use st2110_media::pixels::Converter;
use st2110_media::receive::Session;
use st2110_media::replay::{as_captured, replay};

/// Where a stream's SDP file came from.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Origin {
    /// A file.
    File(PathBuf),
    /// The network: a stream found there, by the name the list gives it, and how it was
    /// found.
    Network { name: String, by: String },
}

/// A stream's SDP file, read.
pub(crate) struct Stream {
    pub(crate) origin: Origin,
    /// The SDP file, as it was read.
    pub(crate) sdp: String,
    pub(crate) description: Description,
    /// How the SDP file's legs were read.
    pub(crate) notes: Vec<String>,
    /// For video, its format and how to unpack its frames.
    pub(crate) video: Option<(VideoFormat, Converter)>,
}

impl Stream {
    /// Reads an SDP file, or says why its stream cannot be received.
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", file_name(path)))?;
        Self::read(text, Origin::File(path.to_path_buf()))
    }

    /// Reads an SDP file's text, or says why its stream cannot be received.
    pub(crate) fn read(sdp: String, origin: Origin) -> Result<Self, String> {
        let name = match &origin {
            Origin::File(path) => file_name(path),
            Origin::Network { name, .. } => name.clone(),
        };
        Self::understand(sdp, origin).map_err(|e| format!("{name}: {e}"))
    }

    fn understand(sdp: String, origin: Origin) -> Result<Self, String> {
        let (description, notes) = Description::parse(&sdp)?;
        // What a session would refuse, refused now rather than when receiving starts.
        Session::new(&description)?;
        let video = match &description.media {
            Media::Video(format) => Some((format.clone(), Converter::new(format)?)),
            Media::Audio(_) => None,
        };
        Ok(Self { origin, sdp, description, notes, video })
    }

    /// What playing the stream an SDP file describes would show, such as
    /// `1920x1080p50 YCbCr-4:2:2 10-bit`, or why it cannot be played.
    pub(crate) fn playable(sdp: &str) -> Result<String, String> {
        let origin = Origin::Network { name: String::new(), by: String::new() };
        Self::understand(sdp.to_string(), origin).map(|stream| stream.format())
    }

    /// The stream's name: as the list of streams found names it, or as its SDP file
    /// does, or its file's.
    pub(crate) fn name(&self) -> String {
        match (&self.origin, self.description.name.trim()) {
            (Origin::Network { name, .. }, _) => name.clone(),
            (Origin::File(path), "") => file_name(path),
            (Origin::File(_), name) => name.to_string(),
        }
    }

    /// The stream's format: `1920x1080p50 YCbCr-4:2:2 10-bit`.
    pub(crate) fn format(&self) -> String {
        match &self.description.media {
            Media::Video(format) => format.to_string(),
            Media::Audio(format) => format.to_string(),
        }
    }
}

/// A file's name, to say which file.
pub(crate) fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned())
}

/// Where the packets come from.
pub(crate) enum Source {
    /// The network, on the port with this address, or the one the system picks.
    Network(Option<Ipv4Addr>),
    /// A capture file, played at the pace it was captured.
    Capture(PathBuf),
}

enum Input {
    Network(Vec<UdpSocket>),
    Capture(PathBuf, st2110_pcap::Reader<BufReader<File>>),
}

/// A stream being received on a thread of its own.
pub(crate) struct Run {
    /// What has arrived.
    pub(crate) monitor: Arc<Monitor>,
    /// What the system allowed that is worth knowing: too small a receive buffer.
    pub(crate) warnings: Vec<String>,
    /// Whether the packets come from a capture.
    pub(crate) capture: bool,
    /// How receiving ended, once it has: `Err` says why it failed.
    pub(crate) ended: Option<Result<(), String>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl Run {
    /// Starts receiving the stream from `source`, calling `wake` whenever something
    /// arrives, or says why it cannot. Opens the sockets or the capture first, so that
    /// what cannot be received fails here.
    pub(crate) fn start(
        stream: &Stream,
        source: &Source,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let mut session = Session::new(&stream.description)?;
        let mut warnings = Vec::new();
        let input = match source {
            Source::Network(port) => {
                let mut sockets = Vec::new();
                for (i, leg) in stream.description.legs.iter().enumerate() {
                    let (socket, buffer) = net::listen(leg, *port).map_err(|e| format!("Cannot receive {leg}: {e}"))?;
                    if stream.video.is_some() && buffer < 4 << 20 {
                        warnings.push(format!(
                            "The system gave leg {} a receive buffer of {} KiB, which a burst of video overflows; \
                             raise {}.",
                            i + 1,
                            buffer / 1024,
                            net::buffer_limit()
                        ));
                    }
                    sockets.push(socket);
                }
                Input::Network(sockets)
            }
            Source::Capture(path) => {
                let failed = |e: &dyn fmt::Display| format!("{}: {e}", file_name(path));
                let file = File::open(path).map_err(|e| failed(&e))?;
                let reader = st2110_pcap::Reader::new(BufReader::new(file)).map_err(|e| failed(&e))?;
                Input::Capture(path.clone(), reader)
            }
        };
        let monitor = Arc::new(Monitor::new(wake));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (monitor, stop) = (Arc::clone(&monitor), Arc::clone(&stop));
            thread::Builder::new()
                .name("receive".into())
                .spawn(move || {
                    let mut sink = &*monitor;
                    let result = match input {
                        Input::Network(sockets) => {
                            net::receive_until_stopped(&mut session, sockets, &stop, TAI_UTC_2017, &mut sink)
                                .map_err(|e| e.to_string())
                        }
                        Input::Capture(path, reader) => {
                            replay(&mut session, reader, TAI_UTC_2017, &mut sink, as_captured(&stop))
                                .map(drop)
                                .map_err(|e| format!("{}: {e}", file_name(&path)))
                        }
                    };
                    monitor.end(Some(session.report()));
                    result
                })
                .map_err(|e| format!("Cannot start receiving: {e}"))?
        };
        let capture = matches!(source, Source::Capture(_));
        Ok(Self { monitor, warnings, capture, ended: None, stop, thread: Some(thread) })
    }

    /// Whether receiving goes on. Notes how it ended, once it has.
    pub(crate) fn running(&mut self) -> bool {
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            self.join();
        }
        self.thread.is_some()
    }

    /// Stops receiving and waits for it to end, which takes a twentieth of a second or
    /// so: as long as receiving waits for a packet before it looks again.
    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.join();
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.ended = Some(thread.join().unwrap_or_else(|_| Err("the receiving thread panicked".into())));
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A network port to receive on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Port {
    /// What the system calls it: `en0`.
    pub(crate) name: String,
    pub(crate) address: Ipv4Addr,
}

impl Port {
    /// `en0  192.168.1.20`.
    pub(crate) fn label(&self) -> String {
        if self.address.is_loopback() {
            format!("{}  {}, this computer", self.name, self.address)
        } else {
            format!("{}  {}", self.name, self.address)
        }
    }
}

/// The machine's ports that have IPv4 addresses, by name, with loopback last. A port
/// with more than one address is listed once, by its lowest: any of them joins a
/// multicast group on the same port.
pub(crate) fn ports() -> Vec<Port> {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    let mut ports: Vec<Port> = interfaces
        .into_iter()
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(v4) => Some(Port { name: interface.name, address: v4.ip }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    ports.sort_by(|a, b| {
        (a.address.is_loopback(), &a.name, a.address).cmp(&(b.address.is_loopback(), &b.name, b.address))
    });
    ports.dedup_by(|a, b| a.name == b.name);
    ports
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;
    use std::time::{Duration, Instant};

    use st2110_media::describe::{Clock, Leg};
    use st2110_media::files::{Capture, UNKNOWN_SOURCE};
    use st2110_media::send::Sender;

    use super::*;

    const NANOS: i128 = 1_000_000_000;

    /// A scratch directory of the test's own, emptied first.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("st2110-viewer-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bars() -> Description {
        Description {
            name: "Bars".into(),
            media: Media::Video(VideoFormat::from_name("320x180p25").unwrap()),
            payload_type: 96,
            legs: vec![Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: None }],
            clock: Some(Clock::Traceable),
            ttl: 32,
        }
    }

    /// Writes `stream`'s SDP file and a capture of `seconds` of it into `dir`.
    fn write_stream(dir: &Path, stream: &Description, seconds: f64) -> (PathBuf, PathBuf) {
        let sdp = dir.join("bars.sdp");
        fs::write(&sdp, stream.sdp(1)).unwrap();
        let destination = stream.legs[0].destination;
        let legs = vec![(SocketAddrV4::new(UNKNOWN_SOURCE, destination.port()), destination)];
        let mut capture = Capture::new(Vec::new(), legs, 32, 37).unwrap();
        let mut sender = Sender::new(stream, 1000, -18.0, 0x1234, 0).unwrap();
        let start = 1_790_510_437 * NANOS;
        sender.run(&mut capture, start, start + (seconds * 1e9) as i128).unwrap();
        let pcap = dir.join("bars.pcap");
        fs::write(&pcap, capture.into_inner()).unwrap();
        (sdp, pcap)
    }

    #[test]
    fn plays_a_capture_until_it_ends() {
        let dir = scratch("capture");
        let (sdp, pcap) = write_stream(&dir, &bars(), 0.4);
        let stream = Stream::open(&sdp).unwrap();
        assert_eq!((stream.name(), stream.format()), ("Bars".into(), "320x180p25 YCbCr-4:2:2 10-bit".into()));
        let mut run = Run::start(&stream, &Source::Capture(pcap), || {}).unwrap();
        let started = Instant::now();
        while run.running() {
            assert!(started.elapsed() < Duration::from_secs(10), "the capture never ended");
            drop(run.monitor.wait(Duration::from_millis(50)));
        }
        assert_eq!(run.ended, Some(Ok(())));
        let latest = run.monitor.lock();
        assert!(latest.ended && latest.whole);
        assert_eq!((latest.frames, latest.incomplete), (10, 0));
        let report = latest.report.as_ref().unwrap();
        assert!(report.problems.is_empty(), "{report:?}");
        drop(latest);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stops_when_asked() {
        let dir = scratch("stop");
        let (sdp, pcap) = write_stream(&dir, &bars(), 3.0);
        let stream = Stream::open(&sdp).unwrap();
        let mut run = Run::start(&stream, &Source::Capture(pcap), || {}).unwrap();
        assert!(run.running());
        let started = Instant::now();
        run.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!run.running());
        assert_eq!(run.ended, Some(Ok(())));
        assert!(run.monitor.lock().ended);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn says_what_cannot_be_opened() {
        let dir = scratch("errors");
        let missing = dir.join("missing.sdp");
        assert!(Stream::open(&missing).err().unwrap().starts_with("missing.sdp: "));
        let junk = dir.join("junk.sdp");
        fs::write(&junk, "not an SDP file").unwrap();
        assert!(Stream::open(&junk).err().unwrap().starts_with("junk.sdp: "));
        let (sdp, _) = write_stream(&dir, &bars(), 0.04);
        let stream = Stream::open(&sdp).unwrap();
        let not_capture = Source::Capture(sdp.clone());
        let error = Run::start(&stream, &not_capture, || {}).err().unwrap();
        assert_eq!(error, "bars.sdp: not a pcap or pcapng file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lists_ports_with_loopback_last() {
        let ports = ports();
        let loopback = ports.iter().position(|p| p.address.is_loopback());
        if let Some(i) = loopback {
            assert!(ports[i..].iter().all(|p| p.address.is_loopback()), "{ports:?}");
        }
        let port = Port { name: "en7".into(), address: Ipv4Addr::new(192, 168, 10, 20) };
        assert_eq!(port.label(), "en7  192.168.10.20");
        let port = Port { name: "lo0".into(), address: Ipv4Addr::LOCALHOST };
        assert_eq!(port.label(), "lo0  127.0.0.1, this computer");
    }
}
