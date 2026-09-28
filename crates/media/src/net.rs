//! UDP sockets: a transmitter that sends each packet at its time by the system clock,
//! and receivers that join each leg's group.
//!
//! These are ordinary sockets, paced by the sending thread: one packet at a time,
//! waiting for each one's time by sleeping and then spinning. That holds the ST 2110-21
//! wide sender's limits at HD rates on a quiet machine, but not a narrow sender's, and
//! a busy machine will burst. The system clock stands in for PTP: it counts UTC, and
//! TAI is taken to be `tai_utc` seconds ahead of it, as on a machine whose clock
//! `phc2sys` keeps to PTP.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};

use crate::describe::Leg;
use crate::receive::{Session, Sink};
use crate::send::Output;

const NANOS: i128 = 1_000_000_000;

/// Packets later than this after their time count as late.
const LATE: i128 = 100_000;

/// The time now by the system clock, in nanoseconds of TAI.
pub fn tai_now(tai_utc: i32) -> i128 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i128);
    since + i128::from(tai_utc) * NANOS
}

/// Waits until `at`, sleeping while it is far and spinning when it is near, and gives
/// the time it stopped waiting.
fn wait_until(at: i128, tai_utc: i32) -> i128 {
    loop {
        let now = tai_now(tai_utc);
        let left = at - now;
        if left <= 0 {
            return now;
        }
        if left > 200_000 {
            thread::sleep(Duration::from_nanos((left - 150_000) as u64));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Whether a send error passes: the system's buffers are full for now.
fn passing(e: &io::Error) -> bool {
    // ENOBUFS: 105 on Linux, 55 on macOS and the BSDs.
    let no_buffers = if cfg!(target_os = "linux") { 105 } else { 55 };
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
        || (cfg!(unix) && e.raw_os_error() == Some(no_buffers))
}

/// How the transmitter kept time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TransmitCounts {
    /// Packets sent, on each leg.
    pub sent: u64,
    /// Packets that went out more than 100 µs after their time.
    pub late: u64,
    /// The most a packet went out after its time, in nanoseconds.
    pub latest_ns: i64,
    /// Packets the operating system did not take, for want of buffer space.
    pub refused: u64,
}

/// Sends each packet on every leg at its time, by the system clock.
pub struct Transmitter {
    /// Each leg's socket and destination.
    sockets: Vec<(UdpSocket, SocketAddrV4)>,
    /// The address each leg's packets go from.
    sources: Vec<Ipv4Addr>,
    tai_utc: i32,
    counts: TransmitCounts,
}

impl Transmitter {
    /// A socket for each leg, sending from `interfaces[i]` when it is given (the address
    /// of the network interface to send leg `i` from), and otherwise from the one the
    /// routing table picks; multicast packets go out with time to live `ttl`, and all
    /// with DSCP `dscp`.
    pub fn new(legs: &[Leg], interfaces: &[Option<Ipv4Addr>], ttl: u8, dscp: u8, tai_utc: i32) -> io::Result<Self> {
        let mut sockets = Vec::new();
        let mut sources = Vec::new();
        for (i, leg) in legs.iter().enumerate() {
            let interface = interfaces.get(i).copied().flatten();
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SocketAddrV4::new(interface.unwrap_or(Ipv4Addr::UNSPECIFIED), 0).into())?;
            if leg.destination.ip().is_multicast() {
                if let Some(interface) = interface {
                    socket.set_multicast_if_v4(&interface)?;
                }
                socket.set_multicast_ttl_v4(u32::from(ttl))?;
                socket.set_multicast_loop_v4(true)?;
            }
            // Best effort: some systems refuse either.
            let _ = socket.set_tos_v4(u32::from(dscp) << 2);
            let _ = socket.set_send_buffer_size(4 << 20);
            let source = match interface {
                Some(interface) => interface,
                None => route_source(leg.destination)?,
            };
            // Unconnected, so that a unicast receiver's ICMP refusals do not stop it.
            sockets.push((socket.into(), leg.destination));
            sources.push(source);
        }
        Ok(Self { sockets, sources, tai_utc, counts: TransmitCounts::default() })
    }

    /// The address each leg's packets go from.
    pub fn sources(&self) -> &[Ipv4Addr] {
        &self.sources
    }

    /// How it kept time so far.
    pub fn counts(&self) -> TransmitCounts {
        self.counts
    }
}

impl Output for Transmitter {
    fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()> {
        let sent = wait_until(at, self.tai_utc);
        let late = sent - at;
        if late > LATE {
            self.counts.late += 1;
        }
        self.counts.latest_ns = self.counts.latest_ns.max(late.min(i128::from(i64::MAX)) as i64);
        for (socket, destination) in &self.sockets {
            match socket.send_to(packet, destination) {
                Ok(_) => {}
                Err(e) if passing(&e) => self.counts.refused += 1,
                Err(e) => return Err(e),
            }
        }
        self.counts.sent += 1;
        Ok(())
    }

    fn now(&self) -> Option<i128> {
        Some(tai_now(self.tai_utc))
    }
}

/// The address the routing table sends to `destination` from, found by connecting a
/// socket there, which sends nothing.
fn route_source(destination: SocketAddrV4) -> io::Result<Ipv4Addr> {
    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    probe.connect(destination)?;
    match probe.local_addr()? {
        SocketAddr::V4(a) => Ok(*a.ip()),
        SocketAddr::V6(_) => Err(io::Error::other("the route is IPv6")),
    }
}

/// Opens a socket that receives a leg: one that joins its multicast group on
/// `interface` (or the interface the system picks), from the leg's source only when it
/// names one, or one bound to its unicast address. Gives the socket and the receive
/// buffer the system allowed it, in octets.
pub fn listen(leg: &Leg, interface: Option<Ipv4Addr>) -> io::Result<(UdpSocket, usize)> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let group = *leg.destination.ip();
    let port = leg.destination.port();
    // Room for a few milliseconds of video; Linux holds it to net.core.rmem_max.
    let _ = socket.set_recv_buffer_size(64 << 20);
    if group.is_multicast() {
        socket.set_reuse_address(true)?;
        #[cfg(all(
            unix,
            not(any(target_os = "linux", target_os = "android", target_os = "solaris", target_os = "illumos"))
        ))]
        socket.set_reuse_port(true)?;
        // Bound to the group, the socket sees only its packets; Windows needs any.
        let bind = if cfg!(windows) { Ipv4Addr::UNSPECIFIED } else { group };
        socket.bind(&SocketAddrV4::new(bind, port).into())?;
        let interface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
        match leg.source {
            Some(source) => socket.join_ssm_v4(&source, &group, &interface)?,
            None => socket.join_multicast_v4(&group, &interface)?,
        }
    } else {
        socket.bind(&leg.destination.into()).map_err(|e| {
            if e.kind() == io::ErrorKind::AddrNotAvailable {
                io::Error::new(e.kind(), format!("the stream goes to {group}, which is not this machine's address"))
            } else {
                e
            }
        })?;
    }
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    let buffer = socket.recv_buffer_size().unwrap_or(0);
    Ok((socket.into(), buffer))
}

/// A datagram as it arrived.
struct Arrival {
    leg: usize,
    source: Ipv4Addr,
    at: i128,
    data: Vec<u8>,
}

/// Receives on each leg's socket, `sockets[i]` for leg `i`, until `until` nanoseconds of
/// TAI by the system clock, and gives each datagram to the session as it arrives.
pub fn receive(
    session: &mut Session,
    sockets: Vec<UdpSocket>,
    until: i128,
    tai_utc: i32,
    sink: &mut impl Sink,
) -> io::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel::<Arrival>(1 << 16);
    let mut threads = Vec::new();
    for (leg, socket) in sockets.into_iter().enumerate() {
        let (tx, stop) = (tx.clone(), Arc::clone(&stop));
        threads.push(thread::spawn(move || -> io::Result<()> {
            let mut buffer = vec![0u8; 65_536];
            while !stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((n, SocketAddr::V4(from))) => {
                        let arrival =
                            Arrival { leg, source: *from.ip(), at: tai_now(tai_utc), data: buffer[..n].to_vec() };
                        if tx.send(arrival).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }));
    }
    drop(tx);
    loop {
        let left = until - tai_now(tai_utc);
        if left <= 0 {
            break;
        }
        match rx.recv_timeout(Duration::from_nanos(left.min(50_000_000) as u64)) {
            Ok(a) if a.at < until => session.push(a.leg, a.source, a.at, &a.data, sink),
            Ok(_) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    // What arrived before the end and is still queued.
    while let Ok(a) = rx.try_recv() {
        if a.at < until {
            session.push(a.leg, a.source, a.at, &a.data, sink);
        }
    }
    let mut result = Ok(());
    for thread in threads {
        let ended = thread.join().unwrap_or_else(|_| Err(io::Error::other("a receiving thread panicked")));
        if result.is_ok() {
            result = ended;
        }
    }
    session.finish(sink);
    result
}
