//! The sockets: hearing SAP, announcing by SAP, asking by multicast DNS, and asking a
//! DNS server.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::dns::{Data, Message, Name, OPT, Question, Record};
use crate::sap;

/// How long a socket waits for a datagram before its thread looks up again.
pub(crate) const TICK: Duration = Duration::from_millis(100);

/// Where multicast DNS is asked and answered (RFC 6762 §3).
pub const MDNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

/// The room offered for a DNS response over UDP, with EDNS(0).
const UDP_ROOM: u16 = 4096;

/// A network port that is up, with its IPv4 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// What the system calls it, such as `en0`.
    pub name: String,
    /// Its IPv4 address: its lowest, where it has more than one.
    pub address: Ipv4Addr,
}

/// The machine's ports that are up and have an IPv4 address, loopback last: those a
/// multicast group can be joined on. Point-to-point links, such as VPN tunnels, carry
/// no multicast DNS, and are left out.
pub fn interfaces() -> Vec<Interface> {
    let mut found: Vec<Interface> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| (i.is_oper_up() || i.is_loopback()) && !i.is_p2p())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(Interface { name: i.name, address: v4.ip }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    found.sort_by(|a, b| {
        (a.address.is_loopback(), &a.name, a.address).cmp(&(b.address.is_loopback(), &b.name, b.address))
    });
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// A UDP socket that shares its port with others on the machine, as the system's own
/// multicast DNS responder and other listeners do.
fn shared(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(
        unix,
        not(any(target_os = "linux", target_os = "android", target_os = "solaris", target_os = "illumos"))
    ))]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    Ok(socket)
}

/// Joins `group` on each of `interfaces`, or on the one the system picks when there are
/// none. Fails only when it joins nowhere.
fn join(socket: &Socket, group: Ipv4Addr, interfaces: &[Ipv4Addr]) -> io::Result<()> {
    if interfaces.is_empty() {
        return socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED);
    }
    let mut last = None;
    let mut joined = false;
    for interface in interfaces {
        match socket.join_multicast_v4(&group, interface) {
            Ok(()) => joined = true,
            Err(e) => last = Some(e),
        }
    }
    match (joined, last) {
        (false, Some(e)) => Err(e),
        _ => Ok(()),
    }
}

/// Joins `groups` on the ports that are up now and were not when `joined` was listed,
/// and lists them again: for a socket that hears every port. Gives whether they changed.
pub(crate) fn rejoin(socket: &UdpSocket, groups: &[Ipv4Addr], joined: &mut Vec<Ipv4Addr>) -> bool {
    let up: Vec<Ipv4Addr> = interfaces().into_iter().map(|i| i.address).collect();
    if up == *joined {
        return false;
    }
    for interface in up.iter().filter(|i| !joined.contains(i)) {
        for group in groups {
            // A port that comes back with its address may still be joined.
            _ = socket.join_multicast_v4(group, interface);
        }
    }
    *joined = up;
    true
}

/// Sockets that hear SAP packets sent to `addresses`, each with the groups it joined:
/// one for the multicast groups on each port, joined on each of `interfaces`, and one
/// bound to each unicast address.
pub(crate) fn sap_sockets(
    addresses: &[SocketAddrV4],
    interfaces: &[Ipv4Addr],
) -> io::Result<Vec<(UdpSocket, Vec<Ipv4Addr>)>> {
    let mut sockets = Vec::new();
    let mut ports: Vec<u16> = addresses.iter().filter(|a| a.ip().is_multicast()).map(|a| a.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    for port in ports {
        let socket = shared(port)?;
        let mut groups = Vec::new();
        for group in addresses.iter().filter(|a| a.ip().is_multicast() && a.port() == port) {
            join(&socket, *group.ip(), interfaces)
                .map_err(|e| io::Error::new(e.kind(), format!("cannot join {}: {e}", group.ip())))?;
            groups.push(*group.ip());
        }
        socket.set_read_timeout(Some(TICK))?;
        sockets.push((socket.into(), groups));
    }
    for address in addresses.iter().filter(|a| !a.ip().is_multicast()) {
        let socket = UdpSocket::bind(address)?;
        socket.set_read_timeout(Some(TICK))?;
        sockets.push((socket, Vec::new()));
    }
    Ok(sockets)
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

/// Announces an SDP file by SAP, and deletes the announcement at the end.
pub struct Announcer {
    socket: UdpSocket,
    to: SocketAddrV4,
    announcement: Vec<u8>,
    deletion: Vec<u8>,
}

impl Announcer {
    /// An announcer of `sdp` to `to`, a multicast group or a unicast address and port,
    /// sending from `interface`, or from the interface the routing table picks, with
    /// multicast time to live `ttl`.
    pub fn new(sdp: &str, to: SocketAddrV4, interface: Option<Ipv4Addr>, ttl: u8) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind(&SocketAddrV4::new(interface.unwrap_or(Ipv4Addr::UNSPECIFIED), 0).into())?;
        if to.ip().is_multicast() {
            if let Some(interface) = interface {
                socket.set_multicast_if_v4(&interface)?;
            }
            socket.set_multicast_ttl_v4(u32::from(ttl))?;
            socket.set_multicast_loop_v4(true)?;
        }
        let origin = match interface {
            Some(interface) => interface,
            None => route_source(to)?,
        };
        Ok(Self {
            socket: socket.into(),
            to,
            announcement: sap::packet(origin, sdp, false),
            deletion: sap::packet(origin, sdp, true),
        })
    }

    /// Sends the announcement.
    pub fn announce(&self) -> io::Result<()> {
        self.socket.send_to(&self.announcement, self.to).map(drop)
    }

    /// Sends the deletion, for listeners to forget the session at once.
    pub fn delete(&self) -> io::Result<()> {
        self.socket.send_to(&self.deletion, self.to).map(drop)
    }
}

/// A multicast DNS querier.
pub(crate) struct Mdns {
    socket: UdpSocket,
    to: SocketAddrV4,
    interfaces: Vec<Ipv4Addr>,
    /// Whether it asks from a port of its own, so that responders answer it alone, by
    /// unicast, and it hears no announcements.
    pub(crate) one_shot: bool,
}

impl Mdns {
    /// A querier that asks `to` on each of `interfaces`. To the multicast DNS group, it
    /// shares the port with the system's responder and joins the group, to hear every
    /// answer and announcement; where it cannot, or to a unicast address, it asks from a
    /// port of its own, and responders answer it straight back (RFC 6762 §6.7).
    pub(crate) fn open(to: SocketAddrV4, interfaces: &[Ipv4Addr]) -> io::Result<Self> {
        let multicast = to.ip().is_multicast();
        let joined = multicast.then(|| shared(to.port()).and_then(|s| join(&s, *to.ip(), interfaces).map(|()| s)));
        let (socket, one_shot) = match joined {
            Some(Ok(socket)) => (socket, false),
            _ => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
                (socket, true)
            }
        };
        if multicast {
            // Responders ignore multicast DNS from beyond the link (RFC 6762 §11).
            socket.set_multicast_ttl_v4(255)?;
            socket.set_multicast_loop_v4(true)?;
        }
        socket.set_read_timeout(Some(TICK))?;
        Ok(Self { socket: socket.into(), to, interfaces: interfaces.to_vec(), one_shot })
    }

    /// Asks `questions` on every interface.
    pub(crate) fn ask(&self, questions: &[Question]) -> io::Result<()> {
        if questions.is_empty() {
            return Ok(());
        }
        let bytes = Message::query(0, questions.to_vec()).encode();
        if !self.to.ip().is_multicast() || self.interfaces.is_empty() {
            return self.socket.send_to(&bytes, self.to).map(drop);
        }
        let socket = socket2::SockRef::from(&self.socket);
        let mut result = Err(io::Error::other("no interface to ask on"));
        for interface in &self.interfaces {
            let sent = socket.set_multicast_if_v4(interface).and_then(|()| self.socket.send_to(&bytes, self.to));
            // Asked on one interface is asked.
            if sent.is_ok() || result.is_err() {
                result = sent.map(drop);
            }
        }
        result
    }

    /// Asks on the ports that are up now, joining the group on those that have come up:
    /// for a querier that asks on every port. Gives whether they changed.
    pub(crate) fn follow(&mut self) -> bool {
        let groups = if self.one_shot { Vec::new() } else { vec![*self.to.ip()] };
        rejoin(&self.socket, &groups, &mut self.interfaces)
    }

    /// The next response to arrive, if one does within a tick.
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> io::Result<Option<Message>> {
        match self.socket.recv_from(buffer) {
            Ok((n, _)) => Ok(Message::decode(&buffer[..n]).ok().filter(|m| m.response)),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A query identifier that differs from one query to the next.
fn query_id() -> u16 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    (nanos ^ (nanos >> 16) ^ std::process::id()) as u16
}

/// Asks a DNS server `question` over UDP, and over TCP when the answer comes cut short.
pub(crate) fn lookup(server: SocketAddr, question: &Question, timeout: Duration) -> io::Result<Message> {
    let id = query_id();
    let mut query = Message::query(id, vec![question.clone()]);
    query.recursion_desired = true;
    // EDNS(0), offering room for a response longer than 512 octets.
    let room = Record {
        name: Name::default(),
        kind: OPT,
        class: UDP_ROOM,
        cache_flush: false,
        ttl: 0,
        data: Data::Other(vec![]),
    };
    query.additionals.push(room);
    let bytes = query.encode();
    let local: SocketAddr = match server.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(server)?;
    socket.send(&bytes)?;
    let deadline = Instant::now() + timeout;
    let mut buffer = vec![0u8; usize::from(UDP_ROOM)];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("{server} did not answer")));
        }
        socket.set_read_timeout(Some(left))?;
        let n = match socket.recv(&mut buffer) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e),
        };
        let Ok(message) = Message::decode(&buffer[..n]) else {
            continue;
        };
        if !message.response || message.id != id {
            continue;
        }
        if message.truncated {
            return lookup_tcp(server, &bytes, timeout);
        }
        return Ok(message);
    }
}

/// Asks a DNS server over TCP, each message after its length (RFC 1035 §4.2.2).
fn lookup_tcp(server: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Message> {
    let mut stream = TcpStream::connect_timeout(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = u16::try_from(query.len()).map_err(|_| io::Error::other("the query is too long"))?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    stream.write_all(&framed)?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut response)?;
    Message::decode(&response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{server}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_the_ports_that_come_up() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let group = Ipv4Addr::new(239, 255, 255, 255);
        let up: Vec<Ipv4Addr> = interfaces().into_iter().map(|i| i.address).collect();
        // Joined on none, as when no port was up at the start.
        let mut joined = Vec::new();
        assert_eq!(rejoin(&socket, &[group], &mut joined), !up.is_empty());
        assert_eq!(joined, up);
        assert!(!rejoin(&socket, &[group], &mut joined), "none has come up since");
    }
}
