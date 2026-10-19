//! WebSocket (RFC 6455), as much as NMOS uses: a client for the IS-04 Query API's
//! subscriptions, which push each change to the registry as it happens, and the framing
//! a server needs to push its own changes to a page.
//!
//! A client connects to a `ws://` or `wss://` URL, such as a subscription's `ws_href`,
//! with any headers it needs (IS-10 sends its token in `Authorization`, as on any other
//! request), and reads text messages. Pings are answered as they arrive.
//!
//! ```no_run
//! use std::time::Duration;
//! use st2110_nmos::ws;
//!
//! let mut socket = ws::connect("ws://registry.example/x-nmos/query/v1.3/ws/?uid=…", &[], Duration::from_secs(5))?;
//! while let Some(message) = socket.read()? {
//!     println!("{message}");
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::base64;

/// The GUID RFC 6455 joins to a client's key to make the server's answer.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The most a message may hold: a registry's first message lists every resource it
/// watches.
pub const MESSAGE_LIMIT: usize = 64 << 20;

/// The most a response head may hold.
const HEAD_LIMIT: usize = 16 << 10;

/// What the server answers a client's `Sec-WebSocket-Key` with.
pub fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{}{GUID}", key.trim()).as_bytes()))
}

/// One frame, or one message once its fragments are joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping, which the other end answers with a pong of the same payload.
    Ping(Vec<u8>),
    /// A pong.
    Pong(Vec<u8>),
    /// A close, with its status code when it has one.
    Close(Option<u16>),
}

/// Reads one message: a control frame, or a text or binary message whose fragments are
/// joined. Fails on a message over `limit` bytes, or text that is not UTF-8.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> io::Result<Frame> {
    let mut message: Option<(u8, Vec<u8>)> = None;
    loop {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head)?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let length = match head[1] & 0x7f {
            126 => {
                let mut bytes = [0u8; 2];
                reader.read_exact(&mut bytes)?;
                u64::from(u16::from_be_bytes(bytes))
            }
            127 => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                u64::from_be_bytes(bytes)
            }
            n => u64::from(n),
        };
        let so_far = message.as_ref().map_or(0, |(_, m)| m.len());
        let length = usize::try_from(length)
            .ok()
            .filter(|n| so_far.saturating_add(*n) <= limit)
            .ok_or_else(|| invalid("a WebSocket message too long to take"))?;
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload)?;
        if masked {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        match opcode {
            0x8 => {
                let code = payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                return Ok(Frame::Close(code));
            }
            0x9 => return Ok(Frame::Ping(payload)),
            0xA => return Ok(Frame::Pong(payload)),
            0x1 | 0x2 if message.is_none() => message = Some((opcode, payload)),
            0x0 => match message.as_mut() {
                Some((_, so_far)) => so_far.extend_from_slice(&payload),
                None => return Err(invalid("a WebSocket continuation with nothing to continue")),
            },
            _ => return Err(invalid(format!("WebSocket opcode {opcode:#x} where it cannot be"))),
        }
        if fin && let Some((opcode, payload)) = message.take() {
            return Ok(if opcode == 0x1 {
                Frame::Text(String::from_utf8(payload).map_err(|_| invalid("WebSocket text that is not UTF-8"))?)
            } else {
                Frame::Binary(payload)
            });
        }
    }
}

/// Writes one frame, unfragmented. A client masks what it sends (`mask`); a server
/// does not.
pub fn write_frame(writer: &mut impl Write, frame: &Frame, mask: Option<[u8; 4]>) -> io::Result<()> {
    let (opcode, payload): (u8, std::borrow::Cow<'_, [u8]>) = match frame {
        Frame::Text(text) => (0x1, text.as_bytes().into()),
        Frame::Binary(bytes) => (0x2, bytes.as_slice().into()),
        Frame::Ping(bytes) => (0x9, bytes.as_slice().into()),
        Frame::Pong(bytes) => (0xA, bytes.as_slice().into()),
        Frame::Close(code) => (0x8, code.map(|c| c.to_be_bytes().to_vec()).unwrap_or_default().into()),
    };
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    let bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(bit | n as u8),
        n if n <= usize::from(u16::MAX) => {
            out.push(bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(mask) => {
            out.extend_from_slice(&mask);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        }
        None => out.extend_from_slice(&payload),
    }
    writer.write_all(&out)?;
    writer.flush()
}

/// What a client reads and writes: a TCP stream, or TLS over one.
trait Transport: Read + Write + Send {}
impl<T: Read + Write + Send> Transport for T {}

/// A client's connection.
pub struct Socket {
    stream: Box<dyn Transport>,
    /// The TCP stream under it, to set timeouts on.
    tcp: TcpStream,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket").field("peer", &self.tcp.peer_addr().ok()).finish_non_exhaustive()
    }
}

/// Connects to a `ws://` or `wss://` URL, sending `headers` with the handshake, and
/// waiting `timeout` at most for each step. `wss://` checks the server's certificate as
/// the system does.
pub fn connect(url: &str, headers: &[(&str, &str)], timeout: Duration) -> io::Result<Socket> {
    let target = Target::parse(url)?;
    let address = (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{} has no address", target.host)))?;
    let tcp = TcpStream::connect_timeout(&address, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    let stream: Box<dyn Transport> =
        if target.secure { tls(&target.host, tcp.try_clone()?)? } else { Box::new(tcp.try_clone()?) };
    let mut socket = Socket { stream, tcp };
    socket.handshake(&target, headers)?;
    Ok(socket)
}

fn tls(host: &str, tcp: TcpStream) -> io::Result<Box<dyn Transport>> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(BuilderVerifierExt::with_platform_verifier)
        .map_err(io::Error::other)?
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string())
        .map_err(|e| invalid(format!("{host}: {e}")))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
    Ok(Box::new(rustls::StreamOwned::new(connection, tcp)))
}

impl Socket {
    fn handshake(&mut self, target: &Target, headers: &[(&str, &str)]) -> io::Result<()> {
        let key = base64(&random_bytes::<16>());
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: st2110-nmos/{}\r\n",
            target.path,
            target.authority,
            env!("CARGO_PKG_VERSION")
        );
        for (name, value) in headers {
            if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
                return Err(invalid(format!("a header that cannot be sent: {name}")));
            }
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        self.stream.write_all(request.as_bytes())?;
        self.stream.flush()?;
        // Byte by byte, so that nothing after the head is read into a buffer and lost.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > HEAD_LIMIT {
                return Err(invalid("a WebSocket handshake answer too long to take"));
            }
            self.stream.read_exact(&mut byte)?;
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        let mut lines = head.split("\r\n");
        let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or_default().to_string();
        if status != "101" {
            return Err(io::Error::new(
                if status == "401" || status == "403" {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::ConnectionRefused
                },
                format!("HTTP {status}: no WebSocket at {}", target.path),
            ));
        }
        let accept = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("sec-websocket-accept"))
            .map(|(_, value)| value.trim().to_string());
        if accept.as_deref() != Some(accept_key(&key).as_str()) {
            return Err(invalid("the server's WebSocket answer does not match the key sent"));
        }
        Ok(())
    }

    /// How long [`Socket::read`] waits for something to arrive; `None` waits as long
    /// as it takes.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.tcp.set_read_timeout(timeout)
    }

    /// The next text message, answering pings on the way. `None` once the server closes
    /// the connection. A read that times out fails with `WouldBlock` or `TimedOut`, and
    /// the socket can be read again.
    pub fn read(&mut self) -> io::Result<Option<String>> {
        loop {
            match self.read_any()? {
                Frame::Text(text) => return Ok(Some(text)),
                Frame::Close(_) => return Ok(None),
                _ => {}
            }
        }
    }

    /// The next frame of any kind, answering a ping, or a close, as it arrives: for a
    /// client that pings the server itself, to hear the pongs.
    pub fn read_any(&mut self) -> io::Result<Frame> {
        let frame = read_frame(&mut self.stream, MESSAGE_LIMIT)?;
        match &frame {
            Frame::Ping(payload) => self.send(&Frame::Pong(payload.clone()))?,
            Frame::Close(code) => {
                let _ = self.send(&Frame::Close(*code));
            }
            _ => {}
        }
        Ok(frame)
    }

    /// Sends a frame, masked as a client's must be.
    pub fn send(&mut self, frame: &Frame) -> io::Result<()> {
        write_frame(&mut self.stream, frame, Some(random_bytes::<4>()))
    }

    /// Closes the connection, telling the server first.
    pub fn close(mut self) {
        let _ = self.send(&Frame::Close(Some(1000)));
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}

/// Where a `ws://` or `wss://` URL points.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    secure: bool,
    /// The host, as it goes in `Host`: with its port, and brackets round an IPv6 address.
    authority: String,
    /// The host to connect to, without brackets.
    host: String,
    port: u16,
    /// The path and query.
    path: String,
}

impl Target {
    fn parse(url: &str) -> io::Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| invalid(format!("{url} is not a URL")))?;
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "ws" | "http" => false,
            "wss" | "https" => true,
            _ => return Err(invalid(format!("{url} is not a ws:// or wss:// URL"))),
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
        let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, after) = rest.split_once(']').ok_or_else(|| invalid(format!("{url}: an unclosed [")))?;
            (host.to_string(), after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host.to_string(), Some(port)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            Some(port) => port.parse().map_err(|_| invalid(format!("{url}: {port} is not a port")))?,
            None if secure => 443,
            None => 80,
        };
        if host.is_empty() {
            return Err(invalid(format!("{url} names no host")));
        }
        Ok(Self { secure, authority: authority.to_string(), host, port, path })
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Bytes no one can guess ahead: for a handshake key and the masks RFC 6455 asks a
/// client for, which keep what it sends from being read as something else by a cache
/// on the way. Hashing with the standard library's random keys is enough for that.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(COUNT.fetch_add(1, Ordering::Relaxed));
        hasher
            .write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
        chunk.copy_from_slice(&hasher.finish().to_le_bytes()[..chunk.len()]);
    }
    out
}

/// SHA-1 (FIPS 180-4), which RFC 6455 uses to answer a client's key. It is not used to
/// keep anything secret.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());
    for block in message.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5A82_7999),
                20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hashes_as_sha1_does() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(&sha1(long)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    #[test]
    fn answers_the_key_rfc_6455_gives() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frames_round_trip_masked_and_not() {
        for frame in [
            Frame::Text("hello".into()),
            Frame::Text("x".repeat(300)),
            Frame::Binary(vec![7; 70_000]),
            Frame::Ping(b"p".to_vec()),
            Frame::Close(Some(1000)),
        ] {
            for mask in [None, Some([1, 2, 3, 4])] {
                let mut wire = Vec::new();
                write_frame(&mut wire, &frame, mask).unwrap();
                assert_eq!(read_frame(&mut wire.as_slice(), MESSAGE_LIMIT).unwrap(), frame);
            }
        }
    }

    #[test]
    fn joins_fragments_and_refuses_too_much() {
        // "Hel" then "lo", as RFC 6455 §5.7 sends it.
        let wire = [0x01, 0x03, b'H', b'e', b'l', 0x80, 0x02, b'l', b'o'];
        assert_eq!(read_frame(&mut wire.as_slice(), 100).unwrap(), Frame::Text("Hello".into()));
        assert!(read_frame(&mut wire.as_slice(), 4).is_err());
        let stray = [0x80, 0x01, b'x'];
        assert!(read_frame(&mut stray.as_slice(), 100).is_err());
    }

    #[test]
    fn reads_urls() {
        let t = Target::parse("wss://[::1]:8443/x-nmos/query/v1.3/ws/?uid=1").unwrap();
        assert_eq!((t.secure, t.host.as_str(), t.port, t.authority.as_str()), (true, "::1", 8443, "[::1]:8443"));
        assert_eq!(t.path, "/x-nmos/query/v1.3/ws/?uid=1");
        let t = Target::parse("ws://registry.example?uid=2").unwrap();
        assert_eq!((t.port, t.path.as_str()), (80, "/?uid=2"));
        assert!(Target::parse("ftp://x/").is_err());
        assert!(Target::parse("ws://:80/").is_err());
    }
}
