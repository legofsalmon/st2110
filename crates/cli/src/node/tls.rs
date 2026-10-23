//! TLS on the Node's own APIs, with `--tls-cert` and `--tls-key`, as BCP-003-01 has an
//! NMOS API serve HTTPS, and WSS for the IS-12 WebSocket.
//!
//! A connection to the Node is a [`Conn`]: plain TCP, or TLS over it. A TLS one is held
//! by both what reads from it and what writes to it, as an IS-12 session sends its
//! notifications while the controller's next message is awaited: reading from the
//! socket takes no lock, so that a notification goes out meanwhile, and only handing
//! what was read to TLS, or what is to be sent, does.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

use crate::http::Stream;

/// The TLS the Node serves, from a certificate chain and its key, each a PEM file.
pub(crate) fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("--tls-cert {}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("--tls-cert {}: no PEM certificate in it", cert.display()));
    }
    let private = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("--tls-key {}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|e| format!("--tls-cert {} and --tls-key {}: {e}", cert.display(), key.display()))?;
    Ok(Arc::new(config))
}

/// A TLS session, and what has come from the socket that it has not taken yet.
struct Session {
    tls: ServerConnection,
    received: Vec<u8>,
}

/// A connection to the Node.
pub(crate) struct Conn {
    tcp: TcpStream,
    tls: Option<Arc<Mutex<Session>>>,
}

impl Conn {
    /// A connection as it comes, over TLS when `config` is given: the handshake is made
    /// as the request is read.
    pub(crate) fn new(tcp: TcpStream, config: Option<&Arc<ServerConfig>>) -> io::Result<Self> {
        let tls = match config {
            Some(config) => {
                let tls = ServerConnection::new(config.clone()).map_err(io::Error::other)?;
                Some(Arc::new(Mutex::new(Session { tls, received: Vec::new() })))
            }
            None => None,
        };
        Ok(Self { tcp, tls })
    }

    /// Another handle on the same connection, and the same TLS session.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self { tcp: self.tcp.try_clone()?, tls: self.tls.clone() })
    }

    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.tcp.set_write_timeout(timeout)
    }

    /// Closes the connection, telling a TLS client first (`close_notify`).
    pub(crate) fn shutdown(&self) {
        if let Some(session) = &self.tls {
            let mut session = lock(session);
            session.tls.send_close_notify();
            let _ = send(&mut session.tls, &self.tcp);
        }
        let _ = self.tcp.shutdown(Shutdown::Both);
    }
}

fn lock(session: &Mutex<Session>) -> MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Sends what TLS has to send.
fn send(tls: &mut ServerConnection, mut tcp: &TcpStream) -> io::Result<()> {
    while tls.wants_write() {
        tls.write_tls(&mut tcp)?;
    }
    tcp.flush()
}

impl Read for &Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(session) = &self.tls else {
            return (&self.tcp).read(buf);
        };
        let mut raw = [0u8; 16 << 10];
        loop {
            {
                let mut session = lock(session);
                let Session { tls, received } = &mut *session;
                // What came from the socket, as far as TLS takes it now.
                while !received.is_empty() && tls.wants_read() {
                    let taken = tls.read_tls(&mut received.as_slice())?;
                    received.drain(..taken);
                    if let Err(e) = tls.process_new_packets() {
                        // The alert that says why, as far as it goes.
                        let _ = send(tls, &self.tcp);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                }
                // The handshake's answers, as it goes.
                send(tls, &self.tcp)?;
                match tls.reader().read(buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    done => return done,
                }
            }
            // Waits for more without holding the session, as long as the socket's
            // read timeout allows.
            let read = (&self.tcp).read(&mut raw)?;
            let mut session = lock(session);
            if read == 0 {
                // Closed: TLS then says whether it was told so first.
                session.tls.read_tls(&mut io::empty())?;
                session.tls.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                return match session.tls.reader().read(buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                    done => done,
                };
            }
            session.received.extend_from_slice(&raw[..read]);
        }
    }
}

impl Write for &Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(session) = &self.tls else {
            return (&self.tcp).write(buf);
        };
        let mut session = lock(session);
        session.tls.writer().write_all(buf)?;
        send(&mut session.tls, &self.tcp)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.tls {
            Some(session) => send(&mut lock(session).tls, &self.tcp),
            None => (&self.tcp).flush(),
        }
    }
}

impl Stream for Conn {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.tcp.set_read_timeout(timeout)
    }

    fn reader(&self) -> impl Read + '_ {
        self
    }

    fn writer(&self) -> impl Write + '_ {
        self
    }
}
