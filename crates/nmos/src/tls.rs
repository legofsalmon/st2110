//! The certificate authorities this program's clients trust for `https://` and
//! `wss://`: the system's, as its platform verifier has them, or only those given with
//! [`trust_only`], as curl's `--cacert` has it, for a facility with a CA of its own or a
//! test with a certificate of its own. It holds for every client of this crate's, and of
//! `st2110-connect`'s, made after it is called.

use std::io;
use std::sync::{Arc, RwLock};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use crate::auth::{Error, error};

/// The certificate authorities trusted in place of the system's, when they are given.
static ROOTS: RwLock<Option<Arc<Vec<CertificateDer<'static>>>>> = RwLock::new(None);

/// Trusts only the certificate authorities in `pem`, one or more PEM certificates, from
/// now on: gives how many there are.
pub fn trust_only(pem: &[u8]) -> Result<usize, Error> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| error(format!("not PEM certificates: {e}")))?;
    if certificates.is_empty() {
        return Err(error("no PEM certificates (-----BEGIN CERTIFICATE-----)"));
    }
    let count = certificates.len();
    *ROOTS.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(certificates));
    Ok(count)
}

fn roots() -> Option<Arc<Vec<CertificateDer<'static>>>> {
    ROOTS.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

/// The TLS configuration of an HTTP client's agent: the system's certificate
/// authorities, or those [`trust_only`] gave.
pub fn tls_config() -> TlsConfig {
    let root_certs = match roots() {
        Some(roots) => RootCerts::new_with_certs(
            &roots.iter().map(|c| Certificate::from_der(c.as_ref()).to_owned()).collect::<Vec<_>>(),
        ),
        None => RootCerts::PlatformVerifier,
    };
    TlsConfig::builder().root_certs(root_certs).build()
}

/// The TLS configuration of a `wss://` client, the same way.
pub(crate) fn client_config() -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let config = match roots() {
        Some(roots) => {
            let mut store = rustls::RootCertStore::empty();
            for root in roots.iter() {
                store.add(root.clone()).map_err(io::Error::other)?;
            }
            builder.with_root_certificates(store)
        }
        None => {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder.with_platform_verifier().map_err(io::Error::other)?
        }
    };
    Ok(config.with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_pem_certificates_only() {
        assert!(trust_only(b"not a certificate").is_err());
        assert!(trust_only(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err());
        assert!(roots().is_none(), "the system's are still trusted");
    }
}
