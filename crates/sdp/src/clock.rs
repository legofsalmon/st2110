//! Reference clock (`a=ts-refclk`, RFC 7273) and media clock (`a=mediaclk`) signalling.

use std::fmt;

use crate::rational::digits;

/// An EUI-64 clock identity, as used for PTP grandmaster IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClockIdentity(pub [u8; 8]);

impl ClockIdentity {
    /// Parses the SDP form, `08-00-11-FF-FE-21-E1-B0`, in either case.
    pub fn parse(text: &str) -> Option<Self> {
        hex_groups(text).map(Self)
    }
}

impl fmt::Display for ClockIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ClockIdentity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Parses `N` two-digit hex groups separated by `-`.
fn hex_groups<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0; N];
    let mut groups = text.split('-');
    for byte in &mut out {
        let group = groups.next()?;
        if group.len() != 2 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(group, 16).ok()?;
    }
    groups.next().is_none().then_some(out)
}

/// Where a stream's timestamps come from: the value of `a=ts-refclk`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "type", rename_all = "kebab-case"))]
pub enum RefClock {
    /// PTP: `ptp=IEEE1588-2008:<grandmaster>:<domain>`, or `ptp=IEEE1588-2008:traceable`.
    Ptp {
        /// The version string, such as `IEEE1588-2008`.
        version: String,
        /// The grandmaster identity; `None` for `traceable`.
        grandmaster: Option<ClockIdentity>,
        /// The PTP domain number, when given.
        domain: Option<u8>,
        /// True for `traceable`: any grandmaster with traceable time will do.
        traceable: bool,
    },
    /// No PTP: the sender's free-running clock, named by a MAC address (`localmac=`).
    LocalMac {
        /// The MAC address as written.
        address: String,
    },
    /// Any other clock source, kept verbatim.
    Other {
        /// The attribute value.
        value: String,
    },
}

impl RefClock {
    /// Parses the value of an `a=ts-refclk` attribute.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let (source, rest) = value.split_once('=').unwrap_or((value, ""));
        if source.eq_ignore_ascii_case("ptp") {
            return parse_ptp(rest);
        }
        if source.eq_ignore_ascii_case("localmac") {
            if hex_groups::<6>(rest).is_none() {
                return Err(format!("localmac={rest} is not a MAC address written like CA-FE-01-CA-FE-02"));
            }
            return Ok(Self::LocalMac { address: rest.to_string() });
        }
        if value.is_empty() {
            return Err("the ts-refclk value is empty".into());
        }
        Ok(Self::Other { value: value.to_string() })
    }

    /// The grandmaster and domain, for comparing two references.
    pub fn grandmaster(&self) -> Option<(ClockIdentity, Option<u8>)> {
        match self {
            Self::Ptp { grandmaster: Some(id), domain, .. } => Some((*id, *domain)),
            _ => None,
        }
    }
}

fn parse_ptp(rest: &str) -> Result<RefClock, String> {
    let mut parts = rest.split(':');
    let version = parts.next().unwrap_or_default();
    if version.is_empty() {
        return Err("ptp= needs a version, such as ptp=IEEE1588-2008:<grandmaster>:<domain>".into());
    }
    let Some(id) = parts.next() else {
        return Err(format!("ptp={version} needs a grandmaster identity, or traceable"));
    };
    if id.eq_ignore_ascii_case("traceable") {
        if parts.next().is_some() {
            return Err("nothing may follow traceable".into());
        }
        return Ok(RefClock::Ptp { version: version.to_string(), grandmaster: None, domain: None, traceable: true });
    }
    let grandmaster = ClockIdentity::parse(id)
        .ok_or_else(|| format!("{id} is not a clock identity written like 08-00-11-FF-FE-21-E1-B0"))?;
    let domain = match parts.next() {
        None => None,
        // RFC 7273's grammar also allows `domain-nmbr=127`; ST 2110-10 writes the bare number.
        Some(text) => Some(
            digits(text.strip_prefix("domain-nmbr=").unwrap_or(text))
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| format!("PTP domain {text} is not a number from 0 to 255"))?,
        ),
    };
    if parts.next().is_some() {
        return Err("unexpected text after the PTP domain".into());
    }
    Ok(RefClock::Ptp { version: version.to_string(), grandmaster: Some(grandmaster), domain, traceable: false })
}

/// How the media clock relates to the reference clock: the value of `a=mediaclk`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "type", rename_all = "kebab-case"))]
pub enum MediaClock {
    /// `direct[=offset]`: RTP time is reference time times the clock rate, plus the offset.
    Direct {
        /// The offset; ST 2110 requires 0. `None` when not written.
        offset: Option<u64>,
    },
    /// `sender`: the sender's own media clock, not locked to the reference.
    Sender,
    /// Any other value, kept verbatim.
    Other {
        /// The attribute value.
        value: String,
    },
}

impl MediaClock {
    /// Parses the value of an `a=mediaclk` attribute. Parameters after the source
    /// (such as `rate=`) are ignored.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let first = value.split_whitespace().next().unwrap_or_default();
        let (source, argument) = match first.split_once('=') {
            Some((source, argument)) => (source, Some(argument)),
            None => (first, None),
        };
        if source.eq_ignore_ascii_case("direct") {
            let offset = match argument {
                None => None,
                Some(text) => {
                    Some(digits(text).ok_or_else(|| format!("direct={text}: the offset must be a whole number"))?)
                }
            };
            return Ok(Self::Direct { offset });
        }
        if source.eq_ignore_ascii_case("sender") && argument.is_none() {
            return Ok(Self::Sender);
        }
        if value.is_empty() {
            return Err("the mediaclk value is empty".into());
        }
        Ok(Self::Other { value: value.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GM: ClockIdentity = ClockIdentity([0x08, 0x00, 0x11, 0xFF, 0xFE, 0x21, 0xE1, 0xB0]);

    #[test]
    fn ptp_with_grandmaster_and_domain() {
        let clock = RefClock::parse("ptp=IEEE1588-2008:08-00-11-ff-fe-21-e1-b0:127").unwrap();
        assert_eq!(clock.grandmaster(), Some((GM, Some(127))));
        assert_eq!(GM.to_string(), "08-00-11-FF-FE-21-E1-B0");
    }

    #[test]
    fn ptp_domain_forms() {
        let clock = RefClock::parse("ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:domain-nmbr=37").unwrap();
        assert_eq!(clock.grandmaster(), Some((GM, Some(37))));
        let clock = RefClock::parse("ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0").unwrap();
        assert_eq!(clock.grandmaster(), Some((GM, None)));
    }

    #[test]
    fn ptp_traceable() {
        let clock = RefClock::parse("ptp=IEEE1588-2008:traceable").unwrap();
        assert!(matches!(clock, RefClock::Ptp { traceable: true, grandmaster: None, .. }));
    }

    #[test]
    fn localmac_and_others() {
        assert!(matches!(RefClock::parse("localmac=CA-FE-01-CA-FE-02"), Ok(RefClock::LocalMac { .. })));
        assert!(RefClock::parse("localmac=CA:FE:01:CA:FE:02").is_err());
        assert!(matches!(RefClock::parse("ntp=traceable"), Ok(RefClock::Other { .. })));
    }

    #[test]
    fn malformed_ptp() {
        for value in [
            "ptp=",
            "ptp=IEEE1588-2008",
            "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1",
            "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:256",
            "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:+1",
            "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127:9",
            "ptp=IEEE1588-2008:traceable:127",
        ] {
            assert!(RefClock::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn media_clock() {
        assert_eq!(MediaClock::parse("direct=0"), Ok(MediaClock::Direct { offset: Some(0) }));
        assert_eq!(MediaClock::parse("direct=0 rate=48000/1"), Ok(MediaClock::Direct { offset: Some(0) }));
        assert_eq!(MediaClock::parse("direct"), Ok(MediaClock::Direct { offset: None }));
        assert_eq!(MediaClock::parse("sender"), Ok(MediaClock::Sender));
        assert!(MediaClock::parse("direct=-5").is_err());
        assert!(matches!(MediaClock::parse("IEEE1722=38-D6-6D-8E-D2-78-13-2F"), Ok(MediaClock::Other { .. })));
    }
}
