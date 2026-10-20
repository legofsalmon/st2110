//! ST 2110-40 ancillary data: the `DID_SDID` parameter of RFC 8331, and the packet types
//! ST 2110-40 says not to carry.

/// Parses a `DID_SDID` value, such as `{0x61,0x01}`, into its DID and SDID.
pub fn did_sdid(value: &str) -> Option<(u8, u8)> {
    let inner = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    let (did, sdid) = inner.split_once(',')?;
    Some((hex_byte(did)?, hex_byte(sdid)?))
}

fn hex_byte(text: &str) -> Option<u8> {
    let text = text.trim();
    let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?;
    if hex.is_empty() || hex.len() > 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(hex, 16).ok()
}

/// What a DID names when ST 2110-40:2023 §5.2.1 says not to carry it: embedded audio
/// data and control packets (ST 299-1 and ST 299-2 in HD, ST 272 in SD), or EDH
/// (RP 165). `None` for any other DID.
pub fn audio_or_edh(did: u8) -> Option<&'static str> {
    match did {
        0xE0..=0xE7 | 0xA0..=0xA7 => Some("embedded audio"),
        0xEC..=0xEF | 0xF8..=0xFF => Some("SD embedded audio"),
        0xF4 => Some("EDH"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_did_sdid() {
        assert_eq!(did_sdid("{0x61,0x01}"), Some((0x61, 0x01)));
        assert_eq!(did_sdid(" {0X41, 0x5} "), Some((0x41, 0x05)));
        assert_eq!(did_sdid("{61,01}"), None);
        assert_eq!(did_sdid("{0x161,0x01}"), None);
    }

    #[test]
    fn names_audio_and_edh() {
        assert_eq!(audio_or_edh(0xE7), Some("embedded audio"));
        assert_eq!(audio_or_edh(0xA3), Some("embedded audio"));
        assert_eq!(audio_or_edh(0xFF), Some("SD embedded audio"));
        assert_eq!(audio_or_edh(0xF4), Some("EDH"));
        assert_eq!(audio_or_edh(0x61), None);
        assert_eq!(audio_or_edh(0xF5), None);
    }
}
