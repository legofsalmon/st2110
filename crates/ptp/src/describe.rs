//! Plain-language names for PTP's coded values, and a summary of a message.

use crate::message::{Body, Flags, Message, TlvContent};
use crate::time::PtpTime;

/// What a `clockAccuracy` value promises, such as `within 100 ns`.
pub fn clock_accuracy(value: u8) -> Option<&'static str> {
    Some(match value {
        0x17 => "within 1 ps",
        0x18 => "within 2.5 ps",
        0x19 => "within 10 ps",
        0x1A => "within 25 ps",
        0x1B => "within 100 ps",
        0x1C => "within 250 ps",
        0x1D => "within 1 ns",
        0x1E => "within 2.5 ns",
        0x1F => "within 10 ns",
        0x20 => "within 25 ns",
        0x21 => "within 100 ns",
        0x22 => "within 250 ns",
        0x23 => "within 1 µs",
        0x24 => "within 2.5 µs",
        0x25 => "within 10 µs",
        0x26 => "within 25 µs",
        0x27 => "within 100 µs",
        0x28 => "within 250 µs",
        0x29 => "within 1 ms",
        0x2A => "within 2.5 ms",
        0x2B => "within 10 ms",
        0x2C => "within 25 ms",
        0x2D => "within 100 ms",
        0x2E => "within 250 ms",
        0x2F => "within 1 s",
        0x30 => "within 10 s",
        0x31 => "more than 10 s",
        0x80..=0xFD => "set by an alternate profile",
        0xFE => "unknown",
        _ => return None,
    })
}

/// The name of a `timeSource` value, such as `GNSS`.
pub fn time_source(value: u8) -> Option<&'static str> {
    Some(match value {
        0x10 => "atomic clock",
        0x20 => "GNSS",
        0x30 => "terrestrial radio",
        0x39 => "serial time code",
        0x40 => "PTP",
        0x50 => "NTP",
        0x60 => "hand set",
        0x90 => "other",
        0xA0 => "internal oscillator",
        0xF0 => "video reference, arbitrary time",
        0xF1 => "video reference, PTP time",
        0xF2..=0xFE => "alternate profile",
        _ => return None,
    })
}

/// What a grandmaster's `clockClass` says about it.
pub fn clock_class(value: u8) -> &'static str {
    match value {
        6 => "locked to a primary reference",
        7 => "in holdover",
        13 => "locked to a reference, arbitrary timescale",
        14 => "in holdover, arbitrary timescale",
        52 | 187 => "out of holdover specification",
        58 | 193 => "out of holdover specification, arbitrary timescale",
        68..=122 | 133..=170 | 216..=232 => "an alternate profile's class",
        248 => "free-running: the default class",
        255 => "slave-only",
        _ => "a reserved class",
    }
}

/// How often a `logMessageInterval` sends: `8 a second`, `one a second`, `one every 2 s`.
pub fn interval(log: i8) -> String {
    match log {
        127 => "no interval".into(),
        0 => "one a second".into(),
        n if n < 0 && n > -63 => format!("{} a second", 1_u64 << -n),
        n if n > 0 && n < 63 => format!("one every {} s", 1_u64 << n),
        n => format!("interval 2^{n} s"),
    }
}

fn flags(flags: Flags) -> String {
    let names = flags.names();
    if names.is_empty() { "no flags".into() } else { names.join(", ") }
}

/// A few lines describing a message, for people: what it is and who sent it, then its
/// fields and TLVs.
pub fn summary(message: &Message) -> Vec<String> {
    let h = &message.header;
    let mut first = format!("{} from {}, domain {}, sequence {}", h.message_type, h.source, h.domain, h.sequence_id);
    if h.log_message_interval != 127 {
        first.push_str(&format!(", {}", interval(h.log_message_interval)));
    }
    if h.minor_version != 0 {
        first.push_str(&format!(", PTP 2.{}", h.minor_version));
    }
    let mut lines = vec![first];
    let correction =
        if h.correction != 0 { format!(", correction {:.3} ns", h.correction_nanos()) } else { String::new() };
    match &message.body {
        Body::Sync { origin } | Body::DelayReq { origin } | Body::PdelayReq { origin } => {
            lines.push(format!("origin {origin}{correction}; {}", flags(h.flags)));
        }
        Body::FollowUp { precise_origin } => lines.push(format!("precise origin {precise_origin}{correction}")),
        Body::DelayResp { receive, requesting } => {
            lines.push(format!("received {receive}{correction} from {requesting}"));
        }
        Body::PdelayResp { request_receipt, requesting } => {
            lines.push(format!("request received {request_receipt}{correction} from {requesting}"));
        }
        Body::PdelayRespFollowUp { response_origin, requesting } => {
            lines.push(format!("response sent {response_origin}{correction} to {requesting}"));
        }
        Body::Announce(a) => {
            let q = &a.quality;
            let accuracy = clock_accuracy(q.accuracy).unwrap_or("reserved accuracy");
            let source = time_source(a.time_source).unwrap_or("reserved source");
            let steps = if a.steps_removed == 1 { "1 step".to_string() } else { format!("{} steps", a.steps_removed) };
            lines.push(format!(
                "grandmaster {}: priority {}/{}, class {} ({}), accuracy {} ({:02X}h), variance {:04X}h, {steps} removed, {source} ({:02X}h)",
                a.grandmaster,
                a.priority1,
                a.priority2,
                q.class,
                clock_class(q.class),
                accuracy,
                q.accuracy,
                q.variance,
                a.time_source
            ));
            let valid = if h.flags.has(Flags::UTC_OFFSET_VALID) { "valid" } else { "not valid" };
            lines.push(format!("UTC offset {} s ({valid}); {}", a.current_utc_offset, flags(h.flags)));
        }
        Body::Signaling { target } => lines.push(format!("to {target}")),
        Body::Management(m) => lines.push(format!(
            "{} to {}, boundary hops {} of {}",
            m.action, m.target, m.boundary_hops, m.starting_boundary_hops
        )),
        Body::Reserved => {}
    }
    for tlv in &message.tlvs {
        let line = match &tlv.content {
            TlvContent::SyncMetadata(sm) => {
                let rate = match sm.frame_rate() {
                    Some(rate) => format!("{rate} fps"),
                    None => format!("frame rate {}/{}", sm.frame_rate_numerator, sm.frame_rate_denominator),
                };
                let mut line = format!(
                    "synchronization metadata: {rate}{}, {}, local offset {} s",
                    if sm.drop_frame() { " drop-frame" } else { "" },
                    sm.locking_status.describe(),
                    sm.current_local_offset,
                );
                if let Some(jam) = sm.next_jam() {
                    line.push_str(&format!(", next jam {:.0} Local Time", jam.time.local(jam.local_offset)));
                }
                if let Some(jump) = PtpTime::new(sm.time_of_next_jump, 0).filter(|_| sm.jump_seconds != 0) {
                    let at = jump.local(sm.current_local_offset);
                    line.push_str(&format!(", jump of {} s at {at:.0} Local Time", sm.jump_seconds));
                }
                line
            }
            TlvContent::PathTrace { clocks } => {
                format!("path trace: {}", clocks.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
            }
            TlvContent::Management { id } => format!("MANAGEMENT TLV, managementId {id:04X}h"),
            TlvContent::OrganizationExtension { organization, subtype } => {
                format!("{} TLV from {organization}, subtype {subtype}", tlv.type_name())
            }
            TlvContent::Other => format!("{} TLV ({:04X}h), {} octets", tlv.type_name(), tlv.kind, tlv.value.len()),
        };
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accuracies() {
        assert_eq!(clock_accuracy(0x21), Some("within 100 ns"));
        assert_eq!(clock_accuracy(0x80), Some("set by an alternate profile"));
        assert_eq!(clock_accuracy(0xFD), Some("set by an alternate profile"));
        for reserved in [0x00, 0x16, 0x32, 0x7F, 0xFF] {
            assert_eq!(clock_accuracy(reserved), None, "{reserved:02X}h");
        }
    }

    #[test]
    fn intervals() {
        assert_eq!(interval(-3), "8 a second");
        assert_eq!(interval(0), "one a second");
        assert_eq!(interval(1), "one every 2 s");
        assert_eq!(interval(127), "no interval");
        assert_eq!(interval(-128), "interval 2^-128 s");
    }
}
