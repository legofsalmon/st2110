//! Checks of one PTP message against ST 2059-2 and IEEE 1588.

use st2110_sdp::{Rule, Severity};

use crate::describe::{clock_class, interval};
use crate::message::{Action, Body, Flags, Message, TlvContent, tlv_type};
use crate::rules::*;
use crate::smpte::{LockingStatus, SyncMetadata};
use crate::time::TAI_UTC_2017;
use crate::timecode::Jam;

/// One problem found in a message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Finding {
    /// Identifier of the rule, from [`crate::rules`].
    pub rule: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub message: String,
    /// The document and clause behind the rule.
    pub reference: &'static str,
}

#[derive(Default)]
struct Findings(Vec<Finding>);

impl Findings {
    fn add(&mut self, rule: &'static Rule, message: impl Into<String>) {
        self.0.push(Finding {
            rule: rule.id,
            severity: rule.severity,
            message: message.into(),
            reference: rule.reference,
        });
    }
}

/// `logMessageInterval` where a message type does not use it, as in unicast.
const NO_INTERVAL: i8 = 127;

/// Local Time lies from UTC−12 h to UTC+14 h, and PTP time runs up to a minute ahead of
/// UTC, so `currentLocalOffset` lies in this range.
const LOCAL_OFFSETS: std::ops::RangeInclusive<i32> = -43_260..=50_400;

/// Checks one message against ST 2059-2:2021 and IEEE 1588, in field order.
pub fn check(message: &Message) -> Vec<Finding> {
    let mut f = Findings::default();
    let h = &message.header;
    if h.domain > 127 {
        f.add(&PTP_DOMAIN, format!("domainNumber {} is outside 0 to 127", h.domain));
    }
    let log = h.log_message_interval;
    let outside = |range: std::ops::RangeInclusive<i8>| log != NO_INTERVAL && !range.contains(&log);
    match &message.body {
        Body::Announce(announce) => {
            if outside(-3..=1) {
                f.add(&ANNOUNCE_INTERVAL, format!("logMessageInterval is {log} ({}), outside −3 to 1", interval(log)));
            }
            let quality = &announce.quality;
            if quality.accuracy == 0xFE {
                f.add(&CLOCK_ACCURACY, "the grandmaster's clockAccuracy is Unknown (FEh)");
            }
            if crate::describe::time_source(announce.time_source).is_none() {
                f.add(&TIME_SOURCE, format!("timeSource {:02X}h is a reserved value", announce.time_source));
            }
            if !matches!(quality.class, 6 | 13) {
                f.add(
                    &GM_CLOCK_CLASS,
                    format!(
                        "grandmaster {} has clockClass {}: {}",
                        announce.grandmaster,
                        quality.class,
                        clock_class(quality.class)
                    ),
                );
            }
            if h.flags.has(Flags::UTC_OFFSET_VALID) && announce.current_utc_offset < TAI_UTC_2017 as i16 {
                f.add(
                    &UTC_OFFSET,
                    format!(
                        "currentUtcOffset is {} s, but TAI − UTC has been {TAI_UTC_2017} s since 1 January 2017",
                        announce.current_utc_offset
                    ),
                );
            }
            if !h.flags.has(Flags::PTP_TIMESCALE) {
                f.add(
                    &ARB_TIMESCALE,
                    format!("grandmaster {} runs an arbitrary timescale (ptpTimescale is clear)", announce.grandmaster),
                );
            }
        }
        Body::Sync { .. } | Body::FollowUp { .. } if outside(-7..=-1) => {
            f.add(&SYNC_INTERVAL, format!("logMessageInterval is {log} ({}), outside −7 to −1", interval(log)));
        }
        Body::DelayResp { .. } if outside(-7..=4) => {
            f.add(&DELAY_REQ_INTERVAL, format!("logMinDelayReqInterval is {log} ({}), outside −7 to 4", interval(log)));
        }
        _ => {}
    }
    for tlv in &message.tlvs {
        if tlv.value.len() % 2 == 1 {
            f.add(
                &TLV_LENGTH,
                format!("the {} TLV's lengthField is {}, an odd number", tlv.type_name(), tlv.value.len()),
            );
        }
        if tlv.is_sync_metadata() {
            sync_metadata_carrier(message, tlv.kind, &mut f);
            if tlv.value.len() != 48 {
                f.add(&SM_TLV_LENGTH, format!("its lengthField is {}, not 48", tlv.value.len()));
            }
        }
        if let TlvContent::SyncMetadata(sm) = &tlv.content {
            sync_metadata(sm, &mut f);
        }
    }
    if let Some(error) = &message.tlv_error {
        f.add(&TLV_LENGTH, error.to_string());
    }
    f.0
}

/// The message around a synchronization metadata TLV.
fn sync_metadata_carrier(message: &Message, kind: u16, f: &mut Findings) {
    let mut problems = Vec::new();
    match &message.body {
        Body::Management(m) => {
            if !m.target.is_all() {
                problems.push(format!("targetPortIdentity is {}, not all ones", m.target));
            }
            if m.action != Action::Command {
                problems.push(format!("actionField is {}, not COMMAND", m.action));
            }
        }
        _ => problems
            .push(format!("it is in {} message, not a Management message", message.header.message_type.with_article())),
    }
    if kind != tlv_type::ORGANIZATION_EXTENSION {
        problems.push(format!("its tlvType is {kind:04X}h, not ORGANIZATION_EXTENSION (0003h)"));
    }
    if !problems.is_empty() {
        f.add(&SM_TLV_MESSAGE, format!("synchronization metadata: {}", problems.join("; ")));
    }
}

fn off_ten_minutes(name: &str, jam: Jam) -> String {
    format!(
        "{name} {} is {:.0} Local Time, not a whole number of 10 minutes",
        jam.time.seconds(),
        jam.time.local(jam.local_offset)
    )
}

fn sync_metadata(sm: &SyncMetadata, f: &mut Findings) {
    let (num, den) = (sm.frame_rate_numerator, sm.frame_rate_denominator);
    match sm.frame_rate() {
        None => f.add(&SM_FRAME_RATE, format!("defaultSystemFrameRate {num}/{den} is not a frame rate")),
        Some(rate) if u64::from(den) != rate.denominator() => f.add(
            &SM_FRAME_RATE,
            format!(
                "defaultSystemFrameRate {num}/{den} is not in lowest terms: {}/{}",
                rate.numerator(),
                rate.denominator()
            ),
        ),
        Some(_) => {}
    }
    if let LockingStatus::Reserved(value) = sm.locking_status {
        f.add(&SM_LOCKING_STATUS, format!("gmLockingStatus is {value}, a reserved value"));
    }
    let reserved: Vec<String> = [
        ("timeAddressFlags", sm.time_address_flags, 0xFC),
        ("daylightSaving", sm.daylight_saving, 0xF8),
        ("leapSecondJump", sm.leap_second_jump, 0xFE),
    ]
    .into_iter()
    .filter(|(_, value, mask)| value & mask != 0)
    .map(|(name, value, _)| format!("{name} is {value:08b}"))
    .collect();
    if !reserved.is_empty() {
        f.add(&SM_RESERVED, format!("reserved bits are set: {}", reserved.join(", ")));
    }
    // A jump in the jam's own second could be read as coming just before the jam or just
    // after it, so there either offset passes.
    let on_ten_minutes = |seconds: u64, offset: i32| (i128::from(seconds) + i128::from(offset)).rem_euclid(600) == 0;
    if let Some(jam) = sm.next_jam() {
        let seconds = jam.time.seconds();
        let tie = sm.time_of_next_jump == seconds && on_ten_minutes(seconds, sm.current_local_offset);
        if !on_ten_minutes(seconds, jam.local_offset) && !tie {
            f.add(&SM_JAM_TIME, off_ten_minutes("timeOfNextJam", jam));
        }
    }
    if let Some(jam) = sm.previous_jam().filter(|jam| !on_ten_minutes(jam.time.seconds(), jam.local_offset)) {
        f.add(&SM_JAM_TIME, off_ten_minutes("timeOfPreviousJam", jam));
    }
    if (sm.jump_seconds == 0) != (sm.time_of_next_jump == 0) {
        f.add(&SM_JUMP, format!("jumpSeconds is {} but timeOfNextJump is {}", sm.jump_seconds, sm.time_of_next_jump));
    }
    for (name, offset) in
        [("currentLocalOffset", sm.current_local_offset), ("previousJamLocalOffset", sm.previous_jam_local_offset)]
    {
        if !LOCAL_OFFSETS.contains(&offset) {
            f.add(&SM_LOCAL_OFFSET, format!("{name} is {offset} s, beyond any time zone"));
        }
    }
}
