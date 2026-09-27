//! Decoding messages built from the IEEE 1588 layouts, and ones from a real capture, then
//! checking them against ST 2059-2.

use std::collections::BTreeSet;

use st2110_ptp::{
    Action, Body, DecodeError, Flags, LockingStatus, Message, MessageType, SyncMetadata, TlvContent, TlvError, check,
    decode, describe, tlv_type,
};
use st2110_sdp::ClockIdentity;

const GM: [u8; 8] = [0x08, 0x00, 0x11, 0xFF, 0xFE, 0x21, 0xE1, 0xB0];
const FOLLOWER: [u8; 8] = [0x00, 0x1B, 0x21, 0xFF, 0xFE, 0x8A, 0x2C, 0x10];

/// 2026-09-27 12:00:00 UTC in PTP seconds.
const NOON: u64 = 1_790_510_437;

/// A message to encode: the header fields the tests change, then the body and the TLVs.
#[derive(Clone)]
struct Build {
    first: u8,
    second: u8,
    domain: u8,
    flags: u16,
    correction: i64,
    control: u8,
    log: i8,
    body: Vec<u8>,
    tlvs: Vec<u8>,
    /// messageLength, when it should not be the true length.
    length: Option<u16>,
}

impl Build {
    fn new(message_type: u8, control: u8, log: i8, body: Vec<u8>) -> Self {
        Self {
            first: message_type,
            second: 0x02,
            domain: 127,
            flags: 0,
            correction: 0,
            control,
            log,
            body,
            tlvs: Vec::new(),
            length: None,
        }
    }

    fn tlv(mut self, kind: u16, value: &[u8]) -> Self {
        self.tlvs.extend(kind.to_be_bytes());
        self.tlvs.extend((value.len() as u16).to_be_bytes());
        self.tlvs.extend(value);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let length = self.length.unwrap_or((34 + self.body.len() + self.tlvs.len()) as u16);
        let mut out = vec![self.first, self.second];
        out.extend(length.to_be_bytes());
        out.extend([self.domain, 0]);
        out.extend(self.flags.to_be_bytes());
        out.extend(self.correction.to_be_bytes());
        out.extend([0; 4]);
        out.extend(port(GM, 1));
        out.extend(0x1234_u16.to_be_bytes());
        out.extend([self.control, self.log as u8]);
        out.extend(&self.body);
        out.extend(&self.tlvs);
        out
    }

    fn decode(&self) -> Message {
        decode(&self.bytes()).expect("decodes")
    }
}

fn timestamp(seconds: u64, nanoseconds: u32) -> Vec<u8> {
    let mut out = seconds.to_be_bytes()[2..].to_vec();
    out.extend(nanoseconds.to_be_bytes());
    out
}

fn port(clock: [u8; 8], number: u16) -> Vec<u8> {
    let mut out = clock.to_vec();
    out.extend(number.to_be_bytes());
    out
}

/// A change that breaks one rule.
type Change<T> = fn(&mut T);

fn rules(message: &Message) -> Vec<&'static str> {
    check(message).iter().map(|f| f.rule).collect()
}

/// An Announce from a grandmaster locked to GNSS.
fn announce() -> Build {
    let mut body = timestamp(NOON, 0);
    body.extend(37_i16.to_be_bytes());
    body.extend([0, 128, 6, 0x21]);
    body.extend(0x4E5D_u16.to_be_bytes());
    body.push(128);
    body.extend(GM);
    body.extend(0_u16.to_be_bytes());
    body.push(0x20);
    let flags = Flags::PTP_TIMESCALE | Flags::UTC_OFFSET_VALID | Flags::TIME_TRACEABLE | Flags::FREQUENCY_TRACEABLE;
    Build { flags, ..Build::new(0x0B, 5, 0, body) }
}

/// A two-step Sync, 8 a second.
fn sync() -> Build {
    Build { flags: Flags::TWO_STEP, ..Build::new(0x00, 0, -3, timestamp(NOON, 123_456_789)) }
}

/// A Delay_Resp to a follower.
fn delay_resp() -> Build {
    let mut body = timestamp(NOON, 125_000_000);
    body.extend(port(FOLLOWER, 1));
    Build::new(0x09, 3, -3, body)
}

#[test]
fn announce_from_a_grandmaster() {
    let message = announce().decode();
    let h = &message.header;
    assert_eq!((h.message_type, h.version, h.minor_version, h.message_length), (MessageType::Announce, 2, 0, 64));
    assert_eq!((h.domain, h.sequence_id, h.log_message_interval), (127, 0x1234, 0));
    assert_eq!(h.source.clock, ClockIdentity(GM));
    let a = message.announce().expect("an Announce");
    assert_eq!((a.origin.seconds, a.current_utc_offset, a.priority1, a.priority2), (NOON, 37, 128, 128));
    assert_eq!((a.quality.class, a.quality.accuracy, a.quality.variance), (6, 0x21, 0x4E5D));
    assert_eq!((a.grandmaster, a.steps_removed, a.time_source), (ClockIdentity(GM), 0, 0x20));
    assert!(message.tlvs.is_empty() && message.tlv_error.is_none());
    assert_eq!(check(&message), []);
    assert_eq!(
        describe::summary(&message),
        [
            "Announce from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 4660, one a second",
            "grandmaster 08-00-11-FF-FE-21-E1-B0: priority 128/128, class 6 (locked to a primary reference), \
             accuracy within 100 ns (21h), variance 4E5Dh, 0 steps removed, GNSS (20h)",
            "UTC offset 37 s (valid); PTP timescale, UTC offset valid, time traceable, frequency traceable",
        ]
    );

    // IEEE 1588-2019 devices send minorVersionPTP 1.
    let message = decode(&Build { second: 0x12, ..announce() }.bytes()).unwrap();
    assert_eq!((message.header.version, message.header.minor_version), (2, 1));
    assert!(describe::summary(&message)[0].ends_with(", PTP 2.1"));
}

#[test]
fn sync_follow_up_and_delay_resp() {
    let message = sync().decode();
    assert_eq!(message.body, Body::Sync { origin: st2110_ptp::Timestamp { seconds: NOON, nanoseconds: 123_456_789 } });
    assert!(message.header.flags.has(Flags::TWO_STEP) && message.header.message_type.is_event());
    assert_eq!(check(&message), []);
    assert_eq!(
        describe::summary(&message),
        [
            "Sync from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 4660, 8 a second",
            "origin 1790510437.123456789; two-step",
        ]
    );

    // correctionField counts 2⁻¹⁶ ns: 0x18000 is 1.5 ns.
    let follow_up = Build { correction: 0x1_8000, ..Build::new(0x08, 2, -3, timestamp(NOON, 123_457_021)) };
    let message = follow_up.decode();
    let Body::FollowUp { precise_origin } = message.body else { panic!("{:?}", message.body) };
    assert_eq!(precise_origin.time().unwrap().to_string(), "1790510437.123457021");
    assert_eq!(message.header.correction_nanos(), 1.5);
    assert!(!message.header.message_type.is_event());
    assert_eq!(describe::summary(&message)[1], "precise origin 1790510437.123457021, correction 1.500 ns");
    assert_eq!(check(&message), []);

    let message = delay_resp().decode();
    let Body::DelayResp { receive, requesting } = message.body else { panic!("{:?}", message.body) };
    assert_eq!((receive.seconds, receive.nanoseconds), (NOON, 125_000_000));
    assert_eq!(requesting.to_string(), "00-1B-21-FF-FE-8A-2C-10 port 1");
    assert_eq!(check(&message), []);
    // Unicast messages send 127, which means no interval.
    assert_eq!(rules(&Build { log: 127, ..delay_resp() }.decode()), [] as [&str; 0]);
}

/// A grandmaster on British Summer Time at noon UTC on 27 September 2026: time code in
/// 29.97 drop-frame, jammed at local midnight, and the clocks going back on 25 October.
fn bst() -> SyncMetadata {
    SyncMetadata {
        frame_rate_numerator: 30000,
        frame_rate_denominator: 1001,
        locking_status: LockingStatus::ExternallyLocked,
        time_address_flags: 0b01,
        current_local_offset: 3563,
        jump_seconds: -3600,
        // 2026-10-25 01:00:00 UTC.
        time_of_next_jump: 1_792_890_037,
        // 2026-09-27 23:00:00 UTC, midnight BST.
        time_of_next_jam: 1_790_550_037,
        time_of_previous_jam: 1_790_550_037 - 86_400,
        previous_jam_local_offset: 3563,
        daylight_saving: 0b101,
        leap_second_jump: 0,
    }
}

/// The synchronization metadata TLV's value: organizationId, organizationSubType, data.
fn sm_value(sm: &SyncMetadata) -> Vec<u8> {
    let mut out = vec![0x68, 0x97, 0xE8, 0, 0, 1];
    out.extend(sm.frame_rate_numerator.to_be_bytes());
    out.extend(sm.frame_rate_denominator.to_be_bytes());
    out.extend([sm.locking_status.value(), sm.time_address_flags]);
    out.extend(sm.current_local_offset.to_be_bytes());
    out.extend(sm.jump_seconds.to_be_bytes());
    for time in [sm.time_of_next_jump, sm.time_of_next_jam, sm.time_of_previous_jam] {
        out.extend(&time.to_be_bytes()[2..]);
    }
    out.extend(sm.previous_jam_local_offset.to_be_bytes());
    out.extend([sm.daylight_saving, sm.leap_second_jump]);
    out
}

/// A Management COMMAND to every port, as ST 2059-2 §6.12 sends the metadata.
fn management(action: u8, target: [u8; 8]) -> Build {
    let mut body = port(target, 0xFFFF);
    body.extend([0, 0, action, 0]);
    Build::new(0x0D, 4, 127, body)
}

fn metadata(sm: &SyncMetadata) -> Build {
    management(3, [0xFF; 8]).tlv(tlv_type::ORGANIZATION_EXTENSION, &sm_value(sm))
}

#[test]
fn synchronization_metadata() {
    let message = metadata(&bst()).decode();
    assert_eq!(message.header.message_length, 100);
    let Body::Management(m) = &message.body else { panic!("{:?}", message.body) };
    assert!(m.target.is_all());
    assert_eq!(m.action, Action::Command);
    assert_eq!(message.tlvs.len(), 1);
    assert_eq!((message.tlvs[0].kind, message.tlvs[0].value.len()), (tlv_type::ORGANIZATION_EXTENSION, 48));
    let sm = message.sync_metadata().expect("synchronization metadata");
    assert_eq!(*sm, bst());
    assert!(sm.drop_frame() && !sm.color_frame() && sm.daylight_saving_now());
    assert_eq!(check(&message), []);
    assert_eq!(
        describe::summary(&message),
        [
            "Management from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 4660",
            "COMMAND to FF-FF-FF-FF-FF-FF-FF-FF port 65535, boundary hops 0 of 0",
            "synchronization metadata: 30000/1001 fps drop-frame, externally locked, local offset 3563 s, \
             next jam 2026-09-28 00:00:00 Local Time, jump of -3600 s at 2026-10-25 02:00:00 Local Time",
        ]
    );
    let jam = sm.next_jam().unwrap();
    assert_eq!((jam.time.seconds(), jam.local_offset), (1_790_550_037, 3563));
    assert_eq!(sm.previous_jam().unwrap().time.seconds(), 1_790_463_637);
}

/// For each rule, messages that break it and nothing else: `(rule, message)`.
fn cases() -> Vec<(&'static str, Build)> {
    fn changed<T>(mut value: T, change: Change<T>) -> T {
        change(&mut value);
        value
    }
    let announce_with = |change: Change<Build>| changed(announce(), change);
    let metadata_with = |change: Change<SyncMetadata>| metadata(&changed(bst(), change));
    let all_ports = || management(3, [0xFF; 8]);
    let value = sm_value(&bst());
    vec![
        ("ptp-domain", announce_with(|b| b.domain = 128)),
        ("announce-interval", announce_with(|b| b.log = 2)),
        ("announce-interval", announce_with(|b| b.log = -4)),
        ("sync-interval", Build { log: 0, ..sync() }),
        ("sync-interval", Build { log: -8, ..sync() }),
        ("delay-req-interval", Build { log: 5, ..delay_resp() }),
        // Offsets into the Announce body: clockClass at 14, clockAccuracy at 15,
        // timeSource at 29.
        ("clock-accuracy", announce_with(|b| b.body[15] = 0xFE)),
        ("time-source", announce_with(|b| b.body[29] = 0x11)),
        ("gm-clock-class", announce_with(|b| b.body[14] = 248)),
        ("utc-offset", announce_with(|b| b.body[10..12].copy_from_slice(&36_i16.to_be_bytes()))),
        ("arb-timescale", announce_with(|b| b.flags &= !Flags::PTP_TIMESCALE)),
        ("sm-tlv-message", management(0, [0xFF; 8]).tlv(tlv_type::ORGANIZATION_EXTENSION, &value)),
        ("sm-tlv-message", management(3, FOLLOWER).tlv(tlv_type::ORGANIZATION_EXTENSION, &value)),
        ("sm-tlv-message", announce().tlv(tlv_type::ORGANIZATION_EXTENSION, &value)),
        ("sm-tlv-message", all_ports().tlv(tlv_type::ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE, &value)),
        ("sm-tlv-length", all_ports().tlv(tlv_type::ORGANIZATION_EXTENSION, &[&value[..], &[0, 0]].concat())),
        ("sm-tlv-length", all_ports().tlv(tlv_type::ORGANIZATION_EXTENSION, &value[..46])),
        ("sm-frame-rate", metadata_with(|sm| (sm.frame_rate_numerator, sm.frame_rate_denominator) = (60000, 2002))),
        ("sm-frame-rate", metadata_with(|sm| sm.frame_rate_denominator = 0)),
        ("sm-locking-status", metadata_with(|sm| sm.locking_status = LockingStatus::Reserved(7))),
        ("sm-reserved", metadata_with(|sm| sm.time_address_flags = 0b101)),
        ("sm-reserved", metadata_with(|sm| sm.leap_second_jump = 2)),
        ("sm-jam-time", metadata_with(|sm| sm.time_of_next_jam += 300)),
        ("sm-jam-time", metadata_with(|sm| sm.previous_jam_local_offset = 3564)),
        ("sm-jump", metadata_with(|sm| sm.time_of_next_jump = 0)),
        ("sm-local-offset", metadata_with(|sm| sm.current_local_offset -= 86_400)),
        ("tlv-length", announce().tlv(0x8008, &[0, 0, 0])),
        ("tlv-length", announce_with(|b| b.tlvs.extend([0, 0]))),
    ]
}

#[test]
fn each_case_breaks_its_rule_alone() {
    for (rule, build) in cases() {
        let hex: String = build.bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(rules(&build.decode()), [rule], "{hex}");
    }
}

#[test]
fn every_rule_has_a_case() {
    let covered: BTreeSet<&str> = cases().iter().map(|(rule, _)| *rule).collect();
    for rule in st2110_ptp::rules::ALL {
        assert!(covered.contains(rule.id), "no test case raises {}", rule.id);
    }
    for rule in &covered {
        assert!(st2110_ptp::rules::find(rule).is_some(), "{rule} is not in the catalogue");
    }
}

#[test]
fn docs_list_every_rule() {
    let docs = include_str!("../../../docs/rules.md");
    assert!(
        docs.contains(&st2110_sdp::rules::markdown_table(st2110_ptp::rules::ALL)),
        "docs/rules.md is stale: run `st2110 rules --format markdown > docs/rules.md`"
    );
}

#[test]
fn what_findings_say() {
    let said = |rule: &str, n: usize| {
        let (_, build) = cases().into_iter().filter(|(r, _)| *r == rule).nth(n).expect("a case");
        check(&build.decode()).remove(0).message
    };
    for (rule, n, message) in [
        (
            "gm-clock-class",
            0,
            "grandmaster 08-00-11-FF-FE-21-E1-B0 has clockClass 248: free-running: the default class",
        ),
        ("sync-interval", 0, "logMessageInterval is 0 (one a second), outside −7 to −1"),
        ("sm-tlv-message", 0, "synchronization metadata: actionField is GET, not COMMAND"),
        (
            "sm-tlv-message",
            1,
            "synchronization metadata: targetPortIdentity is 00-1B-21-FF-FE-8A-2C-10 port 65535, not all ones",
        ),
        ("sm-tlv-message", 2, "synchronization metadata: it is in an Announce message, not a Management message"),
        ("sm-tlv-message", 3, "synchronization metadata: its tlvType is 8000h, not ORGANIZATION_EXTENSION (0003h)"),
        ("sm-tlv-length", 1, "its lengthField is 46, not 48"),
        (
            "sm-jam-time",
            0,
            "timeOfNextJam 1790550337 is 2026-09-28 00:05:00 Local Time, not a whole number of 10 minutes",
        ),
        ("sm-jump", 0, "jumpSeconds is -3600 but timeOfNextJump is 0"),
        ("tlv-length", 0, "the PAD TLV's lengthField is 3, an odd number"),
        ("tlv-length", 1, "2 octets at octet 64 are too few for a TLV"),
    ] {
        assert_eq!(said(rule, n), message);
    }
}

#[test]
fn metadata_in_a_tlv_of_the_wrong_length() {
    // Too long: the metadata is still read. Too short: it is not, but the TLV is still
    // recognised by its organization and subtype.
    let value = sm_value(&bst());
    let all_ports = || management(3, [0xFF; 8]);
    let long = all_ports().tlv(tlv_type::ORGANIZATION_EXTENSION, &[&value[..], &[0, 0]].concat()).decode();
    assert_eq!(long.sync_metadata(), Some(&bst()));
    let short = all_ports().tlv(tlv_type::ORGANIZATION_EXTENSION, &value[..46]).decode();
    assert!(short.sync_metadata().is_none() && short.tlvs[0].is_sync_metadata());
}

#[test]
fn leap_second_before_a_jam() {
    // A grandmaster keeping UTC as Local Time, with a leap second at the end of 2026
    // (hypothetical: none is scheduled). After it, TAI − UTC is 38, so midnight is a
    // second later in PTP time than before, and the jam there only falls on a whole 10
    // minutes with the offset after the jump.
    let sm = SyncMetadata {
        current_local_offset: -37,
        jump_seconds: -1,
        // 2027-01-01 00:00:00 UTC by the old offset: 23:59:60 is shown as 23:59:59 again.
        time_of_next_jump: 1_798_761_637,
        time_of_next_jam: 1_798_761_638,
        time_of_previous_jam: 1_798_675_237,
        previous_jam_local_offset: -37,
        daylight_saving: 0,
        leap_second_jump: 1,
        ..bst()
    };
    assert_eq!(rules(&metadata(&sm).decode()), [] as [&str; 0]);
    assert_eq!(sm.next_jam().unwrap().local_offset, -38);
    let no_jump = SyncMetadata { jump_seconds: 0, time_of_next_jump: 0, leap_second_jump: 0, ..sm };
    assert_eq!(rules(&metadata(&no_jump).decode()), ["sm-jam-time"]);
    // A jump in the jam's own second may be read either way.
    let tie = SyncMetadata { time_of_next_jump: 1_798_761_638, ..sm };
    assert_eq!(rules(&metadata(&tie).decode()), [] as [&str; 0]);
    let tie = SyncMetadata { time_of_next_jam: 1_798_761_637, time_of_next_jump: 1_798_761_637, ..sm };
    assert_eq!(rules(&metadata(&tie).decode()), [] as [&str; 0]);
}

#[test]
fn tlv_problems() {
    let path_trace = [GM, FOLLOWER].concat();
    let message = announce().tlv(tlv_type::PATH_TRACE, &path_trace).decode();
    assert_eq!(
        message.tlvs[0].content,
        TlvContent::PathTrace { clocks: vec![ClockIdentity(GM), ClockIdentity(FOLLOWER)] }
    );
    assert_eq!(check(&message), []);
    assert_eq!(describe::summary(&message)[3], "path trace: 08-00-11-FF-FE-21-E1-B0, 00-1B-21-FF-FE-8A-2C-10");

    // A TLV claiming more octets than the message has: the ones before it are kept.
    let mut overrun = announce().tlv(tlv_type::PATH_TRACE, &GM);
    overrun.tlvs.extend([0x80, 0x08, 0x00, 0x10, 0, 0]);
    let message = overrun.decode();
    assert_eq!(message.tlvs.len(), 1);
    assert_eq!(message.tlv_error, Some(TlvError::Overrun { offset: 76, tlv_type: 0x8008, length: 16, available: 2 }));
    assert_eq!(rules(&message), ["tlv-length"]);

    let mut trailing = announce();
    trailing.tlvs.extend([0, 0]);
    assert_eq!(trailing.decode().tlv_error, Some(TlvError::Trailing { offset: 64, count: 2 }));

    let unknown = announce().tlv(tlv_type::ORGANIZATION_EXTENSION, &[0x00, 0x1B, 0x19, 0, 0, 2, 0xAB, 0xCD]).decode();
    assert_eq!(
        unknown.tlvs[0].content,
        TlvContent::OrganizationExtension { organization: "00-1B-19".into(), subtype: "00-00-02".into() }
    );
    assert_eq!(describe::summary(&unknown)[3], "ORGANIZATION_EXTENSION TLV from 00-1B-19, subtype 00-00-02");
}

#[test]
fn decode_errors() {
    let bytes = announce().bytes();
    assert_eq!(decode(&bytes[..10]), Err(DecodeError::Truncated { needed: 34, available: 10 }));
    assert_eq!(decode(&bytes[..60]), Err(DecodeError::Truncated { needed: 64, available: 60 }));
    let mut v1 = bytes.clone();
    v1[1] = 0x01;
    assert_eq!(decode(&v1), Err(DecodeError::Version(1)));
    let short = Build { length: Some(44), ..announce() }.bytes();
    assert_eq!(
        decode(&short),
        Err(DecodeError::Length { message_type: MessageType::Announce, message_length: 44, needed: 64 })
    );
    assert_eq!(
        decode(&short).unwrap_err().to_string(),
        "messageLength is 44, but an Announce message needs at least 64 octets"
    );
    // A reserved message type is kept, with its body unread.
    let reserved = decode(&Build::new(0x05, 5, 127, vec![1, 2, 3]).bytes()).unwrap();
    assert_eq!((reserved.header.message_type, reserved.body), (MessageType::Reserved(5), Body::Reserved));
    assert_eq!(reserved.header.message_type.to_string(), "reserved message type 5h");
}

/// Messages from `ptpv2.pcap`, a sample capture on the Wireshark wiki recorded in 2007
/// against a draft of IEEE 1588-2008. Its Sync and Pdelay_Req messages have the final
/// layout (its Announce messages do not, so none is used here).
#[test]
fn messages_from_a_capture() {
    let hex = |text: &str| -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    };
    // A Sync sent over Ethernet, padded to the 60-octet minimum frame: the two octets
    // after messageLength are not part of it.
    let sync =
        decode(&hex("0002002c00000000000000000000000000000000008063ffff0009ba0002043d0000000045b111492e3242630000"))
            .unwrap();
    assert_eq!(sync.header.message_length, 44);
    assert_eq!(sync.header.source.to_string(), "00-80-63-FF-FF-00-09-BA port 2");
    assert_eq!(sync.header.sequence_id, 0x043D);
    let Body::Sync { origin } = sync.body else { panic!("{:?}", sync.body) };
    assert_eq!(origin.to_string(), "1169232201.775045731");
    assert!(sync.tlvs.is_empty() && sync.tlv_error.is_none());
    // One Sync a second is slower than ST 2059-2 allows.
    assert_eq!(rules(&sync), ["sync-interval"]);

    // A Sync over UDP, from a port whose transportSpecific (majorSdoId) is 1.
    let sync = decode(&hex("1002002c00000000000000000000000000000000008063ffff0009ba000100730000000045b111590a657725"))
        .unwrap();
    assert_eq!((sync.header.major_sdo_id, sync.header.message_type), (1, MessageType::Sync));

    let pdelay = decode(&hex(
        "0202003600000000000000000000000000000000008063ffff0009ba0002045e050f000045b111491c4178f400000000000000000000",
    ))
    .unwrap();
    let Body::PdelayReq { origin } = pdelay.body else { panic!("{:?}", pdelay.body) };
    assert_eq!(origin.to_string(), "1169232201.474052852");
    assert_eq!((pdelay.header.control, pdelay.header.log_message_interval), (5, 15));
    assert_eq!(
        describe::summary(&pdelay)[0],
        "Pdelay_Req from 00-80-63-FF-FF-00-09-BA port 2, domain 0, sequence 1118, one every 32768 s"
    );
}
