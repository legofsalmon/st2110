//! PTP messages: IEEE 1588-2008 and -2019, both of which send version 2.

use std::fmt;

use st2110_sdp::ClockIdentity;

use crate::smpte::{SMPTE_OUI, SYNC_METADATA_SUBTYPE, SyncMetadata};
use crate::time::PtpTime;

/// Octets in the header every message starts with.
pub const HEADER_LENGTH: usize = 34;

/// A decoded PTP message.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Message {
    /// The common header.
    pub header: Header,
    /// The fields particular to the message type.
    pub body: Body,
    /// The TLVs after the body, in order.
    pub tlvs: Vec<Tlv>,
    /// What stopped the TLVs being read to the end of the message; those before it are kept.
    pub tlv_error: Option<TlvError>,
}

/// The kind of message: messageType.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Sync, 0.
    Sync,
    /// Delay_Req, 1.
    DelayReq,
    /// Pdelay_Req, 2.
    PdelayReq,
    /// Pdelay_Resp, 3.
    PdelayResp,
    /// Follow_Up, 8.
    FollowUp,
    /// Delay_Resp, 9.
    DelayResp,
    /// Pdelay_Resp_Follow_Up, A.
    PdelayRespFollowUp,
    /// Announce, B.
    Announce,
    /// Signaling, C.
    Signaling,
    /// Management, D.
    Management,
    /// A reserved value.
    Reserved(u8),
}

impl MessageType {
    fn from_nibble(nibble: u8) -> Self {
        match nibble {
            0x0 => Self::Sync,
            0x1 => Self::DelayReq,
            0x2 => Self::PdelayReq,
            0x3 => Self::PdelayResp,
            0x8 => Self::FollowUp,
            0x9 => Self::DelayResp,
            0xA => Self::PdelayRespFollowUp,
            0xB => Self::Announce,
            0xC => Self::Signaling,
            0xD => Self::Management,
            other => Self::Reserved(other),
        }
    }

    /// The name IEEE 1588 gives it, such as `Delay_Req`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sync => "Sync",
            Self::DelayReq => "Delay_Req",
            Self::PdelayReq => "Pdelay_Req",
            Self::PdelayResp => "Pdelay_Resp",
            Self::FollowUp => "Follow_Up",
            Self::DelayResp => "Delay_Resp",
            Self::PdelayRespFollowUp => "Pdelay_Resp_Follow_Up",
            Self::Announce => "Announce",
            Self::Signaling => "Signaling",
            Self::Management => "Management",
            Self::Reserved(_) => "reserved",
        }
    }

    /// Its name after "a" or "an", as in `an Announce`.
    pub(crate) fn with_article(self) -> String {
        match self {
            Self::Announce => "an Announce".into(),
            other => format!("a {other}"),
        }
    }

    /// Whether it is an event message, timestamped on sending and receipt (UDP port 319).
    pub fn is_event(self) -> bool {
        matches!(self, Self::Sync | Self::DelayReq | Self::PdelayReq | Self::PdelayResp)
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved(value) => write!(f, "reserved message type {value:X}h"),
            other => f.write_str(other.name()),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MessageType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// The common message header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Header {
    /// messageType.
    pub message_type: MessageType,
    /// majorSdoId, which IEEE 1588-2008 calls transportSpecific.
    pub major_sdo_id: u8,
    /// versionPTP: 2.
    pub version: u8,
    /// minorVersionPTP: 0 from IEEE 1588-2008 devices, 1 from -2019 ones.
    pub minor_version: u8,
    /// messageLength: octets in the whole message, TLVs included.
    pub message_length: u16,
    /// domainNumber.
    pub domain: u8,
    /// minorSdoId (IEEE 1588-2019; reserved in -2008).
    pub minor_sdo_id: u8,
    /// flagField.
    pub flags: Flags,
    /// correctionField, in nanoseconds × 2¹⁶. Serialized as `correction_ns`, in
    /// nanoseconds, which JavaScript can hold whatever its size.
    #[cfg_attr(feature = "serde", serde(rename = "correction_ns", serialize_with = "scaled_nanos"))]
    pub correction: i64,
    /// messageTypeSpecific (IEEE 1588-2019; reserved in -2008).
    pub message_type_specific: u32,
    /// sourcePortIdentity: the port that sent it.
    pub source: PortIdentity,
    /// sequenceId.
    pub sequence_id: u16,
    /// controlField, which IEEE 1588-2019 deprecates.
    pub control: u8,
    /// logMessageInterval: log₂ of the seconds between messages, or 127 where the
    /// message type does not use it.
    pub log_message_interval: i8,
}

impl Header {
    /// The correction in nanoseconds.
    pub fn correction_nanos(&self) -> f64 {
        self.correction as f64 / 65_536.0
    }
}

/// flagField: the two octets as one big-endian number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    /// alternateMasterFlag.
    pub const ALTERNATE_MASTER: u16 = 0x0100;
    /// twoStepFlag: a Follow_Up (or Pdelay_Resp_Follow_Up) carries the precise time.
    pub const TWO_STEP: u16 = 0x0200;
    /// unicastFlag.
    pub const UNICAST: u16 = 0x0400;
    /// PTP profile Specific 1.
    pub const PROFILE_SPECIFIC_1: u16 = 0x2000;
    /// PTP profile Specific 2.
    pub const PROFILE_SPECIFIC_2: u16 = 0x4000;
    /// leap61: the last minute of the UTC day has 61 seconds.
    pub const LEAP_61: u16 = 0x0001;
    /// leap59: the last minute of the UTC day has 59 seconds.
    pub const LEAP_59: u16 = 0x0002;
    /// currentUtcOffsetValid.
    pub const UTC_OFFSET_VALID: u16 = 0x0004;
    /// ptpTimescale: the grandmaster counts PTP (TAI) time rather than an arbitrary scale.
    pub const PTP_TIMESCALE: u16 = 0x0008;
    /// timeTraceable: the time is traceable to a primary reference.
    pub const TIME_TRACEABLE: u16 = 0x0010;
    /// frequencyTraceable: the frequency is traceable to a primary reference.
    pub const FREQUENCY_TRACEABLE: u16 = 0x0020;
    /// synchronizationUncertain (IEEE 1588-2019).
    pub const SYNCHRONIZATION_UNCERTAIN: u16 = 0x0040;

    const NAMES: [(u16, &'static str); 12] = [
        (Self::TWO_STEP, "two-step"),
        (Self::UNICAST, "unicast"),
        (Self::ALTERNATE_MASTER, "alternate master"),
        (Self::PROFILE_SPECIFIC_1, "profile specific 1"),
        (Self::PROFILE_SPECIFIC_2, "profile specific 2"),
        (Self::PTP_TIMESCALE, "PTP timescale"),
        (Self::UTC_OFFSET_VALID, "UTC offset valid"),
        (Self::TIME_TRACEABLE, "time traceable"),
        (Self::FREQUENCY_TRACEABLE, "frequency traceable"),
        (Self::LEAP_61, "leap 61"),
        (Self::LEAP_59, "leap 59"),
        (Self::SYNCHRONIZATION_UNCERTAIN, "synchronization uncertain"),
    ];

    /// Whether `flag`, one of the constants above, is set.
    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// The names of the flags that are set.
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMES.iter().filter(|(bit, _)| self.has(*bit)).map(|(_, name)| *name).collect()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Flags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.names())
    }
}

/// A PTP port: its clock and its port number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PortIdentity {
    /// clockIdentity.
    pub clock: ClockIdentity,
    /// portNumber.
    pub port: u16,
}

impl PortIdentity {
    /// Whether it is all ones, which addresses every port.
    pub fn is_all(&self) -> bool {
        self.clock.0 == [0xFF; 8] && self.port == 0xFFFF
    }
}

/// Written `08-00-11-FF-FE-21-E1-B0 port 1`.
impl fmt::Display for PortIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} port {}", self.clock, self.port)
    }
}

/// A timestamp as PTP sends it: 48-bit seconds and nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Timestamp {
    /// secondsField.
    pub seconds: u64,
    /// nanosecondsField, which must be below 10⁹.
    pub nanoseconds: u32,
}

impl Timestamp {
    /// The time it gives, if its nanoseconds are below a second.
    pub fn time(self) -> Option<PtpTime> {
        PtpTime::new(self.seconds, self.nanoseconds)
    }
}

/// Written `1790510437.123456789`, or `1790510438 s and 4294967295 ns, not a valid
/// time` when the nanoseconds are a second or more.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.time().is_some() {
            write!(f, "{}.{:09}", self.seconds, self.nanoseconds)
        } else {
            write!(f, "{} s and {} ns, not a valid time", self.seconds, self.nanoseconds)
        }
    }
}

/// A clock's quality, as the BMCA compares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ClockQuality {
    /// clockClass.
    pub class: u8,
    /// clockAccuracy.
    pub accuracy: u8,
    /// offsetScaledLogVariance.
    pub variance: u16,
}

/// The fields particular to each message type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "type", rename_all = "snake_case"))]
pub enum Body {
    /// Sync.
    Sync {
        /// originTimestamp: the sending time, or an estimate in a two-step Sync.
        origin: Timestamp,
    },
    /// Delay_Req.
    DelayReq {
        /// originTimestamp.
        origin: Timestamp,
    },
    /// Pdelay_Req.
    PdelayReq {
        /// originTimestamp.
        origin: Timestamp,
    },
    /// Pdelay_Resp.
    PdelayResp {
        /// requestReceiptTimestamp.
        request_receipt: Timestamp,
        /// requestingPortIdentity.
        requesting: PortIdentity,
    },
    /// Follow_Up.
    FollowUp {
        /// preciseOriginTimestamp: when the Sync with the same sequenceId left.
        precise_origin: Timestamp,
    },
    /// Delay_Resp.
    DelayResp {
        /// receiveTimestamp: when the Delay_Req arrived.
        receive: Timestamp,
        /// requestingPortIdentity.
        requesting: PortIdentity,
    },
    /// Pdelay_Resp_Follow_Up.
    PdelayRespFollowUp {
        /// responseOriginTimestamp.
        response_origin: Timestamp,
        /// requestingPortIdentity.
        requesting: PortIdentity,
    },
    /// Announce.
    Announce(Announce),
    /// Signaling.
    Signaling {
        /// targetPortIdentity.
        target: PortIdentity,
    },
    /// Management.
    Management(Management),
    /// A reserved message type, whose body is not read.
    Reserved,
}

/// An Announce message: what the sender knows of the grandmaster.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Announce {
    /// originTimestamp.
    pub origin: Timestamp,
    /// currentUtcOffset: TAI − UTC in seconds.
    pub current_utc_offset: i16,
    /// grandmasterPriority1.
    pub priority1: u8,
    /// grandmasterClockQuality.
    pub quality: ClockQuality,
    /// grandmasterPriority2.
    pub priority2: u8,
    /// grandmasterIdentity.
    pub grandmaster: ClockIdentity,
    /// stepsRemoved: boundary clocks between the grandmaster and the sender.
    pub steps_removed: u16,
    /// timeSource.
    pub time_source: u8,
}

/// A Management message's fields before its TLV.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Management {
    /// targetPortIdentity.
    pub target: PortIdentity,
    /// startingBoundaryHops.
    pub starting_boundary_hops: u8,
    /// boundaryHops.
    pub boundary_hops: u8,
    /// actionField.
    pub action: Action,
}

/// What a Management message asks: actionField.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// GET, 0.
    Get,
    /// SET, 1.
    Set,
    /// RESPONSE, 2.
    Response,
    /// COMMAND, 3.
    Command,
    /// ACKNOWLEDGE, 4.
    Acknowledge,
    /// A reserved value.
    Reserved(u8),
}

impl Action {
    fn from_nibble(nibble: u8) -> Self {
        match nibble {
            0 => Self::Get,
            1 => Self::Set,
            2 => Self::Response,
            3 => Self::Command,
            4 => Self::Acknowledge,
            other => Self::Reserved(other),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => f.write_str("GET"),
            Self::Set => f.write_str("SET"),
            Self::Response => f.write_str("RESPONSE"),
            Self::Command => f.write_str("COMMAND"),
            Self::Acknowledge => f.write_str("ACKNOWLEDGE"),
            Self::Reserved(value) => write!(f, "reserved action {value}"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Action {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// tlvType values this crate reads.
pub mod tlv_type {
    /// MANAGEMENT.
    pub const MANAGEMENT: u16 = 0x0001;
    /// MANAGEMENT_ERROR_STATUS.
    pub const MANAGEMENT_ERROR_STATUS: u16 = 0x0002;
    /// ORGANIZATION_EXTENSION, which ST 2059-2 uses for its metadata.
    pub const ORGANIZATION_EXTENSION: u16 = 0x0003;
    /// PATH_TRACE.
    pub const PATH_TRACE: u16 = 0x0008;
    /// ORGANIZATION_EXTENSION_PROPAGATE (IEEE 1588-2019).
    pub const ORGANIZATION_EXTENSION_PROPAGATE: u16 = 0x4000;
    /// ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE (IEEE 1588-2019).
    pub const ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE: u16 = 0x8000;
}

/// One TLV: a type, a length and a value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Tlv {
    /// tlvType.
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub kind: u16,
    /// The value: lengthField octets.
    #[cfg_attr(feature = "serde", serde(serialize_with = "hex"))]
    pub value: Vec<u8>,
    /// What the value says, for the TLVs this crate reads.
    pub content: TlvContent,
}

/// What a TLV's value says.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "kind", rename_all = "snake_case"))]
pub enum TlvContent {
    /// A MANAGEMENT TLV, by managementId.
    Management {
        /// managementId.
        id: u16,
    },
    /// PATH_TRACE: the clocks the Announce message has passed through.
    PathTrace {
        /// pathSequence.
        clocks: Vec<ClockIdentity>,
    },
    /// The ST 2059-2 synchronization metadata.
    SyncMetadata(SyncMetadata),
    /// Another organization extension.
    OrganizationExtension {
        /// organizationId, such as `68-97-E8` for SMPTE.
        organization: String,
        /// organizationSubType.
        subtype: String,
    },
    /// A TLV this crate does not read.
    Other,
}

impl Tlv {
    /// The name IEEE 1588 gives its type, such as `ORGANIZATION_EXTENSION`.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            tlv_type::MANAGEMENT => "MANAGEMENT",
            tlv_type::MANAGEMENT_ERROR_STATUS => "MANAGEMENT_ERROR_STATUS",
            tlv_type::ORGANIZATION_EXTENSION => "ORGANIZATION_EXTENSION",
            0x0004 => "REQUEST_UNICAST_TRANSMISSION",
            0x0005 => "GRANT_UNICAST_TRANSMISSION",
            0x0006 => "CANCEL_UNICAST_TRANSMISSION",
            0x0007 => "ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION",
            tlv_type::PATH_TRACE => "PATH_TRACE",
            0x0009 => "ALTERNATE_TIME_OFFSET_INDICATOR",
            tlv_type::ORGANIZATION_EXTENSION_PROPAGATE => "ORGANIZATION_EXTENSION_PROPAGATE",
            0x4001 => "ENHANCED_ACCURACY_METRICS",
            tlv_type::ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE => "ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE",
            0x8001 => "L1_SYNC",
            0x8002 => "PORT_COMMUNICATION_AVAILABILITY",
            0x8003 => "PROTOCOL_ADDRESS",
            0x8008 => "PAD",
            0x8009 => "AUTHENTICATION",
            _ => "unknown",
        }
    }

    fn read(kind: u16, value: &[u8]) -> Self {
        let content = match kind {
            tlv_type::MANAGEMENT if value.len() >= 2 => {
                TlvContent::Management { id: u16::from_be_bytes([value[0], value[1]]) }
            }
            tlv_type::PATH_TRACE => TlvContent::PathTrace {
                clocks: value.as_chunks::<8>().0.iter().map(|clock| ClockIdentity(*clock)).collect(),
            },
            tlv_type::ORGANIZATION_EXTENSION
            | tlv_type::ORGANIZATION_EXTENSION_PROPAGATE
            | tlv_type::ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE
                if value.len() >= 6 =>
            {
                let (organization, subtype) = (&value[..3], &value[3..6]);
                match SyncMetadata::decode(&value[6..]) {
                    Some(metadata) if organization == SMPTE_OUI && subtype == SYNC_METADATA_SUBTYPE => {
                        TlvContent::SyncMetadata(metadata)
                    }
                    _ => TlvContent::OrganizationExtension {
                        organization: dashed(organization),
                        subtype: dashed(subtype),
                    },
                }
            }
            _ => TlvContent::Other,
        };
        Self { kind, value: value.to_vec(), content }
    }

    /// The synchronization metadata, if this is that TLV.
    pub fn sync_metadata(&self) -> Option<&SyncMetadata> {
        match &self.content {
            TlvContent::SyncMetadata(metadata) => Some(metadata),
            _ => None,
        }
    }

    /// Whether it carries SMPTE's organizationId and the synchronization metadata
    /// subtype, whether or not its value was long enough to read.
    pub fn is_sync_metadata(&self) -> bool {
        matches!(
            self.kind,
            tlv_type::ORGANIZATION_EXTENSION
                | tlv_type::ORGANIZATION_EXTENSION_PROPAGATE
                | tlv_type::ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE
        ) && self.value.get(..3) == Some(&SMPTE_OUI[..])
            && self.value.get(3..6) == Some(&SYNC_METADATA_SUBTYPE[..])
    }
}

fn dashed(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
}

#[cfg(feature = "serde")]
fn scaled_nanos<S: serde::Serializer>(correction: &i64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_f64(*correction as f64 / 65_536.0)
}

#[cfg(feature = "serde")]
fn hex<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Why the TLVs could not be read to the end of the message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(tag = "kind", rename_all = "snake_case"))]
pub enum TlvError {
    /// A TLV's lengthField runs past the end of the message.
    Overrun {
        /// Where the TLV starts, counting from the start of the message.
        offset: usize,
        /// Its tlvType.
        tlv_type: u16,
        /// Its lengthField.
        length: u16,
        /// The octets left for its value.
        available: usize,
    },
    /// Octets left over after the last TLV, too few to be one.
    Trailing {
        /// Where they start.
        offset: usize,
        /// How many there are.
        count: usize,
    },
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overrun { offset, tlv_type, length, available } => write!(
                f,
                "the TLV at octet {offset} (type {tlv_type:04X}h) says it has {length} octets, but only {available} are left"
            ),
            Self::Trailing { offset, count } => {
                write!(f, "{count} octets at octet {offset} are too few for a TLV")
            }
        }
    }
}

/// Why a message could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer octets than the message needs.
    Truncated {
        /// Octets it needs.
        needed: usize,
        /// Octets there are.
        available: usize,
    },
    /// A versionPTP other than 2, such as a PTPv1 message.
    Version(u8),
    /// A messageLength too short for the message type.
    Length {
        /// The message type.
        message_type: MessageType,
        /// messageLength.
        message_length: usize,
        /// Octets the message type needs at least.
        needed: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "{available} octets, but the message needs {needed}")
            }
            Self::Version(version) => {
                write!(f, "PTP version {version}: only version 2 (IEEE 1588-2008 and -2019) is read")
            }
            Self::Length { message_type, message_length, needed } => {
                let message_type = message_type.with_article();
                write!(
                    f,
                    "messageLength is {message_length}, but {message_type} message needs at least {needed} octets"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Reads fields in order from a message.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let out = self.bytes[self.at..self.at + N].try_into().expect("length checked before reading");
        self.at += N;
        out
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }

    fn clock(&mut self) -> ClockIdentity {
        ClockIdentity(self.take())
    }

    fn port(&mut self) -> PortIdentity {
        PortIdentity { clock: self.clock(), port: self.u16() }
    }

    fn timestamp(&mut self) -> Timestamp {
        let high = u64::from(self.u16());
        let low = u64::from(self.u32());
        Timestamp { seconds: high << 32 | low, nanoseconds: self.u32() }
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }
}

/// The octets each message type's body takes after the header.
fn body_length(message_type: MessageType) -> usize {
    match message_type {
        MessageType::Sync | MessageType::DelayReq | MessageType::FollowUp => 10,
        MessageType::PdelayReq | MessageType::PdelayResp | MessageType::DelayResp | MessageType::PdelayRespFollowUp => {
            20
        }
        MessageType::Announce => 30,
        MessageType::Signaling => 10,
        MessageType::Management => 14,
        MessageType::Reserved(_) => 0,
    }
}

/// Decodes one message, such as the payload of a UDP datagram to port 319 or 320.
/// Octets after `messageLength`, such as Ethernet padding, are ignored.
pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(DecodeError::Truncated { needed: HEADER_LENGTH, available: bytes.len() });
    }
    if bytes[1] & 0x0F != 2 {
        return Err(DecodeError::Version(bytes[1] & 0x0F));
    }
    let message_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let message_type = MessageType::from_nibble(bytes[0] & 0x0F);
    let needed = HEADER_LENGTH + body_length(message_type);
    if message_length < needed {
        return Err(DecodeError::Length { message_type, message_length, needed });
    }
    if bytes.len() < message_length {
        return Err(DecodeError::Truncated { needed: message_length, available: bytes.len() });
    }
    let mut r = Reader { bytes: &bytes[..message_length], at: 0 };
    let first = r.u8();
    let second = r.u8();
    let header = Header {
        message_type,
        major_sdo_id: first >> 4,
        version: second & 0x0F,
        minor_version: second >> 4,
        message_length: r.u16(),
        domain: r.u8(),
        minor_sdo_id: r.u8(),
        flags: Flags(r.u16()),
        correction: r.u64() as i64,
        message_type_specific: r.u32(),
        source: r.port(),
        sequence_id: r.u16(),
        control: r.u8(),
        log_message_interval: r.u8() as i8,
    };
    let body = match message_type {
        MessageType::Sync => Body::Sync { origin: r.timestamp() },
        MessageType::DelayReq => Body::DelayReq { origin: r.timestamp() },
        MessageType::PdelayReq => {
            let origin = r.timestamp();
            r.take::<10>();
            Body::PdelayReq { origin }
        }
        MessageType::PdelayResp => Body::PdelayResp { request_receipt: r.timestamp(), requesting: r.port() },
        MessageType::FollowUp => Body::FollowUp { precise_origin: r.timestamp() },
        MessageType::DelayResp => Body::DelayResp { receive: r.timestamp(), requesting: r.port() },
        MessageType::PdelayRespFollowUp => {
            Body::PdelayRespFollowUp { response_origin: r.timestamp(), requesting: r.port() }
        }
        MessageType::Announce => {
            let origin = r.timestamp();
            let current_utc_offset = r.u16() as i16;
            r.u8();
            Body::Announce(Announce {
                origin,
                current_utc_offset,
                priority1: r.u8(),
                quality: ClockQuality { class: r.u8(), accuracy: r.u8(), variance: r.u16() },
                priority2: r.u8(),
                grandmaster: r.clock(),
                steps_removed: r.u16(),
                time_source: r.u8(),
            })
        }
        MessageType::Signaling => Body::Signaling { target: r.port() },
        MessageType::Management => {
            let target = r.port();
            let starting_boundary_hops = r.u8();
            let boundary_hops = r.u8();
            let action = Action::from_nibble(r.u8() & 0x0F);
            r.u8();
            Body::Management(Management { target, starting_boundary_hops, boundary_hops, action })
        }
        MessageType::Reserved(_) => Body::Reserved,
    };
    let (tlvs, tlv_error) = match body {
        Body::Reserved => (Vec::new(), None),
        _ => read_tlvs(r.rest(), r.at),
    };
    Ok(Message { header, body, tlvs, tlv_error })
}

fn read_tlvs(mut rest: &[u8], mut offset: usize) -> (Vec<Tlv>, Option<TlvError>) {
    let mut tlvs = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return (tlvs, Some(TlvError::Trailing { offset, count: rest.len() }));
        }
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let length = u16::from_be_bytes([rest[2], rest[3]]);
        let Some(value) = rest.get(4..4 + usize::from(length)) else {
            let error = TlvError::Overrun { offset, tlv_type: kind, length, available: rest.len() - 4 };
            return (tlvs, Some(error));
        };
        tlvs.push(Tlv::read(kind, value));
        rest = &rest[4 + value.len()..];
        offset += 4 + value.len();
    }
    (tlvs, None)
}

impl Message {
    /// The synchronization metadata this message carries, if any.
    pub fn sync_metadata(&self) -> Option<&SyncMetadata> {
        self.tlvs.iter().find_map(Tlv::sync_metadata)
    }

    /// The Announce fields, if this is an Announce message.
    pub fn announce(&self) -> Option<&Announce> {
        match &self.body {
            Body::Announce(announce) => Some(announce),
            _ => None,
        }
    }
}
