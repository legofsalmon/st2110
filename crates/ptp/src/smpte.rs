//! The synchronization metadata TLV that an ST 2059-2 grandmaster sends every second.

use st2110_sdp::Rational;

use crate::time::PtpTime;
use crate::timecode::Jam;

/// SMPTE's IEEE OUI, the TLV's organizationId.
pub const SMPTE_OUI: [u8; 3] = [0x68, 0x97, 0xE8];

/// The organizationSubType of the synchronization metadata TLV.
pub const SYNC_METADATA_SUBTYPE: [u8; 3] = [0, 0, 1];

/// How the grandmaster is locked to its reference: gmLockingStatus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockingStatus {
    /// 0: the Announce message says all there is.
    Unavailable,
    /// 1: running on its internal reference, not synchronized to an external one.
    Internal,
    /// 2: relocking fast after a disturbance, with a jump in phase and time.
    ColdLocking,
    /// 3: relocking slowly by frequency, keeping phase and time continuous.
    WarmLocking,
    /// 4: locked to an external reference: normal operation.
    ExternallyLocked,
    /// A reserved value.
    Reserved(u8),
}

impl LockingStatus {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Unavailable,
            1 => Self::Internal,
            2 => Self::ColdLocking,
            3 => Self::WarmLocking,
            4 => Self::ExternallyLocked,
            other => Self::Reserved(other),
        }
    }

    /// Its value on the wire.
    pub fn value(self) -> u8 {
        match self {
            Self::Unavailable => 0,
            Self::Internal => 1,
            Self::ColdLocking => 2,
            Self::WarmLocking => 3,
            Self::ExternallyLocked => 4,
            Self::Reserved(other) => other,
        }
    }

    /// A short description: `externally locked`, `cold locking` and so on.
    pub fn describe(self) -> String {
        match self {
            Self::Unavailable => "unavailable".into(),
            Self::Internal => "internal".into(),
            Self::ColdLocking => "cold locking".into(),
            Self::WarmLocking => "warm locking".into(),
            Self::ExternallyLocked => "externally locked".into(),
            Self::Reserved(other) => format!("reserved value {other}"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LockingStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.describe())
    }
}

/// The synchronization metadata (SM) TLV of ST 2059-2:2021 §6.12 and Table 2: what a
/// device needs, beyond PTP time, to make time code and to follow time jumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SyncMetadata {
    /// defaultSystemFrameRate, numerator.
    pub frame_rate_numerator: u32,
    /// defaultSystemFrameRate, denominator.
    pub frame_rate_denominator: u32,
    /// gmLockingStatus.
    pub locking_status: LockingStatus,
    /// timeAddressFlags: bit 0 drop-frame, bit 1 colour frame identification.
    pub time_address_flags: u8,
    /// currentLocalOffset: seconds from PTP time to Local Time.
    pub current_local_offset: i32,
    /// jumpSeconds: the size of the next discontinuity in Local Time, or 0.
    pub jump_seconds: i32,
    /// timeOfNextJump: the PTP second of that discontinuity, or 0.
    pub time_of_next_jump: u64,
    /// timeOfNextJam: the PTP second of the next daily jam, or 0 if none is scheduled.
    pub time_of_next_jam: u64,
    /// timeOfPreviousJam: the PTP second of the last daily jam.
    pub time_of_previous_jam: u64,
    /// previousJamLocalOffset: currentLocalOffset at the last daily jam.
    pub previous_jam_local_offset: i32,
    /// daylightSaving: bit 0 now, bit 1 after the next jump, bit 2 at the last jam.
    pub daylight_saving: u8,
    /// leapSecondJump: bit 0 set when the next jump is a leap second.
    pub leap_second_jump: u8,
}

impl SyncMetadata {
    /// Bytes of data after organizationId and organizationSubType.
    pub const DATA_LENGTH: usize = 42;

    /// Reads the data that follows organizationId and organizationSubType.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let data: &[u8; Self::DATA_LENGTH] = data.get(..Self::DATA_LENGTH)?.try_into().ok()?;
        let u32_at = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let u48_at = |i: usize| data[i..i + 6].iter().fold(0_u64, |n, &b| n << 8 | u64::from(b));
        Some(Self {
            frame_rate_numerator: u32_at(0),
            frame_rate_denominator: u32_at(4),
            locking_status: LockingStatus::from_byte(data[8]),
            time_address_flags: data[9],
            current_local_offset: u32_at(10) as i32,
            jump_seconds: u32_at(14) as i32,
            time_of_next_jump: u48_at(18),
            time_of_next_jam: u48_at(24),
            time_of_previous_jam: u48_at(30),
            previous_jam_local_offset: u32_at(36) as i32,
            daylight_saving: data[40],
            leap_second_jump: data[41],
        })
    }

    /// The default system frame rate, when both parts are non-zero.
    pub fn frame_rate(&self) -> Option<Rational> {
        Rational::new(u64::from(self.frame_rate_numerator), u64::from(self.frame_rate_denominator))
    }

    /// Whether time code counts in drop-frame.
    pub fn drop_frame(&self) -> bool {
        self.time_address_flags & 1 != 0
    }

    /// Whether time code uses colour frame identification.
    pub fn color_frame(&self) -> bool {
        self.time_address_flags & 2 != 0
    }

    /// Whether daylight saving time is in effect now.
    pub fn daylight_saving_now(&self) -> bool {
        self.daylight_saving & 1 != 0
    }

    /// The next daily jam, if one is scheduled. Its offset is the one Local Time will have
    /// then: `currentLocalOffset`, plus `jumpSeconds` when the next jump comes first. A
    /// jump takes effect at the start of its second, so one in the jam's own second counts
    /// as coming first.
    pub fn next_jam(&self) -> Option<Jam> {
        let time = PtpTime::new(self.time_of_next_jam, 0).filter(|_| self.time_of_next_jam != 0)?;
        let jump_first = self.time_of_next_jump != 0 && self.time_of_next_jump <= self.time_of_next_jam;
        let local_offset = if jump_first {
            self.current_local_offset.saturating_add(self.jump_seconds)
        } else {
            self.current_local_offset
        };
        Some(Jam { time, local_offset })
    }

    /// The last daily jam, if the grandmaster names one.
    pub fn previous_jam(&self) -> Option<Jam> {
        let time = PtpTime::new(self.time_of_previous_jam, 0).filter(|_| self.time_of_previous_jam != 0)?;
        Some(Jam { time, local_offset: self.previous_jam_local_offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_field() {
        let mut data = Vec::new();
        data.extend(30000_u32.to_be_bytes());
        data.extend(1001_u32.to_be_bytes());
        data.extend([4, 0b01]);
        data.extend((-18_037_i32).to_be_bytes());
        data.extend(3600_i32.to_be_bytes());
        data.extend(&1_794_207_637_u64.to_be_bytes()[2..]);
        data.extend(&1_790_568_037_u64.to_be_bytes()[2..]);
        data.extend(&1_790_481_637_u64.to_be_bytes()[2..]);
        data.extend((-18_037_i32).to_be_bytes());
        data.extend([0b011, 0]);
        assert_eq!(data.len(), SyncMetadata::DATA_LENGTH);
        let sm = SyncMetadata::decode(&data).unwrap();
        assert_eq!(sm.frame_rate().map(|r| r.to_string()).as_deref(), Some("30000/1001"));
        assert_eq!(sm.locking_status, LockingStatus::ExternallyLocked);
        assert!(sm.drop_frame() && !sm.color_frame() && sm.daylight_saving_now());
        assert_eq!((sm.current_local_offset, sm.jump_seconds), (-18_037, 3600));
        assert_eq!(sm.time_of_next_jump, 1_794_207_637);
        assert_eq!(sm.time_of_next_jam, 1_790_568_037);
        assert_eq!(sm.previous_jam().unwrap().time.seconds(), 1_790_481_637);
        assert_eq!(SyncMetadata::decode(&data[..41]), None);
    }
}
