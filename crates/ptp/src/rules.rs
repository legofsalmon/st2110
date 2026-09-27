//! The PTP message rule catalogue.
//!
//! Every finding about a PTP message comes from one of these rules, whose identifiers
//! never clash with those of the SDP and NMOS catalogues.

use st2110_sdp::{Rule, Severity};

macro_rules! rules {
    ($($name:ident = $id:literal, $severity:ident, $reference:literal, $summary:literal;)+) => {
        $(
            #[doc = $summary]
            pub static $name: Rule = Rule {
                id: $id,
                severity: Severity::$severity,
                reference: $reference,
                summary: $summary,
            };
        )+

        /// Every rule, in catalogue order.
        pub static ALL: &[&Rule] = &[$(&$name),+];
    };
}

rules! {
    // Header and message rates.
    PTP_DOMAIN = "ptp-domain", Error, "ST 2059-2:2021 §6.5.2",
        "`domainNumber` is 0 to 127, the range the profile allows; the default is 127.";
    ANNOUNCE_INTERVAL = "announce-interval", Error, "ST 2059-2:2021 §6.5.2",
        "An Announce message's `logMessageInterval` is −3 (8 a second) to 1 (one every 2 s); the default is 0, one a second.";
    SYNC_INTERVAL = "sync-interval", Error, "ST 2059-2:2021 §6.5.2",
        "A Sync or Follow_Up message's `logMessageInterval` is −7 (128 a second) to −1 (2 a second); the default is −3, 8 a second.";
    DELAY_REQ_INTERVAL = "delay-req-interval", Error, "ST 2059-2:2021 §6.5.3",
        "A Delay_Resp message's `logMessageInterval`, the leader's `logMinDelayReqInterval`, is at most 5 more than `logSyncInterval`: −7 to 4.";

    // The grandmaster, from Announce messages.
    CLOCK_ACCURACY = "clock-accuracy", Warning, "ST 2059-2:2021 §6.5.4",
        "The grandmaster's `clockAccuracy` is not Unknown (FEh).";
    TIME_SOURCE = "time-source", Warning, "ST 2059-2:2021 §6.5.5 · IEEE 1588-2008 §7.6.2.6",
        "`timeSource` is a value IEEE 1588 defines, or F0h or F1h, which ST 2059-2 adds for a grandmaster locked to a video reference.";
    GM_CLOCK_CLASS = "gm-clock-class", Warning, "IEEE 1588-2008 §7.6.2.4",
        "The grandmaster is locked to its reference: `clockClass` 6, or 13 on an arbitrary timescale, rather than in holdover, degraded or free-running.";
    UTC_OFFSET = "utc-offset", Warning, "IEEE 1588-2008 §8.2.4.2 · IERS Bulletin C",
        "A `currentUtcOffset` marked valid is at least 37 s, TAI − UTC since 1 January 2017.";
    ARB_TIMESCALE = "arb-timescale", Info, "IEEE 1588-2008 §7.2.1 · ST 2059-1:2021 §6.1",
        "Notes a grandmaster on an arbitrary timescale (`ptpTimescale` clear): its time is not TAI, so signals align to its own epoch, not the SMPTE Epoch.";

    // The synchronization metadata TLV.
    SM_TLV_MESSAGE = "sm-tlv-message", Error, "ST 2059-2:2021 §6.12",
        "The synchronization metadata TLV is an ORGANIZATION_EXTENSION TLV in a Management message whose `targetPortIdentity` is all ones and whose `actionField` is COMMAND.";
    SM_TLV_LENGTH = "sm-tlv-length", Error, "ST 2059-2:2021 Table 2",
        "The synchronization metadata TLV's `lengthField` is 48.";
    SM_FRAME_RATE = "sm-frame-rate", Warning, "ST 2059-2:2021 Table 2",
        "`defaultSystemFrameRate` is a frame rate in lowest terms, such as 30000/1001 or 50/1.";
    SM_LOCKING_STATUS = "sm-locking-status", Error, "ST 2059-2:2021 Table 2",
        "`gmLockingStatus` is 0 to 4.";
    SM_RESERVED = "sm-reserved", Warning, "ST 2059-2:2021 Table 2",
        "The reserved bits of `timeAddressFlags`, `daylightSaving` and `leapSecondJump` are zero.";
    SM_JAM_TIME = "sm-jam-time", Error, "ST 2059-2:2021 Annex A",
        "A daily jam falls on a Local Time that is a whole number of 10 minutes.";
    SM_JUMP = "sm-jump", Warning, "ST 2059-2:2021 Table 2",
        "`jumpSeconds` and `timeOfNextJump` are both zero, or both set: a discontinuity has a size and a time.";
    SM_LOCAL_OFFSET = "sm-local-offset", Warning, "ST 2059-2:2021 Table 2",
        "`currentLocalOffset` and `previousJamLocalOffset` are time-zone offsets: from UTC−12 h to UTC+14 h, less TAI − UTC.";

    // TLVs.
    TLV_LENGTH = "tlv-length", Error, "IEEE 1588-2008 §14.1",
        "Each TLV's `lengthField` is even and ends within `messageLength`.";
}

/// Looks a rule up by its identifier.
pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().copied().find(|rule| rule.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_new() {
        let mut ids: Vec<&str> = ALL.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ALL.len());
        for rule in ALL {
            assert!(st2110_sdp::rules::find(rule.id).is_none(), "{} is an SDP rule too", rule.id);
            assert!(rule.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'), "{}", rule.id);
            assert!(rule.summary.ends_with('.'), "{}", rule.id);
        }
    }
}
