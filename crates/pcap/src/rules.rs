//! The capture rule catalogue.
//!
//! Every finding about a capture comes from one of these rules, whose identifiers never
//! clash with those of the SDP, NMOS and PTP message catalogues. Findings on single PTP
//! messages come from the PTP message catalogue, [`st2110_ptp::rules`].

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
    // Every RTP flow.
    PACKET_LOSS = "packet-loss", Error, "RFC 3550 §5.1",
        "No RTP packets are missing: sequence numbers, extended to 32 bits where ST 2110-20 and ST 2110-40 carry the high bits, run without gaps.";
    PACKET_ORDER = "packet-order", Warning, "RFC 3550 §5.1",
        "Packets arrive in sequence order, and each arrives once.";
    SSRC_CHANGE = "ssrc-change", Warning, "RFC 3550 §8",
        "A flow keeps one SSRC; a new one means the sender restarted or another sender took its place.";
    PAYLOAD_TYPE_MISMATCH = "payload-type-mismatch", Error, "RFC 3550 §5.1 · RFC 8866 §5.14",
        "Packets carry the payload type that the SDP file's `m=` line gives.";
    IP_FRAGMENT = "ip-fragment", Error, "ST 2110-10:2022",
        "No packet is fragmented at the IP layer.";
    UDP_SIZE = "udp-size", Error, "ST 2110-10:2022",
        "A UDP datagram is at most 1460 octets, the Standard UDP Size Limit, or the `MAXUDP` that the SDP file signals, at most 8960.";

    // Video and ancillary data.
    MARKER_BIT = "marker-bit", Error, "ST 2110-20:2022 §6.1 · RFC 8331 §2.1 · RFC 9134 §4.2",
        "The marker bit is set on the last packet of each frame, or of each field of interlaced video, and on no other packet.";
    RTP_ALIGNMENT = "rtp-alignment", Warning, "ST 2110-10:2022 §7.6 · ST 2059-1:2021",
        "Video and ancillary data timestamps fall on frame boundaries (field boundaries, for interlaced video) counted from the SMPTE Epoch and truncated to the 90 kHz clock.";
    TIMESTAMP_FUTURE = "timestamp-future", Warning, "RP 2110-25:2023 §4.8 · JT-NM Tested 2022",
        "No packet arrives before the instant its RTP timestamp names: latency is never negative.";
    TIMESTAMP_LATE = "timestamp-late", Info, "JT-NM Tested 2022",
        "Latency from RTP timestamp to arrival stays under 1 ms, or 35 ms for ancillary data, as JT-NM testing expects of a sender that stamps its own media.";
    CINST = "cinst", Error, "ST 2110-21:2022 §6.6.1, §7.1",
        "CINST, the network compatibility model's bucket, never exceeds the CMAX of the sender type in `TP`, or the `CMAX` the SDP file signals.";
    VRX_OVERFLOW = "vrx-overflow", Error, "ST 2110-21:2022 §6.6.2, §7.1",
        "The virtual receiver buffer never holds more than VRXFULL packets.";
    VRX_UNDERFLOW = "vrx-underflow", Error, "ST 2110-21:2022 §6.6.2",
        "Every packet arrives no later than its read time on the schedule that `TP` and `TROFF` give.";
    FRAME_PACKETS = "frame-packets", Error, "ST 2110-22:2022 §4",
        "Compressed video sends the same number of packets for every frame.";
    JXS_PAYLOAD_HEADER = "jxs-payload-header", Error, "RFC 9134 §4.3",
        "JPEG XS payload headers keep T and K for the whole stream, set L with M (and equal to it in codestream mode), use no reserved I value, and mark fields only in interlaced video.";

    // Audio.
    PACKET_TIME = "packet-time", Error, "ST 2110-30:2025 §6.2.1 · RFC 8866 §6.4",
        "Audio packets hold the samples that the SDP file's `ptime` gives, so consecutive timestamps step by the sampling rate times the packet time.";
    AUDIO_CHANNELS = "audio-channels", Error, "RFC 3190 §4 · ST 2110-30:2025 §6.2.1",
        "Audio packets hold the channels that the SDP file's `a=rtpmap` gives: the payload is samples times channels times octets per sample.";
    TS_DF = "ts-df", Warning, "EBU Tech 3337 · RP 2110-25:2023",
        "The timestamped delay factor over each 200 ms of an audio stream is at most one packet time.";

    // PTP, across messages.
    PTP_GRANDMASTER_CHANGE = "ptp-grandmaster-change", Warning, "IEEE 1588-2008 §9.3",
        "The grandmaster that Announce messages name in a domain stays the same through the capture.";
    PTP_MASTERS = "ptp-masters", Warning, "IEEE 1588-2008 §9.3 · ST 2059-2:2021 §6.2",
        "One port at a time sends Announce messages in a domain on the captured link, as the best master clock algorithm leaves it.";
    PTP_MESSAGE_RATE = "ptp-message-rate", Warning, "IEEE 1588-2008 §7.7.2",
        "Each port sends Announce and Sync messages at a mean interval within 30% of 2^`logMessageInterval` seconds.";
    PTP_FOLLOW_UP = "ptp-follow-up", Warning, "IEEE 1588-2008 §9.5.10",
        "Every two-step Sync is followed by a Follow_Up with its `sequenceId`.";
    PTP_DELAY_RESP = "ptp-delay-resp", Warning, "IEEE 1588-2008 §9.5.12 · ST 2059-2:2021 §6.10",
        "Every Delay_Req gets a Delay_Resp.";
    PTP_ANNOUNCE_UNIFORM = "ptp-announce-uniform", Error, "ST 2059-2:2021 §6.5.2",
        "Every port of an ST 2059-2 domain sends Announce messages with the same `logMessageInterval`, which the profile has uniform throughout a domain.";
    PTP_DELAY_REQ_RANGE = "ptp-delay-req-range", Error, "ST 2059-2:2021 §6.5.3",
        "A port's `logMinDelayReqInterval`, which its Delay_Resp messages carry, is from its own `logSyncInterval` to 5 more.";
    PTP_TRANSPORT_MODE = "ptp-transport-mode", Error, "ST 2059-2:2021 §6.10",
        "In an ST 2059-2 domain, Announce, Sync and Follow_Up messages are all multicast or all unicast, synchronization metadata goes the same way, each Delay_Resp goes as its Delay_Req came, and unicast mode shares the domain with no other mode.";
    PTP_SM_TLV_RATE = "ptp-sm-tlv-rate", Warning, "ST 2059-2:2021 §6.12",
        "The grandmaster sends the synchronization metadata TLV once a second: no more than 1.5 s passes between two from one port, and a domain announced for 3 s has some.";
    PTP_SM_LOCKING = "ptp-sm-locking", Info, "ST 2059-2:2021 §6.12, Table 2",
        "Notes each change of the grandmaster's `gmLockingStatus` in the synchronization metadata, and when it came.";
    PTP_GM_QUALITY = "ptp-gm-quality", Info, "IEEE 1588-2008 §7.6.2.4, §7.6.2.5 · ST 2059-2:2021 §6.5.4",
        "Notes each change of a grandmaster's `clockClass` or `clockAccuracy` through the capture, such as into holdover and back, and when it came.";
    PTP_REFCLK = "ptp-refclk", Warning, "ST 2110-10:2022 §8.2 · RP 2110-25:2023 §4.1",
        "A stream's `a=ts-refclk` names the grandmaster and domain the capture's PTP messages show, and says `traceable` only when a grandmaster is on the PTP timescale, time-traceable and accurate to 250 ns or better.";
}

/// Looks a rule up by its identifier.
pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().copied().find(|rule| rule.id == id)
}
