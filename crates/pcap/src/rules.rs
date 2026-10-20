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
    MARKER_BIT = "marker-bit", Error, "ST 2110-20:2022 §6.1 · RFC 8331 §2.1",
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
    FRAME_BYTES = "frame-bytes", Error, "ST 2110-22:2022 §4",
        "Compressed video sends the same number of octets for every frame.";
    CBR_RATE = "cbr-rate", Error, "ST 2110-22:2022 §7.3",
        "The SDP file's `b=AS` is the measured rate of whole IP packets: octets a frame times the frame rate, in kilobits a second rounded up.";
    MULTISTREAM_TIMESTAMP = "multistream-timestamp", Error, "RP 2110-23:2019 §5.5",
        "The streams of a `MULTI-2SI` or `MULTI-SD` group carry the same RTP timestamp for each frame.";

    // ST 2110-20 payloads.
    SRD_LENGTH = "srd-length", Error, "ST 2110-20:2022 §6.1.4, §6.2",
        "Each packet has one to three sample row data headers, whose lengths are whole pixel groups, never zero beside another header, and fit the payload.";
    SRD_ORDER = "srd-order", Error, "ST 2110-20:2022 §6.1.4, §6.1.5",
        "Row segments run down the field or frame, and from left to right within a row: rows and offsets only increase.";
    SRD_GEOMETRY = "srd-geometry", Error, "ST 2110-20:2022 §6.1.4, §7.2",
        "Row segments lie within the `width` and `height` the SDP file gives, with each field of interlaced and PsF video holding half the rows.";
    BPM_BLOCKS = "bpm-blocks", Error, "ST 2110-20:2022 §6.3.3",
        "In block packing mode, every packet but the last of a field or frame carries a multiple of 180 octets of sample data.";
    GPM_SHORT = "gpm-short", Warning, "ST 2110-20:2022 §6.3.2",
        "In general packing mode, IP datagrams under 1000 octets come only at the end of a field or frame.";

    // JPEG XS.
    JXSV_ALIGNMENT = "jxsv-alignment", Warning, "VSF TR-08:2026 §8.1.2",
        "JPEG XS packets carry payload data in multiples of 8 octets, except the last packet of a field or frame.";

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
}

/// Looks a rule up by its identifier.
pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().copied().find(|rule| rule.id == id)
}
