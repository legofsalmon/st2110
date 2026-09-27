//! WebAssembly bindings for the ST 2110 SDP linter, the NMOS registry checks and the
//! PTP tools, for browsers and Node.
//!
//! Build with `wasm-pack build crates/wasm --target web` (or `--target nodejs`), then:
//!
//! ```js
//! import init, { lint, checkRegistry, decodePtp, timing } from "./pkg/st2110_wasm.js";
//!
//! await init();
//! const report = lint(sdpText);
//! for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);
//! const registry = checkRegistry(snapshot);
//! for (const f of registry.findings) console.log(f.resource?.label, f.severity, f.rule, f.message);
//! const ptp = decodePtp(udpPayload);
//! console.log(ptp.summary.join("\n"), ptp.findings);
//! const now = timing({ video: ["60000/1001"], audio: [48000], localOffset: 3563 });
//! console.log(now.video[0].next_frame, now.video[0].next_rtp, now.video[0].timecode?.address);
//! ```
//!
//! Results are plain objects shaped like the Rust types; the TypeScript declarations
//! below describe them. The registry checks read a snapshot the caller assembles from
//! the Query API (or one saved by `st2110 nmos --save`); fetching is left to the page.

use std::collections::BTreeMap;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use st2110_nmos::Snapshot;
use st2110_ptp::timing::{self, Options};
use st2110_ptp::{Message, PtpTime, TAI_UTC_2017};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type Severity = "info" | "warning" | "error";

export type Essence =
  | "video" | "compressed-video" | "audio" | "aes3" | "ancillary"
  | "fast-metadata" | "timed-text" | "sdi" | "unknown";

/** One finding. `line` counts from 1; `stream` indexes `Report.streams`. */
export interface Diagnostic {
  rule: string;
  severity: Severity;
  message: string;
  line: number | null;
  stream: number | null;
  reference: string;
}

export type RefClock =
  | { type: "ptp"; version: string; grandmaster: string | null; domain: number | null; traceable: boolean }
  | { type: "local-mac"; address: string }
  | { type: "other"; value: string };

export type MediaClock =
  | { type: "direct"; offset: number | null }
  | { type: "sender" }
  | { type: "other"; value: string };

export interface Param {
  name: string;
  value: string | null;
  quoted: boolean;
}

/** One media section. */
export interface Stream {
  index: number;
  line: number;
  media: string;
  essence: Essence;
  mid: string | null;
  destination: string | null;
  port: number | null;
  source: string | null;
  payload_type: number | null;
  encoding: string | null;
  clock_rate: number | null;
  channels: number | null;
  reference_clock: RefClock | null;
  media_clock: MediaClock | null;
  parameters: Param[];
  summary: string;
  /** Bits per second of pixels or samples, before any headers. */
  payload_bitrate: number | null;
}

export interface Report {
  streams: Stream[];
  diagnostics: Diagnostic[];
}

export interface Rule {
  id: string;
  severity: Severity;
  reference: string;
  summary: string;
}

/** What a Sender's manifest_href returned. */
export interface Manifest {
  url: string;
  status?: number;
  sdp?: string;
  error?: string;
}

/** Resources as the IS-04 Query API returned them, and each Sender's SDP file by Sender id. */
export interface Snapshot {
  source?: string;
  api_version?: string;
  nodes?: object[];
  devices?: object[];
  sources?: object[];
  flows?: object[];
  senders?: object[];
  receivers?: object[];
  manifests?: Record<string, Manifest>;
}

export type ResourceKind = "node" | "device" | "source" | "flow" | "sender" | "receiver";

/** `index` is the resource's position in its Snapshot list. */
export interface ResourceRef {
  kind: ResourceKind;
  id: string | null;
  label: string;
  index: number;
}

/** One registry finding. `line` is set for findings in a Sender's SDP file. */
export interface Finding {
  rule: string;
  severity: Severity;
  message: string;
  reference: string;
  resource: ResourceRef | null;
  line: number | null;
}

export interface SenderView {
  id: string | null;
  label: string;
  node: string | null;
  device: string | null;
  transport: string | null;
  active: boolean | null;
  flow_id: string | null;
  media_type: string | null;
  manifest_href: string | null;
  /** The streams in its SDP file, when the file was fetched. */
  streams: Stream[];
  /** Ids of the Receivers taking its stream. */
  receivers: string[];
}

export interface ReceiverView {
  id: string | null;
  label: string;
  node: string | null;
  device: string | null;
  transport: string | null;
  format: string | null;
  active: boolean;
  sender_id: string | null;
  sender_label: string | null;
}

export interface Grandmaster {
  id: string;
  clocks: number;
}

export interface RegistrySummary {
  nodes: number;
  devices: number;
  sources: number;
  flows: number;
  senders: number;
  receivers: number;
  active_senders: number;
  active_receivers: number;
  grandmasters: Grandmaster[];
  unlocked_clocks: number;
}

export interface RegistryReport {
  source: string | null;
  api_version: string | null;
  summary: RegistrySummary;
  senders: SenderView[];
  receivers: ReceiverView[];
  findings: Finding[];
}

/** A PTP timestamp as sent: 48-bit seconds and nanoseconds. */
export interface PtpTimestamp {
  seconds: number;
  nanoseconds: number;
}

export interface PortIdentity {
  clock: string;
  port: number;
}

export interface PtpHeader {
  /** "Sync", "Announce", "Management" and so on. */
  message_type: string;
  major_sdo_id: number;
  version: number;
  minor_version: number;
  message_length: number;
  domain: number;
  minor_sdo_id: number;
  /** The flags that are set, such as "two-step" or "PTP timescale". */
  flags: string[];
  correction_ns: number;
  message_type_specific: number;
  source: PortIdentity;
  sequence_id: number;
  control: number;
  /** log2 of the seconds between messages; 127 where the message type has none. */
  log_message_interval: number;
}

export interface ClockQuality {
  class: number;
  accuracy: number;
  variance: number;
}

export type PtpBody =
  | { type: "sync" | "delay_req" | "pdelay_req"; origin: PtpTimestamp }
  | { type: "pdelay_resp"; request_receipt: PtpTimestamp; requesting: PortIdentity }
  | { type: "follow_up"; precise_origin: PtpTimestamp }
  | { type: "delay_resp"; receive: PtpTimestamp; requesting: PortIdentity }
  | { type: "pdelay_resp_follow_up"; response_origin: PtpTimestamp; requesting: PortIdentity }
  | {
      type: "announce";
      origin: PtpTimestamp;
      current_utc_offset: number;
      priority1: number;
      quality: ClockQuality;
      priority2: number;
      grandmaster: string;
      steps_removed: number;
      time_source: number;
    }
  | { type: "signaling"; target: PortIdentity }
  | {
      type: "management";
      target: PortIdentity;
      starting_boundary_hops: number;
      boundary_hops: number;
      /** "GET", "SET", "RESPONSE", "COMMAND" or "ACKNOWLEDGE". */
      action: string;
    }
  | { type: "reserved" };

/** The ST 2059-2 synchronization metadata. Times are PTP seconds; offsets are seconds. */
export interface SyncMetadata {
  frame_rate_numerator: number;
  frame_rate_denominator: number;
  /** "unavailable", "internal", "cold locking", "warm locking" or "externally locked". */
  locking_status: string;
  time_address_flags: number;
  current_local_offset: number;
  jump_seconds: number;
  time_of_next_jump: number;
  time_of_next_jam: number;
  time_of_previous_jam: number;
  previous_jam_local_offset: number;
  daylight_saving: number;
  leap_second_jump: number;
}

export type TlvContent =
  | { kind: "management"; id: number }
  | { kind: "path_trace"; clocks: string[] }
  | ({ kind: "sync_metadata" } & SyncMetadata)
  | { kind: "organization_extension"; organization: string; subtype: string }
  | { kind: "other" };

export interface Tlv {
  type: number;
  /** The value in hex. */
  value: string;
  content: TlvContent;
}

export type TlvError =
  | { kind: "overrun"; offset: number; tlv_type: number; length: number; available: number }
  | { kind: "trailing"; offset: number; count: number };

export interface PtpMessage {
  header: PtpHeader;
  body: PtpBody;
  tlvs: Tlv[];
  tlv_error: TlvError | null;
}

export interface PtpFinding {
  rule: string;
  severity: Severity;
  message: string;
  reference: string;
}

/** A decoded message: lines describing it, its fields, and what breaks ST 2059-2. */
export interface DecodedPtp {
  summary: string[];
  message: PtpMessage;
  findings: PtpFinding[];
}

export interface TimingOptions {
  /** PTP time, "1790510437.123456789" or "1790510437:123456789", or UTC,
   *  "2026-09-27T12:00:00Z" as toISOString writes it. Now when omitted. */
  at?: string;
  /** TAI − UTC in seconds; 37 when omitted. */
  taiUtc?: number;
  /** Seconds from PTP time to Local Time (currentLocalOffset); UTC when omitted. */
  localOffset?: number;
  /** Video frame rates: 50, "60000/1001", 59.94. */
  video?: (number | string)[];
  /** Audio sampling rates in Hz. */
  audio?: number[];
  /** The last daily jam, as PTP or UTC time; the last Local Time midnight when omitted. */
  jam?: string;
  /** Whether 30000/1001 time code drops frames; true when omitted. */
  dropFrame?: boolean;
}

/** Times are PTP times, "seconds.nanoseconds", or calendar times, "YYYY-MM-DD hh:mm:ss.nnnnnnnnn". */
export interface Timecode {
  address: string;
  rate: string;
  drop_frame: boolean;
  jam: string;
  jam_local: string;
}

export interface VideoTiming {
  rate: string;
  frame: number;
  frame_start: string;
  next_frame: string;
  /** RTP timestamps at 90 kHz. */
  rtp: number;
  next_rtp: number;
  timecode: Timecode | null;
}

export interface AudioTiming {
  rate: number;
  rtp: number;
  block: number;
  block_start: string;
  next_block: string;
}

export interface Timing {
  ptp: string;
  utc: string;
  tai_utc: number;
  local: string;
  local_offset: number;
  video: VideoTiming[];
  audio: AudioTiming[];
}
"#;

fn to_js(value: &impl Serialize) -> Result<JsValue, JsError> {
    value.serialize(&Serializer::json_compatible()).map_err(|e| JsError::new(&e.to_string()))
}

/// Checks an SDP file: describes each stream and lists every finding in line order.
#[wasm_bindgen(unchecked_return_type = "Report")]
pub fn lint(sdp: &str) -> Result<JsValue, JsError> {
    to_js(&st2110_sdp::lint(sdp))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = JSON, js_name = stringify, catch)]
    fn json_stringify(value: &JsValue) -> Result<Option<String>, JsValue>;

    #[wasm_bindgen(js_name = String)]
    fn js_string(value: &JsValue) -> String;
}

/// A value as JSON text. Objects are read through JSON rather than directly, so that
/// nesting is limited as it is for text (serde_json stops at 128 levels) instead of
/// overflowing the stack, and keys set to `undefined` are left out as JSON leaves them.
fn json_text(value: &JsValue) -> Result<String, String> {
    if let Some(text) = value.as_string() {
        return Ok(text);
    }
    match json_stringify(value) {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Err("it has no JSON form".into()),
        Err(e) => Err(js_string(&e)),
    }
}

/// Checks a registry snapshot: its resources, PTP clocks, connections and every
/// Sender's SDP file. Takes the snapshot as an object or as JSON text.
#[wasm_bindgen(js_name = checkRegistry, unchecked_return_type = "RegistryReport")]
pub fn check_registry(
    #[wasm_bindgen(unchecked_param_type = "Snapshot | string")] snapshot: JsValue,
) -> Result<JsValue, JsError> {
    let snapshot = json_text(&snapshot)
        .and_then(|text| Snapshot::from_json(&text).map_err(|e| e.to_string()))
        .map_err(|e| JsError::new(&format!("not a registry snapshot: {e}")))?;
    to_js(&st2110_nmos::check(&snapshot))
}

/// A decoded PTP message, as `decodePtp` returns it.
#[derive(Serialize)]
struct Decoded {
    summary: Vec<String>,
    message: Message,
    findings: Vec<st2110_ptp::Finding>,
}

/// Decodes one PTP message, such as the payload of a UDP datagram to port 319 or 320,
/// and checks it against ST 2059-2. Throws when the octets are not a PTP version 2
/// message.
#[wasm_bindgen(js_name = decodePtp, unchecked_return_type = "DecodedPtp")]
pub fn decode_ptp(message: &[u8]) -> Result<JsValue, JsError> {
    let message = st2110_ptp::decode(message).map_err(|e| JsError::new(&format!("not a PTP message: {e}")))?;
    to_js(&Decoded { summary: st2110_ptp::describe::summary(&message), findings: st2110_ptp::check(&message), message })
}

#[wasm_bindgen]
extern "C" {
    /// Milliseconds since 1970-01-01 00:00:00 UTC, by the JavaScript clock.
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct TimingOptions {
    at: Option<String>,
    tai_utc: Option<i32>,
    local_offset: Option<i32>,
    video: Vec<RateValue>,
    audio: Vec<u32>,
    jam: Option<String>,
    drop_frame: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RateValue {
    Number(f64),
    Text(String),
}

/// Works out where a PTP time falls, by ST 2059-1: for each video frame rate its frame,
/// RTP timestamps and time code, and for each audio rate its RTP timestamp and AES3 block.
#[wasm_bindgen(unchecked_return_type = "Timing")]
pub fn timing(
    #[wasm_bindgen(unchecked_param_type = "TimingOptions")] options: Option<JsValue>,
) -> Result<JsValue, JsError> {
    let o: TimingOptions = if let Some(options) = options.filter(|o| !o.is_null() && !o.is_undefined()) {
        let invalid = |e: serde_wasm_bindgen::Error| JsError::new(&format!("timing options: {e}"));
        // Struct fields are looked up by name, so a misspelt option would be ignored.
        let names: BTreeMap<String, IgnoredAny> = serde_wasm_bindgen::from_value(options.clone()).map_err(invalid)?;
        const KNOWN: [&str; 7] = ["at", "taiUtc", "localOffset", "video", "audio", "jam", "dropFrame"];
        if let Some(name) = names.keys().find(|name| !KNOWN.contains(&name.as_str())) {
            return Err(JsError::new(&format!(
                "timing options: unknown option {name}; expected one of {}",
                KNOWN.join(", ")
            )));
        }
        serde_wasm_bindgen::from_value(options).map_err(invalid)?
    } else {
        TimingOptions::default()
    };
    let tai_utc = o.tai_utc.unwrap_or(TAI_UTC_2017);
    let time = |name: &str, text: &str| {
        timing::read_time(text, tai_utc)
            .ok_or_else(|| JsError::new(&format!("{name}: {text} is not a PTP or UTC time")))
    };
    let t = match o.at.as_deref() {
        Some(text) => time("at", text)?,
        None => PtpTime::from_utc(now() as i128 * 1_000_000, tai_utc)
            .ok_or_else(|| JsError::new("the clock is out of PTP's range"))?,
    };
    let jam = o.jam.as_deref().map(|text| time("jam", text)).transpose()?;
    let video = o
        .video
        .iter()
        .map(|rate| {
            let text = match rate {
                RateValue::Number(n) => n.to_string(),
                RateValue::Text(text) => text.clone(),
            };
            timing::read_frame_rate(&text).ok_or_else(|| JsError::new(&format!("video: {text} is not a frame rate")))
        })
        .collect::<Result<_, _>>()?;
    if o.audio.contains(&0) {
        return Err(JsError::new("audio: 0 is not a sampling rate"));
    }
    let options = Options {
        tai_utc,
        local_offset: o.local_offset.unwrap_or(-tai_utc),
        video,
        audio: o.audio,
        jam,
        drop_frame: o.drop_frame.unwrap_or(true),
    };
    to_js(&timing::at(t, &options).ok_or_else(|| JsError::new("a rate is too large to work with"))?)
}

/// Every rule: the SDP file rules, then the registry rules, then the PTP message rules.
#[wasm_bindgen(unchecked_return_type = "Rule[]")]
pub fn rules() -> Result<JsValue, JsError> {
    let all: Vec<&st2110_sdp::Rule> =
        st2110_sdp::rules::ALL.iter().chain(st2110_nmos::rules::ALL).chain(st2110_ptp::rules::ALL).copied().collect();
    to_js(&all)
}
