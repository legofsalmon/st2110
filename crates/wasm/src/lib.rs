//! WebAssembly bindings for the ST 2110 SDP linter, the NMOS registry checks, the IS-05
//! connection planner, the PTP tools and the capture analyser, for browsers and Node.
//!
//! Build with `wasm-pack build crates/wasm --target web` (or `--target nodejs`), then:
//!
//! ```js
//! import init, { lint, checkRegistry, routingMatrix, planConnection, verifyConnection, decodePtp, timing, analyseCapture }
//!   from "./pkg/st2110_wasm.js";
//!
//! await init();
//! const report = lint(sdpText);
//! for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);
//! const registry = checkRegistry(snapshot);
//! for (const f of registry.findings) console.log(f.resource?.label, f.severity, f.rule, f.message);
//! const matrix = routingMatrix(snapshot);
//! const plan = planConnection({ sdp: senderSdp, constraints: receiverConstraints, senderId });
//! // PATCH plan.request to the Receiver's /staged endpoint, then:
//! const differences = verifyConnection(plan, await (await fetch(activeUrl)).json());
//! const ptp = decodePtp(udpPayload);
//! console.log(ptp.summary.join("\n"), ptp.findings);
//! const now = timing({ video: ["60000/1001"], audio: [48000], localOffset: 3563 });
//! console.log(now.video[0].next_frame, now.video[0].next_rtp, now.video[0].timecode?.address);
//! const capture = analyseCapture(new Uint8Array(await file.arrayBuffer()), {
//!   sdp: [{ name: "camera1.sdp", text: sdpText }],
//! });
//! for (const f of capture.findings) console.log(f.flow, f.at, f.severity, f.rule, f.message);
//! ```
//!
//! Results are plain objects shaped like the Rust types; the TypeScript declarations
//! below describe them. The registry checks read a snapshot the caller assembles from
//! the Query API (or one saved by `st2110 nmos --save`), and the connection planner
//! what the caller fetched from the Connection API; fetching is left to the page.
//! A capture is analysed from memory, so the largest a page can take is what it can
//! hold; `st2110 pcap` reads files of any size as it goes.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use st2110_connect::{Activation, Constraints, Plan};
use st2110_nmos::Snapshot;
use st2110_pcap::{SdpFile, Timescale};
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

/** One Receiver's row: `fits` and `current` are positions in RoutingMatrix.senders. */
export interface MatrixRow {
  receiver: ResourceRef;
  fits: number[];
  current: number | null;
}

/** Which Senders each Receiver can take, both in label order. */
export interface RoutingMatrix {
  senders: ResourceRef[];
  receivers: MatrixRow[];
}

/** One IS-05 constraint on a transport parameter. */
export interface Constraint {
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  pattern?: string;
  description?: string;
}

export interface ConnectionOptions {
  /** The SDP file of the stream to take; leave it out to disconnect the Receiver. */
  sdp?: string;
  /** The Receiver's /constraints, one object per leg, as its Connection API returns them. */
  constraints?: Record<string, Constraint>[];
  /** The Sender whose stream it is; null or left out for one from outside NMOS. */
  senderId?: string | null;
  /** When it takes effect: "now" (the default), a PTP time such as "1790510437:0", or UTC such as "2026-09-27T12:00:00Z". */
  at?: string;
  /** Seconds after the Connection API has the request, in place of `at`. */
  in?: number;
  taiUtc?: number;
}

/** One stream a Receiver joins: the only one, or one leg of an ST 2022-7 pair. */
export interface Leg {
  destination: string;
  multicast: boolean;
  source_ip: string | null;
  destination_port: number;
}

export interface ConnectionPlan {
  /** The body to PATCH to the Receiver's /staged endpoint. */
  request: Record<string, unknown>;
  /** What its /active endpoint should show once the change takes effect. */
  expect: { sender_id: string | null; master_enable: boolean; legs: (Leg | null)[] };
  notes: string[];
  /** Why the Receiver would refuse the request, judged against its constraints. */
  problems: string[];
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
  /** TAI − UTC in seconds, at most a day either way; 37 when omitted. */
  taiUtc?: number;
  /** Seconds from PTP time to Local Time (currentLocalOffset), at most a day either way;
   *  UTC when omitted. */
  localOffset?: number;
  /** Video frame rates: 50, "60000/1001", 59.94. */
  video?: (number | string)[];
  /** Audio sampling rates in Hz. */
  audio?: number[];
  /** The last daily jam, a whole second of PTP or UTC time and not after `at`; the last
   *  Local Time midnight when omitted. */
  jam?: string;
  /** The local offset when the jam happened (previousJamLocalOffset), which time code
   *  keeps until the next jam; localOffset when omitted. */
  jamLocalOffset?: number;
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

export interface CaptureOptions {
  /** SDP files of streams in the capture; each flow is checked against the stream it
   *  matches, and flows without one are recognised from their packets. */
  sdp?: { name: string; text: string }[];
  /** The clock the capture's timestamps count: "auto" works it out from PTP Sync
   *  messages, or else the RTP timestamps; "auto" when omitted. */
  timescale?: "auto" | "ptp" | "utc";
  /** TAI − UTC in seconds, for a capture on UTC, at most a day either way; 37 when omitted. */
  taiUtc?: number;
}

/** The minimum, maximum and mean of a measurement. */
export interface Stats {
  count: number;
  min: number;
  max: number;
  mean: number;
}

export interface CaptureFile {
  /** "pcap", "pcap (nanosecond)" or "pcapng". */
  format: string;
  frames: number;
  /** When the first frame was captured, by the capturing clock: "seconds.nanoseconds" since 1970. */
  start: string | null;
  /** Seconds from the first frame to the last. */
  duration: number;
  bytes: number;
  udp: number;
  rtp: number;
  /** RTP packets in flows past the first 10,000, counted in rtp but not measured. */
  rtp_untracked: number;
  ptp: number;
  /** IP fragments after the first, which carry no UDP header. */
  fragments: number;
  other: number;
  /** Why the file could not be read to the end, when it could not. */
  error: string | null;
}

export interface CaptureTimescale {
  clock: "ptp" | "utc" | "unknown";
  /** What decided it. */
  basis: string;
  /** Nanoseconds added to the capture's timestamps to give PTP time. */
  shift: number;
  /** Anything that limits the measurements that need PTP time. */
  note: string | null;
}

/** The network compatibility model (ST 2110-21 §6.6.1). */
export interface CinstReport {
  peak: number;
  sender_type: string | null;
  cmax: number | null;
  signalled_cmax: number | null;
  cmax_narrow: number;
  cmax_narrow_linear: number;
  cmax_wide: number | null;
  /** The sender types whose CMAX the peak fits. */
  fits: string[];
  drain_us: number;
}

/** The virtual receiver buffer (ST 2110-21 §6.6.2). */
export interface VrxReport {
  schedule: "gapped" | "linear";
  troffset_us: number;
  troffset_signalled: boolean;
  vrxfull: number;
  peak: number;
  underflows: number;
  overflows: number;
  /** From each packet's arrival to its read time. */
  margin_us: Stats | null;
  method: string;
}

/** One second of a video stream: PTP seconds when the capture's clock is known. */
export interface VideoWindow {
  second: number;
  fpt: Stats | null;
  rtp_offset: Stats | null;
  latency: Stats | null;
  gap: Stats | null;
  cinst: number | null;
  vrx: number | null;
}

/** RP 2110-25 measurements of video and ancillary data. Times are in microseconds, RTP
 *  offsets in 90 kHz ticks. */
export interface VideoReport {
  frame_rate: string | null;
  height: number | null;
  interlaced: boolean;
  segmented: boolean;
  /** Frames, or fields of interlaced video. */
  units: number;
  packets_per_frame: Stats | null;
  npackets: number | null;
  /** First packet time, from each frame's reference time. */
  fpt: Stats | null;
  rtp_offset: Stats | null;
  latency: Stats | null;
  gap: Stats | null;
  cinst: CinstReport | null;
  vrx: VrxReport | null;
  models_skipped: string | null;
  vrx_skipped: string | null;
  windows: VideoWindow[];
}

export interface AudioWindow {
  second: number;
  latency: Stats | null;
  interval: Stats | null;
  ts_df: number | null;
}

/** Audio measurements. Times are in microseconds. */
export interface AudioReport {
  encoding: string;
  sample_rate: number;
  channels: number | null;
  samples_per_packet: number | null;
  packet_time_us: number | null;
  latency: Stats | null;
  interval: Stats | null;
  /** The timestamped delay factor of each 200 ms (EBU Tech 3337). */
  ts_df: Stats | null;
  windows: AudioWindow[];
}

/** One RTP flow. `first` and `last` are seconds since the capture began. */
export interface FlowReport {
  index: number;
  source: string;
  destination: string;
  essence: Essence;
  /** The SDP stream it matched, such as "camera1.sdp stream 0". */
  sdp: string | null;
  /** True when the essence was worked out from the packets. */
  guessed: boolean;
  payload_type: number;
  ssrc: string;
  packets: number;
  bytes: number;
  first: number;
  last: number;
  mbps: number | null;
  lost: number;
  out_of_order: number;
  duplicates: number;
  video: VideoReport | null;
  audio: AudioReport | null;
}

export interface MessageCount {
  kind: string;
  count: number;
  log_interval: number | null;
  interval_ms: Stats | null;
}

export interface PtpPortReport {
  port: string;
  address: string;
  messages: MessageCount[];
}

export interface PtpDomainReport {
  domain: number;
  /** The grandmasters that Announce messages named, in order, up to 16. */
  grandmasters: string[];
  ports: PtpPortReport[];
  /** From a Sync leaving the grandmaster to its arrival, in microseconds. */
  sync_offset_us: Stats | null;
}

export interface CapturePtp {
  messages: number;
  undecodable: number;
  /** Messages from ports past the first 10,000, counted in messages but not followed. */
  untracked: number;
  domains: PtpDomainReport[];
}

/** One capture finding. `flow` is a FlowReport index; `at` is seconds since the capture began. */
export interface CaptureFinding {
  rule: string;
  severity: Severity;
  message: string;
  reference: string;
  flow: number | null;
  domain: number | null;
  at: number | null;
  count: number;
}

export interface CaptureReport {
  capture: CaptureFile;
  timescale: CaptureTimescale;
  flows: FlowReport[];
  ptp: CapturePtp;
  /** Streams in the SDP files that no flow matched. */
  missing: string[];
  findings: CaptureFinding[];
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

    #[wasm_bindgen(js_namespace = JSON, js_name = parse, catch)]
    fn json_parse(text: &str) -> Result<JsValue, JsValue>;

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

/// Which Senders each Receiver in a registry snapshot can take, by transport, format
/// and capabilities: the crosspoint matrix. Takes the snapshot as `checkRegistry` does.
#[wasm_bindgen(js_name = routingMatrix, unchecked_return_type = "RoutingMatrix")]
pub fn routing_matrix(
    #[wasm_bindgen(unchecked_param_type = "Snapshot | string")] snapshot: JsValue,
) -> Result<JsValue, JsError> {
    let snapshot = json_text(&snapshot)
        .and_then(|text| Snapshot::from_json(&text).map_err(|e| e.to_string()))
        .map_err(|e| JsError::new(&format!("not a registry snapshot: {e}")))?;
    to_js(&st2110_nmos::routing::matrix(&snapshot))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionOptions {
    sdp: Option<String>,
    constraints: Option<serde_json::Value>,
    sender_id: Option<String>,
    at: Option<String>,
    #[serde(rename = "in")]
    after: Option<f64>,
    tai_utc: Option<i32>,
}

/// Plans connecting a Receiver to the stream an SDP file describes, as IS-05 asks of a
/// controller: the request for its `/staged` endpoint, with each leg's transport
/// parameters, and the problems its constraints would raise. Without `sdp`, plans
/// disconnecting it. Sending the request, and fetching what it needs, is left to the page.
#[wasm_bindgen(js_name = planConnection, unchecked_return_type = "ConnectionPlan")]
pub fn plan_connection(
    #[wasm_bindgen(unchecked_param_type = "ConnectionOptions")] options: JsValue,
) -> Result<JsValue, JsError> {
    let o: ConnectionOptions = read_options("connection options", Some(options))?;
    within_a_day("taiUtc", o.tai_utc)?;
    let tai_utc = o.tai_utc.unwrap_or(TAI_UTC_2017);
    let activation = match (o.at.as_deref().map(str::trim), o.after) {
        (Some(_), Some(_)) => return Err(JsError::new("give at or in, not both")),
        (None | Some("now"), None) => Activation::Immediate,
        (Some(text), None) => Activation::At(
            timing::read_time(text, tai_utc)
                .ok_or_else(|| JsError::new(&format!("at: {text} is not now, a PTP time or a UTC time")))?,
        ),
        (None, Some(seconds)) => Activation::After(
            std::time::Duration::try_from_secs_f64(seconds)
                .ok()
                .and_then(|d| u64::try_from(d.as_nanos()).ok())
                .ok_or_else(|| JsError::new(&format!("in: {seconds} is not a number of seconds")))?,
        ),
    };
    let plan = match o.sdp {
        None => Plan::disconnect(activation),
        Some(sdp) => {
            let constraints = o.constraints.ok_or_else(|| JsError::new("constraints: the Receiver's are needed"))?;
            let constraints =
                Constraints::from_json(&constraints).map_err(|e| JsError::new(&format!("constraints: {e}")))?;
            Plan::connect(&sdp, o.sender_id.as_deref(), &constraints, activation)
                .map_err(|e| JsError::new(&format!("sdp: {e}")))?
        }
    };
    to_js(&plan)
}

/// Where a Receiver's `/active` endpoint differs from what a plan from `planConnection`
/// asks for; an empty list when it shows the change took effect.
#[wasm_bindgen(js_name = verifyConnection, unchecked_return_type = "string[]")]
pub fn verify_connection(
    #[wasm_bindgen(unchecked_param_type = "ConnectionPlan")] plan: JsValue,
    #[wasm_bindgen(unchecked_param_type = "object")] active: JsValue,
) -> Result<JsValue, JsError> {
    let read = |name: &str, value: &JsValue| {
        json_text(value)
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&format!("{name}: {e}")))
    };
    let plan: Plan = serde_json::from_value(read("plan", &plan)?).map_err(|e| JsError::new(&format!("plan: {e}")))?;
    to_js(&plan.verify(&read("active", &active)?))
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

/// Options passed as an object or JSON text. Read through JSON, as `checkRegistry` reads
/// a snapshot, and through a Value, so that errors do not give a line and column in text
/// the caller never wrote.
fn read_options<T: DeserializeOwned + Default>(name: &str, options: Option<JsValue>) -> Result<T, JsError> {
    match options.filter(|o| !o.is_null() && !o.is_undefined()) {
        Some(options) => json_text(&options)
            .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            .and_then(|value| serde_json::from_value(value).map_err(|e| e.to_string()))
            .map_err(|e| JsError::new(&format!("{name}: {e}"))),
        None => Ok(T::default()),
    }
}

/// Refuses an offset of more than a day either way, beyond any real one.
fn within_a_day(name: &str, offset: Option<i32>) -> Result<(), JsError> {
    match offset.filter(|offset| !(-86_400..=86_400).contains(offset)) {
        Some(offset) => Err(JsError::new(&format!("{name}: {offset} s is more than a day"))),
        None => Ok(()),
    }
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct TimingOptions {
    at: Option<String>,
    tai_utc: Option<i32>,
    local_offset: Option<i32>,
    /// Numbers or text, each read as its JSON text.
    video: Option<Vec<serde_json::Value>>,
    audio: Option<Vec<u32>>,
    jam: Option<String>,
    jam_local_offset: Option<i32>,
    drop_frame: Option<bool>,
}

/// Works out where a PTP time falls, by ST 2059-1: for each video frame rate its frame,
/// RTP timestamps and time code, and for each audio rate its RTP timestamp and AES3 block.
#[wasm_bindgen(unchecked_return_type = "Timing")]
pub fn timing(
    #[wasm_bindgen(unchecked_optional_param_type = "TimingOptions")] options: Option<JsValue>,
) -> Result<JsValue, JsError> {
    let o: TimingOptions = read_options("timing options", options)?;
    for (name, offset) in
        [("taiUtc", o.tai_utc), ("localOffset", o.local_offset), ("jamLocalOffset", o.jam_local_offset)]
    {
        within_a_day(name, offset)?;
    }
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
    if let (Some(text), Some(jam)) = (&o.jam, jam) {
        if jam.subsec_nanos() != 0 {
            return Err(JsError::new(&format!("jam: {text} is not a whole second, as a daily jam is")));
        }
        if jam > t {
            return Err(JsError::new(&format!("jam: {text} is later than at; time code counts from a jam before it")));
        }
    }
    let video = o
        .video
        .unwrap_or_default()
        .iter()
        .map(|rate| {
            let text = match rate {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            timing::read_frame_rate(&text).ok_or_else(|| JsError::new(&format!("video: {text} is not a frame rate")))
        })
        .collect::<Result<_, _>>()?;
    let audio = o.audio.unwrap_or_default();
    if audio.contains(&0) {
        return Err(JsError::new("audio: 0 is not a sampling rate"));
    }
    let options = Options {
        tai_utc,
        local_offset: o.local_offset.unwrap_or(-tai_utc),
        video,
        audio,
        jam,
        jam_local_offset: o.jam_local_offset,
        drop_frame: o.drop_frame.unwrap_or(true),
    };
    to_js(&timing::at(t, &options).map_err(|e| JsError::new(&e.to_string()))?)
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct CaptureOptions {
    sdp: Option<Vec<SdpInput>>,
    timescale: Option<Clock>,
    tai_utc: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SdpInput {
    name: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Clock {
    Auto,
    Ptp,
    Utc,
}

/// Analyses a packet capture, a pcap or pcapng file: measures each RTP flow and the PTP
/// messages as RP 2110-25 describes, and checks them against the standards. Throws when
/// the octets are not a capture; one that ends partway through is analysed as far as it
/// goes, and `capture.error` says why it stopped.
#[wasm_bindgen(js_name = analyseCapture, unchecked_return_type = "CaptureReport")]
pub fn analyse_capture(
    capture: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "CaptureOptions")] options: Option<JsValue>,
) -> Result<JsValue, JsError> {
    let o: CaptureOptions = read_options("capture options", options)?;
    within_a_day("taiUtc", o.tai_utc)?;
    let options = st2110_pcap::Options {
        sdp: o.sdp.unwrap_or_default().into_iter().map(|f| SdpFile { name: f.name, text: f.text }).collect(),
        timescale: match o.timescale {
            None | Some(Clock::Auto) => Timescale::Auto,
            Some(Clock::Ptp) => Timescale::Ptp,
            Some(Clock::Utc) => Timescale::Utc,
        },
        tai_utc: o.tai_utc.unwrap_or(TAI_UTC_2017),
    };
    let report = st2110_pcap::analyse(capture, &options).map_err(|e| JsError::new(&e.to_string()))?;
    // Through JSON text, so that a count past 2⁵³, which a hostile capture can reach,
    // becomes the nearest number rather than an error.
    let text = serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))?;
    json_parse(&text).map_err(|e| JsError::new(&js_string(&e)))
}

/// Every rule: the SDP file rules, then the registry rules, the PTP message rules and
/// the capture rules.
#[wasm_bindgen(unchecked_return_type = "Rule[]")]
pub fn rules() -> Result<JsValue, JsError> {
    let all: Vec<&st2110_sdp::Rule> = st2110_sdp::rules::ALL
        .iter()
        .chain(st2110_nmos::rules::ALL)
        .chain(st2110_ptp::rules::ALL)
        .chain(st2110_pcap::rules::ALL)
        .copied()
        .collect();
    to_js(&all)
}
