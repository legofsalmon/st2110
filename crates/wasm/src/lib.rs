//! WebAssembly bindings for the ST 2110 SDP linter and the NMOS registry checks, for
//! browsers and Node.
//!
//! Build with `wasm-pack build crates/wasm --target web` (or `--target nodejs`), then:
//!
//! ```js
//! import init, { lint, checkRegistry } from "./pkg/st2110_wasm.js";
//!
//! await init();
//! const report = lint(sdpText);
//! for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);
//! const registry = checkRegistry(snapshot);
//! for (const f of registry.findings) console.log(f.resource?.label, f.severity, f.rule, f.message);
//! ```
//!
//! Results are plain objects shaped like the Rust types; the TypeScript declarations
//! below describe them. The registry checks read a snapshot the caller assembles from
//! the Query API (or one saved by `st2110 nmos --save`); fetching is left to the page.

use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use st2110_nmos::Snapshot;
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

/// Every rule: the SDP file rules, then the registry rules.
#[wasm_bindgen(unchecked_return_type = "Rule[]")]
pub fn rules() -> Result<JsValue, JsError> {
    let all: Vec<&st2110_sdp::Rule> = st2110_sdp::rules::ALL.iter().chain(st2110_nmos::rules::ALL).copied().collect();
    to_js(&all)
}
