//! WebAssembly bindings for the ST 2110 SDP linter, for browsers and Node.
//!
//! Build with `wasm-pack build crates/wasm --target web` (or `--target nodejs`), then:
//!
//! ```js
//! import init, { lint, rules } from "./pkg/st2110_wasm.js";
//!
//! await init();
//! const report = lint(sdpText);
//! for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);
//! ```
//!
//! Results are plain objects shaped like the Rust types; the TypeScript declarations
//! below describe them.

use serde::Serialize;
use serde_wasm_bindgen::Serializer;
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
"#;

fn to_js(value: &impl Serialize) -> Result<JsValue, JsError> {
    value.serialize(&Serializer::json_compatible()).map_err(|e| JsError::new(&e.to_string()))
}

/// Checks an SDP file: describes each stream and lists every finding in line order.
#[wasm_bindgen(unchecked_return_type = "Report")]
pub fn lint(sdp: &str) -> Result<JsValue, JsError> {
    to_js(&st2110_sdp::lint(sdp))
}

/// Every lint rule, in catalogue order.
#[wasm_bindgen(unchecked_return_type = "Rule[]")]
pub fn rules() -> Result<JsValue, JsError> {
    to_js(&st2110_sdp::rules::ALL)
}
