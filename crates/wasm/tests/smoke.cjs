// Runs the Node build against the fixtures. Build it first:
//   cargo build -p st2110-wasm --target wasm32-unknown-unknown --release
//   wasm-bindgen --target nodejs --out-dir crates/wasm/pkg target/wasm32-unknown-unknown/release/st2110_wasm.wasm
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { lint, rules, checkRegistry } = require("../pkg/st2110_wasm.js");

const fixture = (name) => readFileSync(path.join(__dirname, "../../sdp/tests/fixtures", name), "utf8");

const clean = lint(fixture("video-dup.sdp"));
assert.deepEqual(clean.diagnostics, []);
assert.equal(clean.streams.length, 2);
assert.equal(clean.streams[1].mid, "secondary");
assert.equal(clean.streams[0].essence, "video");
assert.equal(clean.streams[0].payload_bitrate, 2073600000);
assert.deepEqual(clean.streams[0].reference_clock, {
  type: "ptp",
  version: "IEEE1588-2008",
  grandmaster: "08-00-11-FF-FE-21-E1-B0",
  domain: 127,
  traceable: false,
});
assert.deepEqual(clean.streams[0].media_clock, { type: "direct", offset: 0 });

const broken = lint(fixture("aes67-offset.sdp"));
assert.deepEqual(
  broken.diagnostics.map((d) => [d.rule, d.severity, d.line, d.stream]),
  [
    ["source-filter-missing", "warning", 7, 0],
    ["tsmode-absent", "info", 7, 0],
    ["mediaclk-offset", "error", 13, 0],
  ],
);

const all = rules();
assert.ok(all.length > 110);
assert.equal(all.find((r) => r.id === "mediaclk-offset").reference, "ST 2110-10:2022 §7.3");
assert.equal(all.find((r) => r.id === "receiver-caps").severity, "warning");

// The registry checks, from an object and from JSON text.
const facilityText = readFileSync(path.join(__dirname, "../../nmos/tests/fixtures/facility.json"), "utf8");
const facility = JSON.parse(facilityText);
const registry = checkRegistry(facility);
assert.deepEqual(registry.findings, []);
assert.equal(registry.summary.senders, 2);
assert.deepEqual(registry.summary.grandmasters, [{ id: "08-00-11-ff-fe-21-e1-b0", clocks: 2 }]);
assert.equal(registry.senders[1].streams[1].mid, "secondary");
assert.deepEqual(registry.receivers.map((r) => r.sender_label), ["CAM 1 audio", "CAM 1 video"]);
assert.deepEqual(checkRegistry(facilityText), registry);

facility.flows[0].frame_width = 1280;
facility.nodes[1].clocks[0].locked = false;
const flagged = checkRegistry(facility);
assert.deepEqual(
  flagged.findings.map((f) => [f.rule, f.severity, f.resource.kind, f.resource.label]),
  [
    ["ptp-unlocked", "warning", "node", "Monitor 1"],
    ["flow-sdp", "warning", "sender", "CAM 1 video"],
    ["receiver-caps", "warning", "receiver", "MON 1 video"],
  ],
);
assert.throws(() => checkRegistry("v=0"), /not a registry snapshot/);

// Objects are read as JSON: undefined keys are missing, and deep nesting or a cycle
// is refused without harming the module.
const fresh = () => JSON.parse(facilityText);
assert.equal(checkRegistry({ ...fresh(), manifests: undefined, receivers: undefined }).summary.receivers, 0);
const deep = fresh();
let nest = {};
deep.nodes[0].tags = nest;
for (let i = 0; i < 10000; i++) nest = nest.a = {};
assert.throws(() => checkRegistry(deep), /not a registry snapshot/);
const cyclic = fresh();
cyclic.nodes[0].tags = cyclic;
assert.throws(() => checkRegistry(cyclic), /not a registry snapshot: TypeError/);
assert.deepEqual(checkRegistry(fresh()), registry);
console.log(`ok: ${all.length} rules, ${registry.summary.senders} senders`);
