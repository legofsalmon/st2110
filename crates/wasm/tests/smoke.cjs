// Runs the Node build against the fixtures. Build it first:
//   cargo build -p st2110-wasm --target wasm32-unknown-unknown --release
//   wasm-bindgen --target nodejs --out-dir crates/wasm/pkg target/wasm32-unknown-unknown/release/st2110_wasm.wasm
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { lint, rules, checkRegistry, decodePtp, timing } = require("../pkg/st2110_wasm.js");

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
assert.equal(all.find((r) => r.id === "sm-jam-time").reference, "ST 2059-2:2021 Annex A");

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

// PTP messages from the grandmaster fixture, one per line in hex.
const messages = readFileSync(path.join(__dirname, "../../ptp/tests/fixtures/grandmaster.hex"), "utf8")
  .split("\n")
  .filter((line) => line && !line.startsWith("#"))
  .map((hex) => Uint8Array.from(hex.match(/../g), (octet) => parseInt(octet, 16)));
const announce = decodePtp(messages[0]);
assert.equal(announce.message.header.message_type, "Announce");
assert.deepEqual(announce.message.header.flags, [
  "PTP timescale",
  "UTC offset valid",
  "time traceable",
  "frequency traceable",
]);
assert.equal(announce.message.body.type, "announce");
assert.equal(announce.message.body.grandmaster, "08-00-11-FF-FE-21-E1-B0");
assert.deepEqual(announce.findings, []);
assert.equal(decodePtp(messages[2]).message.header.correction_ns, 1.5);
const metadata = decodePtp(messages[4]);
assert.equal(metadata.message.body.action, "COMMAND");
assert.equal(metadata.message.tlvs[0].content.kind, "sync_metadata");
assert.equal(metadata.message.tlvs[0].content.current_local_offset, 3563);
assert.match(metadata.summary[2], /next jam 2026-09-28 00:00:00 Local Time/);
const slow = messages[1].slice();
slow[33] = 0; // logMessageInterval 0: one Sync a second
assert.deepEqual(decodePtp(slow).findings.map((f) => [f.rule, f.severity]), [["sync-interval", "error"]]);
assert.throws(() => decodePtp(new Uint8Array(10)), /not a PTP message: 10 octets/);

// ST 2059-1 timing at 13:00 British Summer Time.
const at = timing({ at: "2026-09-27T12:00:00.123456789Z", localOffset: 3563, video: [59.94, "50"], audio: [48000] });
assert.equal(at.ptp, "1790510437.123456789");
assert.equal(at.local, "2026-09-27 13:00:00.123456789");
assert.deepEqual(
  at.video.map((v) => [v.rate, v.next_frame, v.next_rtp, v.timecode.address]),
  [
    ["60000/1001", "1790510437.132083334", 3061363263, "13:00:00;04"],
    ["50", "1790510437.140000000", 3061363976, "13:00:00:03"],
  ],
);
assert.equal(at.audio[0].rtp, 2205388965);
assert.ok(Number(timing().ptp) > 1790510437, "now, by Date.now()");
assert.throws(() => timing({ localoffset: 3563 }), /unknown field `localoffset`, expected one of `at`/);
assert.throws(() => timing({ video: [null] }), /video: null is not a frame rate/);
assert.throws(() => timing({ audio: [48000.5] }), /timing options: invalid type: floating point `48000.5`, expected u32$/);
let deepRate = [];
const deepOptions = { video: [deepRate] };
for (let i = 0; i < 10000; i++) deepRate = deepRate[0] = [];
assert.throws(() => timing(deepOptions), /timing options/);
const cyclicOptions = { video: [] };
cyclicOptions.video.push(cyclicOptions);
assert.throws(() => timing(cyclicOptions), /timing options: TypeError/);
assert.equal(timing({ at: "1790510437", video: [50], dropFrame: undefined }).video[0].rtp, 3061351376);
assert.throws(() => timing({ video: ["fast"] }), /not a frame rate/);
assert.throws(() => timing({ at: "noon" }), /not a PTP or UTC time/);
// Missing lists are empty lists, however they are missing.
assert.deepEqual(timing({ at: "1790510437", video: undefined, audio: null }).video, []);
assert.throws(() => timing({ taiUtc: -2147483648 }), /taiUtc: -2147483648 s is more than a day/);
assert.throws(() => timing({ at: "1790510437", jam: "1790467237.5" }), /jam: 1790467237.5 is not a whole second/);
assert.throws(() => timing({ at: "1790510437", jam: "1790510438" }), /jam: 1790510438 is later than at/);
// The clocks went forward on 28 March 2027; time code keeps the midnight jam's offset.
const spring = timing({ at: "2027-03-28T12:00:00Z", localOffset: 3563, jamLocalOffset: -37, video: [25] });
assert.deepEqual(
  [spring.local, spring.video[0].timecode.address, spring.video[0].timecode.jam_local],
  ["2027-03-28 13:00:00.000000000", "12:00:00:00", "2027-03-28 00:00:00.000000000"],
);
console.log(`ok: ${all.length} rules, ${registry.summary.senders} senders, ${messages.length} PTP messages`);
