# st2110

Tools for SMPTE ST 2110 media over IP, written in Rust. There are two so far:

- an SDP linter, which reads the session description a sender publishes, describes
  each stream in it and checks it against ST 2110 and the documents it builds on;
- an NMOS registry checker, which reads a facility's IS-04 registry and checks its
  resources, PTP clocks and connections, and every Sender's SDP file.

Every finding cites the clause behind it.

| Crate | What it is |
|---|---|
| [`crates/sdp`](crates/sdp) (`st2110-sdp`) | RFC 8866 parser, ST 2110 stream model and the linter's 94 rules. No dependencies; `serde` is an optional feature. |
| [`crates/nmos`](crates/nmos) (`st2110-nmos`) | IS-04 resource model, BCP-004-01 capability matching and the registry checker's 20 rules. The Query API client is the optional `client` feature. |
| [`crates/cli`](crates/cli) (`st2110`) | The command line: `st2110 lint` and `st2110 nmos`. |
| [`crates/wasm`](crates/wasm) (`st2110-wasm`) | WebAssembly bindings for browsers and Node. |

## Lint an SDP file

```console
$ cargo install --path crates/cli
$ st2110 lint stagebox.sdp
stagebox.sdp: 1 stream
  stream 0 (line 7, ST 2110-30) 239.69.83.67:5004: L24 48 kHz, 2 channels, 1 ms, level A, 2.30 Mb/s
stagebox.sdp:7: warning[source-filter-missing]: multicast 239.69.83.67 has no a=source-filter, so receivers join any source rather than the sender's (ST 2110-10:2022 §8.4)
stagebox.sdp:7: info[tsmode-absent]: no TSMODE, so the timestamps count as NEW (made at egress), not as sampling instants (ST 2110-10:2022 §8.7)
     7 | m=audio 5004 RTP/AVP 97
stagebox.sdp:13: error[mediaclk-offset]: RTP clock offset 963214424: ST 2110 requires direct=0; a 2110 receiver assumes zero and will misalign this stream (ST 2110-10:2022 §7.3)
    13 | a=mediaclk:direct=963214424
stagebox.sdp: 1 error, 1 warning, 1 note
```

- `st2110 lint FILE...` checks each file; `-` reads standard input.
  - `--format json` prints the streams and findings as JSON.
  - `--quiet` prints only warnings and errors.
  - `--deny-warnings` fails on warnings too.
- It exits with 0 when no file has an error, 1 when one does, and 2 when a file cannot be read.
- `st2110 rules` lists the rules; `st2110 rules mediaclk-offset` explains one.

## Check an NMOS registry

```console
$ st2110 nmos http://registry.example:8080
http://registry.example:8080/x-nmos/query/v1.3/ (IS-04 v1.3)
  2 nodes, 2 devices, 2 sources, 2 flows, 2 senders (2 active), 2 receivers (2 active)
  PTP: 1 clock locked to 08-00-11-ff-fe-21-e1-b0; 1 clock unlocked
senders:
  "CAM 1 audio" (5e0d0002) on Camera 1: active, rtp.mcast, audio/L24, 1 receiver
    stream 0 (line 5, ST 2110-30) 239.10.10.2:5006: L24 48 kHz, 8 channels (51,ST), 1 ms, level A, 9.22 Mb/s
  "CAM 1 video" (5e0d0001) on Camera 1: active, rtp.mcast, video/raw, 1 receiver
    stream 0 (line 6, ST 2110-20, mid primary) 239.10.10.1:5004: 1920x1080 progressive, 50 fps, YCbCr-4:2:2 10-bit, BT709 SDR, 2110GPM, 2110TPN, 2.07 Gb/s
    stream 1 (line 14, ST 2110-20, mid secondary) 239.20.10.1:5004: 1920x1080 progressive, 50 fps, YCbCr-4:2:2 10-bit, BT709 SDR, 2110GPM, 2110TPN, 2.07 Gb/s
receivers:
  "MON 1 audio" (7ecf0002) on Monitor 1: active, rtp.mcast, audio, from "CAM 1 audio" (5e0d0002)
  "MON 1 video" (7ecf0001) on Monitor 1: active, rtp.mcast, video, from "CAM 1 video" (5e0d0001)
node "Monitor 1" (a0de0002): warning[ptp-unlocked]: PTP clock clk0 is not locked, so its time has no defined relationship to the grandmaster (IS-04 v1.3 schemas)
sender "CAM 1 audio" (5e0d0002), SDP line 12: error[mediaclk-offset]: RTP clock offset 963214424: ST 2110 requires direct=0; a 2110 receiver assumes zero and will misalign this stream (ST 2110-10:2022 §7.3)
    12 | a=mediaclk:direct=963214424
sender "CAM 1 video" (5e0d0001): warning[flow-sdp]: its Flow's frame_width is 1280, but width is 1920 (NMOS Parameter Registers: Capabilities)
receiver "MON 1 video" (7ecf0001): warning[receiver-caps]: none of its constraint sets accepts what sender "CAM 1 video" (5e0d0001) sends: "1080p": frame_width 1280 is not one of 1920; "720p": frame_height 1080 is not one of 720 (BCP-004-01 v1.0 · IS-04 v1.3 schemas)
registry: 1 error, 3 warnings, 0 notes
```

- `st2110 nmos URL` reads a registry through its IS-04 Query API, then fetches each Sender's SDP file from its `manifest_href`.
  - It uses the newest Query API version the registry offers from v1.0 to v1.3, or the one a URL such as `http://registry.example:8080/x-nmos/query/v1.2` names.
  - It pages through each collection and asks for resources registered at every version. It falls back when a registry answers 501 to either request, and reads every page of a registry that pages without being asked. It asks a v1.0 registry, which has neither, for each collection whole.
  - It goes through the proxy in `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` unless `NO_PROXY` names the host, and checks HTTPS certificates against the system's trust store.
- `--save FILE` keeps what it read as a JSON snapshot. `st2110 nmos FILE` checks a snapshot again without the network, and `-` reads one from standard input.
- `--no-sdp` skips the SDP files, and `--timeout` sets the seconds allowed for each response (5 by default).
- `--format json`, `--quiet` and `--deny-warnings` work as they do for `lint`.
- It exits with 0 when nothing is an error, 1 when something is, and 2 when the registry or file cannot be read.

It only reads. It does not browse DNS-SD for the registry, so give it the URL, and it does not yet send IS-10 access tokens.

Severities follow the standards' own words. An **error** breaks a "shall" (or an RFC or NMOS "MUST"), so equipment may reject or misread what it describes. A **warning** breaks a "should" or is a known interoperability hazard. An **info** note needs no action on its own.

## What it checks

The full catalogue, with the clause behind each rule, is in [docs/rules.md](docs/rules.md).

### SDP files

| Area | Checks |
|---|---|
| RFC 8866 | Line syntax and order, required and repeated lines, `o=`, `t=`, `c=` with multicast TTL, `b=`, `rtpmap`/`fmtp` pairing |
| ST 2110-10 | Dynamic payload types, `ts-refclk` (PTP version, grandmaster, domain, `localmac`), `mediaclk:direct=0`, `source-filter`, `MAXUDP`, `TSMODE`, `TSDELAY` |
| ST 2022-7, RP 2110-23 | `DUP` legs that match and are addressed apart, `MULTI-2SI` stream counts and addresses, `FID` without ANC |
| ST 2110-20, -21 | Required parameters and their values, the `SSN` edition rule, interlace and PsF, pixel groups, block packing, `TP`, default `TROFF`, RFC 4175 look-alikes |
| RP 2110-24 | SD width, height and pixel aspect ratio |
| ST 2110-22 | `b=AS`, `TP`, frame rate, JPEG XS `packetmode` (VSF TR-08) |
| ST 2110-30, -31 | Sampling rate, `ptime`, conformance levels, packet size against `MAXUDP`, `channel-order`, AM824 channel pairs |
| ST 2110-40, -41, -43 | ANC `SSN`/`TM`/`exactframerate`, `DID_SDID`, `VPID_Code`; FMX `SSN` and `DIT`; TTML clock and `codecs` |

It follows the editions current on pub.smpte.org in September 2026: ST 2110-10:2022, -20:2022, -21:2022, -22:2022, -30:2025, -31:2022, -40:2023, -41:2024 (whose SSN the 2026 edition keeps), -43:2021, RP 2110-23:2019, RP 2110-24:2023 and ST 2022-7:2019.

It reads SDP only. It never looks at packets, so it cannot confirm that a sender does what its SDP says; that is the job of the planned RP 2110-25 analyser. It also leaves out the interlaced `TROFF` defaults, which ST 2110-21:2022 Table 1 misprints for 525 and 625 lines, and the ST 2110-31 levels at 44.1 and 96 kHz.

### NMOS registries

| Area | Checks |
|---|---|
| Resources | The attributes each IS-04 schema requires and their types, `id` and `version` syntax, duplicate ids, parents and references that are not registered, interface and clock names a Node does not have |
| PTP | Unlocked clocks, locked clocks that follow different grandmasters (unless both are traceable to TAI), and a Sender whose `a=ts-refclk` disagrees with its Source's clock |
| Connections | Subscriptions that contradict `active`, active Receivers taking from an inactive Sender, and Receivers whose BCP-004-01 `caps` reject what their Sender sends |
| SDP files | Each Sender's `manifest_href` and whether it answers, every SDP rule above, one interface binding per stream, multicast or unicast addresses to match the transport, and the file against the Flow, Source and Sender attributes that the NMOS capabilities register maps to SDP |

It reads resources registered at any IS-04 version from v1.0 to v1.3, and reports an attribute as missing only when every version that could have registered the resource requires it.

## Use the library

```rust
let report = st2110_sdp::lint(&sdp);
for stream in &report.streams {
    println!("{} {}: {}", stream.essence.standard(), stream.destination.as_deref().unwrap_or("-"), stream.summary);
}
for d in &report.diagnostics {
    println!("{:?} {} {}: {} ({})", d.line, d.severity, d.rule, d.message, d.reference);
}
```

`st2110_sdp::parse` gives the raw session description, and the `video` and `audio` modules expose the arithmetic behind the checks: pixel groups, payload bit rates, ST 2110-21 read offsets, conformance levels and packet sizes.

For a registry, read a snapshot with the client (the `client` feature) or from JSON, then check it:

```rust
use st2110_nmos::client::{Options, QueryClient};

let snapshot = QueryClient::connect("http://registry.example:8080", &Options::default())?.snapshot()?;
let report = st2110_nmos::check(&snapshot);
for f in &report.findings {
    let at = f.resource.as_ref().map_or("registry".to_string(), |r| r.describe());
    println!("{at}: {} {}: {}", f.severity, f.rule, f.message);
}
```

`report.senders` and `report.receivers` list the connections as a controller would show them, with the streams from each Sender's SDP file.

## Use it from JavaScript

```console
$ rustup target add wasm32-unknown-unknown
$ cargo build -p st2110-wasm --target wasm32-unknown-unknown --release
$ wasm-bindgen --target web --out-dir crates/wasm/pkg target/wasm32-unknown-unknown/release/st2110_wasm.wasm
```

`wasm-pack build crates/wasm --target web` does the same in one step. The package exports `lint(sdp)`, `checkRegistry(snapshot)` and `rules()`, and ships TypeScript types for what they return:

```js
import init, { lint, checkRegistry } from "./pkg/st2110_wasm.js";

await init();
const report = lint(sdpText);
for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);

const registry = checkRegistry(snapshot);
for (const f of registry.findings) console.log(f.resource?.label, f.severity, f.rule, f.message);
```

`checkRegistry` takes a snapshot as an object or as JSON text, in the format `st2110 nmos --save` writes. The page fetches the resources and SDP files itself.

## Development

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
```

To add an SDP rule, add it to the catalogue in `crates/sdp/src/rules.rs`, raise it from the check in `crates/sdp/src/lint/`, and add a case to `crates/sdp/tests/rules.rs`. A registry rule goes in `crates/nmos/src/rules.rs`, is raised from `crates/nmos/src/check.rs`, and needs a case in `crates/nmos/tests/checks.rs`. A test fails for any rule without one. Then regenerate the docs, which another test compares:

```console
$ cargo run -q -p st2110-cli -- rules --format markdown > docs/rules.md
```

## Roadmap

These are the first two steps of the plan in the September 2026 standards review: the SDP model and linter, then the read-only NMOS client. Next come PTP decoders with ST 2059-1 arithmetic, an RP 2110-25 pcap analyser, an IS-05 controller, and senders and receivers on Intel MTL.
