# st2110

Tools for SMPTE ST 2110 media over IP, written in Rust. The first piece is an SDP
linter: it reads the session description a sender publishes, describes each
stream in it and checks it against ST 2110 and the documents it builds on, citing
the clause behind every finding.

| Crate | What it is |
|---|---|
| [`crates/sdp`](crates/sdp) (`st2110-sdp`) | RFC 8866 parser, ST 2110 stream model and the linter's 94 rules. No dependencies; `serde` is an optional feature. |
| [`crates/cli`](crates/cli) (`st2110`) | The command-line linter. |
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

Severities follow the standards' own words. An **error** breaks a "shall" (or an RFC "MUST") and receivers may reject or misread the stream. A **warning** breaks a "should" or is a known interoperability hazard. An **info** note needs no action on its own.

## What it checks

The full catalogue, with the clause behind each rule, is in [docs/rules.md](docs/rules.md).

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

## Use it from JavaScript

```console
$ rustup target add wasm32-unknown-unknown
$ cargo build -p st2110-wasm --target wasm32-unknown-unknown --release
$ wasm-bindgen --target web --out-dir crates/wasm/pkg target/wasm32-unknown-unknown/release/st2110_wasm.wasm
```

`wasm-pack build crates/wasm --target web` does the same in one step. The package exports `lint(sdp)` and `rules()`, and ships TypeScript types for what they return:

```js
import init, { lint } from "./pkg/st2110_wasm.js";

await init();
const report = lint(sdpText);
for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);
```

## Development

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
```

To add a rule, add it to the catalogue in `crates/sdp/src/rules.rs`, raise it from the check in `crates/sdp/src/lint/`, and add a case to `crates/sdp/tests/rules.rs`; a test fails for any rule without one. Then regenerate the docs, which another test compares:

```console
$ cargo run -q -p st2110-cli -- rules --format markdown > docs/rules.md
```

## Roadmap

The linter is the first step of the plan in the September 2026 standards review: SDP model and linter, then a read-only NMOS client (IS-04, IS-05), PTP decoders with ST 2059-1 arithmetic, an RP 2110-25 pcap analyser, an IS-05 controller, and senders and receivers on Intel MTL.
