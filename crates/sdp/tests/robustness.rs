//! The linter never panics, whatever it is given.

use st2110_sdp::{lint, parse};

const FIXTURES: [&str; 9] = [
    include_str!("fixtures/video-dup.sdp"),
    include_str!("fixtures/audio-pcm.sdp"),
    include_str!("fixtures/aes3.sdp"),
    include_str!("fixtures/aes67-offset.sdp"),
    include_str!("fixtures/anc.sdp"),
    include_str!("fixtures/jpeg-xs.sdp"),
    include_str!("fixtures/fmx.sdp"),
    include_str!("fixtures/ttml.sdp"),
    include_str!("fixtures/rfc4175.sdp"),
];

/// Fragments that stress the parsers: separators, huge and negative numbers,
/// multi-byte characters and whole lines that change the structure.
const TOKENS: [&str; 30] = [
    "=",
    ":",
    ";",
    "/",
    ",",
    " ",
    "\n",
    "\r\n",
    "{",
    "}",
    "\"",
    "0",
    "96",
    "4294967296",
    "99999999999999999999999",
    "-1",
    "0x",
    "é",
    "\u{feff}",
    "a=",
    "m=audio 0 RTP/AVP 97\n",
    "m=video 5004 RTP/AVP 96\n",
    "a=group:DUP x y\n",
    "a=group:MULTI-2SI x\n",
    "a=mid:x\n",
    "; interlace",
    "; TROFF=",
    "a=ptime:",
    "; MAXUDP=",
    "c=IN IP4 ",
];

/// xorshift64*, so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) % n as u64) as usize
    }
}

#[test]
fn edge_cases() {
    let cases = [
        "",
        "\n\n\n",
        "\u{feff}",
        "m=",
        "a",
        "=",
        "v=0\nm=video 5004 RTP/AVP 96\n",
        "v=0\nm=video 5004 RTP/AVP 96\na=fmtp:96\na=rtpmap:96 raw/90000\n",
        "v=0\nm=audio 5004 RTP/AVP 97\na=rtpmap:97 L24/48000/65535\na=ptime:99999999999999999999\n",
        "v=0\nm=audio 5004 RTP/AVP 97\na=rtpmap:97 L24/48000/8\na=ptime:0.000000000001\n",
        "v=0\nm=audio 5004 RTP/AVP 97\na=rtpmap:97 AM824/48000/65535\na=ptime:1\n",
        "v=0\nm=video 5004 RTP/AVP 96\na=rtpmap:96 raw/90000\na=fmtp:96 exactframerate=18446744073709551615/9223372036854775807; interlace\n",
        "v=0\nm=video 5004 RTP/AVP 96\na=rtpmap:96 raw/90000\na=fmtp:96 width=32767; height=32767; exactframerate=18446744073709551615; sampling=RGB; depth=16\n",
        "v=0\nm=video 5004 RTP/AVP 96\na=rtpmap:96 raw/90000\na=fmtp:96 TROFF=18446744073709551615; height=1080; exactframerate=50\n",
        "v=0\nm=application 5004 RTP/AVP 117\na=rtpmap:117 ST2110-41/48000\na=fmtp:117 SSN=ST2110-41:2024; DIT=FFFFFFFFFFFFFFFFFFFF,,\n",
        "v=0\nm=video 5004 RTP/AVP 100\na=rtpmap:100 smpte291/90000\na=fmtp:100 DID_SDID={0x,0x};DID_SDID={;DID_SDID=}\n",
        "c=IN IP4 239.1.1.1/255/4294967296\nc=IN IP6 ff0e::1/1/1\nb=AS:\no=\ns=\nt=\n",
        "a=ts-refclk:ptp=\na=mediaclk:direct=99999999999999999999999\na=source-filter:\n",
    ];
    for text in cases {
        let report = lint(text);
        let _ = parse(text);
        for d in &report.diagnostics {
            assert!(d.stream.is_none_or(|s| s < report.streams.len()), "{d:?} in {text:?}");
        }
    }
}

#[test]
fn mutated_fixtures() {
    let mut rng = Rng(0x2110_2022_0007_0040);
    for base in FIXTURES {
        for _ in 0..400 {
            let mut text: Vec<char> = base.chars().collect();
            for _ in 0..=rng.below(4) {
                let at = rng.below(text.len() + 1);
                if rng.below(3) == 0 {
                    let end = (at + 1 + rng.below(12)).min(text.len());
                    text.drain(at..end);
                } else {
                    let token = TOKENS[rng.below(TOKENS.len())];
                    text.splice(at..at, token.chars());
                }
            }
            let text: String = text.into_iter().collect();
            let report = lint(&text);
            for d in &report.diagnostics {
                assert!(d.line.is_none_or(|l| l >= 1 && l <= text.split('\n').count()), "{d:?} in {text:?}");
            }
        }
    }
}
