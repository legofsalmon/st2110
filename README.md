# st2110

Tools for SMPTE ST 2110 media over IP, written in Rust. There are seven so far:

- an SDP linter, which reads the session description a sender publishes, describes
  each stream in it and checks it against ST 2110 and the documents it builds on;
- an NMOS registry checker, which reads a facility's IS-04 registry and checks its
  resources, PTP clocks and connections, and every Sender's SDP file;
- an IS-05 connection controller, which connects Receivers to Senders one at a time
  or as a salvo that switches at one PTP time, checking each against the Receiver's
  constraints and capabilities first and on the Receiver and in the registry after;
- stream discovery, which finds the streams on a network as a monitor does: from the
  SDP files senders announce by SAP, and from the Senders of the NMOS registries and
  Nodes it finds by DNS-SD, read peer to peer where there is no registry;
- PTP tools, which decode IEEE 1588 messages and check them against the ST 2059-2
  profile, and work out from PTP time where frames, RTP timestamps and time code fall
  by ST 2059-1;
- a capture analyser, which reads pcap and pcapng files and measures each flow as
  RP 2110-25 describes: loss, timing against PTP time, the ST 2110-21 sender models,
  audio packet timing, and the PTP messages across the capture;
- a sender and receiver on ordinary UDP sockets, which send colour bars as ST 2110-20
  video or tone as ST 2110-30 audio, paced by ST 2110-21 and lined up with the SMPTE
  Epoch, on one leg or an ST 2022-7 pair, and receive a stream from its SDP file,
  merging the legs, putting the packets back in order and the frames and samples back
  together, and reporting what arrived, or showing the video in a window as it arrives,
  from the command line or in ST 2110 Viewer, an app for the Mac that lists the streams
  discovery finds.

Every finding cites the clause behind it.

| Crate | What it is |
|---|---|
| [`crates/sdp`](crates/sdp) (`st2110-sdp`) | RFC 8866 parser, ST 2110 stream model and the linter's 94 rules. No dependencies; `serde` is an optional feature. |
| [`crates/nmos`](crates/nmos) (`st2110-nmos`) | IS-04 resource model, BCP-004-01 capability matching, the registry checker's 21 rules, and the crosspoint matrix of which Senders each Receiver can take. The Query API client is the optional `client` feature. |
| [`crates/connect`](crates/connect) (`st2110-connect`) | IS-05 connection planning: an SDP file's streams as a Receiver's legs, its constraints, the request that connects it and the check of what it shows after. The Connection API client and the controller that makes salvos and rolls them back are the optional `client` feature. |
| [`crates/ptp`](crates/ptp) (`st2110-ptp`) | IEEE 1588 message decoder, the ST 2059-2 profile's 20 rules, and ST 2059-1 arithmetic: alignment points, RTP timestamps and daily-jam time code. `serde` is an optional feature. |
| [`crates/pcap`](crates/pcap) (`st2110-pcap`) | pcap and pcapng reader, RP 2110-25 measurements, the ST 2110-21 network compatibility and virtual receiver models, and the analyser's 22 rules. `serde` is an optional feature. |
| [`crates/media`](crates/media) (`st2110-media`) | ST 2110-20 and -30 packetisers and depacketisers, ST 2110-21 pacing, ST 2022-7 merging and reordering, colour bars and tone, the SDP files senders write, and PNG, WAV and pcap writers. The sockets are the optional `net` feature, and `serde` is another. |
| [`crates/discover`](crates/discover) (`st2110-discover`) | Stream discovery: SAP (RFC 2974) listening and announcing, a DNS-SD browser over multicast and unicast DNS for NMOS registries and Nodes, and the reader that lists their Senders' streams with those SAP announces, each once. |
| [`crates/cli`](crates/cli) (`st2110`) | The command line: `st2110 lint`, `st2110 nmos`, `st2110 connect`, `st2110 ptp`, `st2110 pcap`, `st2110 time`, `st2110 discover`, `st2110 send`, `st2110 receive` and `st2110 view`. The window `view` opens is the default `view` feature. |
| [`crates/viewer`](crates/viewer) (`st2110-viewer`) | ST 2110 Viewer, a desktop app that lists the streams on the network and plays one, or a capture, with what has arrived beside it. Built with egui, and needs Rust 1.95; the rest builds with 1.88. |
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

- `st2110 nmos URL` reads a registry through its IS-04 Query API, then fetches each Sender's SDP file from its `manifest_href`, and from its Connection API's `/transportfile` too when that is another URL.
  - It uses the newest Query API version the registry offers from v1.0 to v1.3, or the one a URL such as `http://registry.example:8080/x-nmos/query/v1.2` names.
  - It pages through each collection and asks for resources registered at every version. It falls back when a registry answers 501 to either request, and reads every page of a registry that pages without being asked. It asks a v1.0 registry, which has neither, for each collection whole.
  - It goes through the proxy in `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` unless `NO_PROXY` names the host, and checks HTTPS certificates against the system's trust store.
- `--save FILE` keeps what it read as a JSON snapshot. `st2110 nmos FILE` checks a snapshot again without the network, and `-` reads one from standard input.
- `--no-sdp` skips the SDP files, and `--timeout` sets the seconds allowed for each response (5 by default).
- `--format json`, `--quiet` and `--deny-warnings` work as they do for `lint`.
- It exits with 0 when nothing is an error, 1 when something is, and 2 when the registry or file cannot be read.

It only reads; `st2110 connect` makes connections. Give it a Node's address, or its Node API URL such as `http://camera.example/x-nmos/node/`, to check that Node alone where there is no registry. It reads the registry it is given, and `st2110 discover` finds registries and Nodes by DNS-SD. It does not yet send IS-10 access tokens.

## Connect Receivers to Senders

```console
$ st2110 connect http://registry.example:8080 --receiver "MON 1 video"
receiver "MON 1 video" (7ecf0001)
  sender "CAM 1 video" (5e0d0001), taking it now
  sender "CAM 2 video" (5e0d0003)
$ cat switch.json
[
  {"receiver": "MON 1 video", "sender": "CAM 2 video"},
  {"receiver": "MON 1 audio", "sender": "CAM 2 audio"}
]
$ st2110 connect http://registry.example:8080 --salvo switch.json
receiver "MON 1 video" (7ecf0001) ← sender "CAM 2 video" (5e0d0003): done at 2026-09-27 12:00:02.113542817 UTC
  leg 1: 239.10.20.1:5004 from 192.168.10.21
  leg 2: 239.20.20.1:5004 from 192.168.20.21
receiver "MON 1 audio" (7ecf0002) ← sender "CAM 2 audio" (5e0d0004): done at 2026-09-27 12:00:02.113542817 UTC
  leg 1: 239.10.20.2:5006 from 192.168.10.22
2 connections: 2 done
$ st2110 connect http://registry.example:8080 --receiver "MON 1 video" --sender "CAM 1 audio"
receiver "MON 1 video" (7ecf0001) ← sender "CAM 1 audio" (5e0d0002): refused
  leg 1: 239.10.10.2:5006 from 192.168.10.22
  leg 2: off
  note: the stream has one leg, so the Receiver's leg 2 is turned off: it has no ST 2022-7 protection
  problem: it is a video Receiver, but sender "CAM 1 audio" (5e0d0002) sends audio
1 connection: 1 refused
```

- `st2110 connect URL` lists which Senders each Receiver can take, by transport, format and BCP-004-01 capabilities (reading each Sender's SDP file for those judged on it), and marks the one it takes now; `--receiver` shows one Receiver, and `--format json` gives the whole crosspoint matrix.
- `--receiver` with `--sender` connects a Receiver to a Sender's stream, `--sdp FILE` to the stream an SDP file describes (such as one from outside NMOS), and `--disconnect` turns it off. A Sender or Receiver is named by its id, its label or the start of its id.
- `--salvo FILE` makes several connections together, from a JSON list like the one above; an entry takes `"sender"`, `"sdp"` or `"disconnect": true`.
- Each connection follows IS-05 v1.2 as a controller should:
  - it reads the Receiver's `/active` endpoint, its `/constraints` and the Sender's SDP file, fetched afresh from `manifest_href` or else its `/transportfile`;
  - it stages the SDP file with every leg's `transport_params` spelled out (group, source, port and `rtp_enabled`), `master_enable` and `sender_id`. A two-leg ST 2022-7 Receiver given a one-leg stream has leg 2 turned off; a one-leg Receiver given a pair joins path 1;
  - it sends nothing the Receiver's constraints or capabilities would reject, unless `--force` is given. `--dry-run` shows what it would send.
- One connection takes effect at once. Several are scheduled for one PTP time `--lead` seconds ahead (2 by default), so that every Receiver switches together. `--at` sets the time (`now`, a PTP time or a UTC time), and `--in` a delay each Device counts from when it has the request.
- Receivers that share a Connection API get one `/bulk/receivers` request, or one `PATCH` each when the API has no bulk interface. A salvo's requests have half the lead to be answered, so that when a Connection API refuses its part, fails or does not answer, the rest can be cancelled before they are due. A Receiver that switched all the same is put back as its `/active` endpoint showed it, and one that another controller has changed since is left alone.
- After, it waits for each connection to come due, checks the Receiver's `/active` endpoint shows it, and checks the registry for the Receiver's new subscription and version, which IS-05 requires the Node to update; a registry that lags is a warning. `--wait` sets how long each check may take (5 s), and a connection due later than that is reported as scheduled. `--cancel` cancels an activation scheduled on a Receiver.
- TARGET may also be a snapshot saved with `st2110 nmos --save`, when the registry is out of reach; the registry check is then skipped.
- It exits with 0 when every connection was made, scheduled or planned, 1 when one was refused, failed or differs, and 2 when the registry or a file cannot be read, or a name finds no Sender or Receiver or more than one.

It connects Receivers only: it does not yet set a unicast Sender's destination or turn Senders on and off. It polls rather than following the Query API's WebSocket subscriptions, and like `st2110 nmos` it does not browse DNS-SD or send IS-10 access tokens.

## Decode PTP messages

```console
$ tshark -r studio.pcap -Y "ptp && udp" -T fields -e udp.payload > gm.hex
$ st2110 ptp gm.hex
gm.hex:1: Announce from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 2, one a second
  grandmaster 08-00-11-FF-FE-21-E1-B0: priority 128/128, class 248 (free-running: the default class), accuracy unknown (FEh), variance 4E5Dh, 0 steps removed, GNSS (20h)
  UTC offset 37 s (valid); PTP timescale, UTC offset valid
gm.hex:1: warning[clock-accuracy]: the grandmaster's clockAccuracy is Unknown (FEh) (ST 2059-2:2021 §6.5.4)
gm.hex:1: warning[gm-clock-class]: grandmaster 08-00-11-FF-FE-21-E1-B0 has clockClass 248: free-running: the default class (IEEE 1588-2008 §7.6.2.4)
gm.hex:2: Sync from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 9, one a second
  origin 1790510439.000000000; two-step
gm.hex:2: error[sync-interval]: logMessageInterval is 0 (one a second), outside −7 to −1 (ST 2059-2:2021 §6.5.2)
gm.hex:3: Management from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 2
  COMMAND to FF-FF-FF-FF-FF-FF-FF-FF port 65535, boundary hops 0 of 0
  synchronization metadata: 30000/1001 fps drop-frame, externally locked, local offset 3563 s, next jam 2026-09-28 00:05:00 Local Time, jump of -3600 s at 2026-10-25 02:00:00 Local Time
gm.hex:3: error[sm-jam-time]: timeOfNextJam 1790550337 is 2026-09-28 00:05:00 Local Time, not a whole number of 10 minutes (ST 2059-2:2021 Annex A)
gm.hex: 3 messages, 2 errors, 2 warnings, 0 notes
```

- `st2110 ptp FILE...` reads one message per line in hex, with or without colons between octets, or a file that holds one message in binary. `#` starts a comment, and `-` reads standard input.
- It decodes every IEEE 1588-2008 and -2019 message type, and the TLVs after them: the ST 2059-2 synchronization metadata, path traces, and the organization and management TLVs by name.
- It checks each message on its own: the domain and message rates the profile allows, the grandmaster's quality and time source, and the synchronization metadata's frame rate, jam times and time jumps. `st2110 pcap` makes the checks across messages, such as whether every Announce names the same grandmaster.
- `--format json`, `--quiet` and `--deny-warnings` work as they do for `lint`. A line that is not a message counts as an error.

## Analyse a packet capture

```console
$ tcpdump -i ens1f0 -j adapter_unsynced --time-stamp-precision nano -w studio.pcap
$ st2110 pcap studio.pcap --sdp camera1.sdp --sdp camera1-audio.sdp
studio.pcap: pcap (nanosecond), 108515 frames in 0.499 s: 108497 RTP packets in 2 flows, 18 PTP messages
  clock: PTP time: by the capture's clock, 4 Sync messages arrived a median 5.0 µs after leaving the grandmaster
  flow 1: 192.168.10.21:5004 to 239.10.10.1:5004, ST 2110-20, camera1.sdp stream 0
    107998 packets (payload type 96, SSRC 11110001) at 2160.0 Mb/s, 2 lost
    video: 1080 lines, progressive, 50 frames a second, 25 frames, 4320 packets a frame
    first packet time 746.0 µs (744.7 to 747.3), RTP offset 0.0 ticks (0.0 to 0.0), latency 746.0 µs (744.7 to 747.3)
    CINST peaked at 2, CMAX 5 for 2110TPN; fits 2110TPN, 2110TPNL, 2110TPW
    virtual receiver buffer peaked at 5 of VRXFULL 8, gapped reads from TROFFSET 764.4 µs; packets arrived 17.0 µs or more before their reads
  flow 2: 192.168.10.22:5006 to 239.10.10.2:5006, ST 2110-30, camera1-audio.sdp stream 0
    499 packets (payload type 97, SSRC 22220002) at 9.5 Mb/s
    audio: L24, 48000 Hz, 8 channels, 48 samples a packet (1000.0 µs)
    latency 1150.0 µs (1150.0 to 1150.0), packet interval 1000.0 µs (1000.0 to 1000.0), TS-DF at most 0.0 µs
  PTP domain 127: grandmaster 08-00-11-FF-FE-21-E1-B0
    00-1B-21-FF-FE-8A-2C-10 port 1 at 192.168.1.50: 4 Delay_Req every 125.0 ms
    08-00-11-FF-FE-21-E1-B0 port 1 at 192.168.1.1: 4 Sync every 125.0 ms, 4 Follow_Up every 125.0 ms, 4 Delay_Resp every 125.0 ms, 2 Announce every 250.0 ms
    Sync arrival less departure 5.0 µs (5.0 to 5.0)
  not in the capture: camera1.sdp stream 1, to 239.20.10.1:5004
studio.pcap: flow 1 at 0.244 s: error[packet-loss]: 2 packets of 108000 never arrived (0.002%), in 1 gap (RFC 3550 §5.1)
studio.pcap: 2 flows, 1 error, 0 warnings, 0 notes
```

- `st2110 pcap FILE...` reads pcap and pcapng files as it goes, so a capture of any size will do; `-` reads standard input. It reads Ethernet with VLAN tags, Linux cooked captures and raw IP, over IPv4 or IPv6, and PTP over UDP or Ethernet.
- `--sdp FILE` gives a stream's SDP file, as often as needed. Each flow is matched to a stream by its destination and, where the stream has a source filter, its sender. It is checked against that stream and modelled on the schedule its `TP` and `TROFF` give. A flow without an SDP file is recognised from its packets, with its frame rate, image height or channels.
- For video and ancillary data it measures, frame by frame, the first packet time from each frame's reference time counted from the SMPTE Epoch, the RTP offset and the latency, as RP 2110-25 does. It runs the ST 2110-21 network compatibility model (CINST against each sender type's CMAX) and the virtual receiver buffer (against VRXFULL, with underflows). For audio it measures latency, packet intervals and the timestamped delay factor (TS-DF) of each 200 ms. `--format json` gives the video and audio measurements for each second of the capture as well as overall.
- It follows each PTP domain: grandmasters, ports, message rates, Sync messages without a Follow_Up, Delay_Req messages without a Delay_Resp, and two ports announcing at once. Every message also gets the checks `st2110 ptp` makes, each reported once for its port.
- The timing measurements need the capture's timestamps on PTP time. A capture timestamped by a NIC whose clock ptp4l disciplines, as `tcpdump -j adapter_unsynced` does, counts PTP time; one timestamped by the system clock counts UTC, which it moves 37 s onto PTP time (`--tai-utc` changes that). It works out which from the capture's PTP Sync messages, or else from the RTP timestamps, and says why; `--timescale ptp` or `utc` says so outright. When it cannot tell, it skips what needs PTP time and measures the rest.
- `--quiet` and `--deny-warnings` work as they do for `lint`.
- It exits with 0 when nothing is an error, 1 when something is or a file ends partway through, and 2 when a file cannot be read or is not a capture.

It measures what arrived where the capture was made, so a capture from a switch's mirror port also shows that switch's queuing. It does not reassemble IP fragments, which ST 2110-10 forbids; it reports them. SMPTE ST 2022-7 legs are separate flows, each checked on its own. It measures the first 10,000 flows and follows the first 10,000 PTP ports, and counts the packets and messages of any more.

## Work out ST 2059-1 timing

```console
$ st2110 time --at 2026-09-27T12:00:00.123456789Z --local-offset 3563 --video 59.94 --audio 48000
PTP time    1790510437.123456789
UTC         2026-09-27 12:00:00.123456789 (TAI − UTC 37 s)
Local Time  2026-09-27 13:00:00.123456789 (offset 3563 s)

video 60000/1001 (59.94 fps)
  frame       107323302924 since the SMPTE Epoch
  began       1790510437.115400000, RTP 3061361762 at 90 kHz
  next        1790510437.132083334, RTP 3061363263
  time code   13:00:00;04 (30000/1001 fps drop-frame, from the jam at 2026-09-27 00:00:00 Local Time)

audio 48000 Hz
  RTP         2205388965 for a sample taken now
  AES3 block  447627609280 of 192 samples, began 1790510437.120000000
  next block  1790510437.124000000
```

- `--at` takes PTP time in seconds (or IS-04's `seconds:nanoseconds`) or a UTC time. Without it, `st2110 time` uses the system clock.
- `--video` and `--audio` take each rate to work out, as often as needed. Without either, it shows 50 and 59.94 fps video and 48 kHz audio.
- `--local-offset` is a grandmaster's `currentLocalOffset`: seconds from PTP time to Local Time, such as 3563 for British Summer Time. Local Time is UTC when it is not given.
- `--jam` sets the last daily jam, which is otherwise the last Local Time midnight. Time code keeps the local offset of its jam until the next one, so after a daylight saving change give the jam's offset, a grandmaster's `previousJamLocalOffset`, as `--jam-local-offset`; without it the offset is taken not to have changed since the jam.
- `--non-drop` counts 29.97 time code without dropping frames, and `--tai-utc` changes TAI − UTC from 37 s.
- The arithmetic is exact: PTP time is kept in integer nanoseconds and rates as ratios, so 1000/1001 rates land on the right nanosecond and RTP timestamps step 1501 and 1502 at 59.94 fps.

## Find the streams on a network

```console
$ st2110 discover
CAM 1 audio
  ST 2110-30, L24 48 kHz, 8 channels (51,ST), 1 ms, level A, 9.22 Mb/s, to 239.10.10.2:5006
  NMOS Node Camera 1
CAM 1 video
  ST 2110-20, 1920x1080 progressive, 50 fps, YCbCr-4:2:2 10-bit, BT709 SDR, 2110GPM, 2110TPN, 2.07 Gb/s, to 239.10.10.1:5004 and 239.20.10.1:5004
  NMOS Node Camera 1; SAP from 192.168.10.21
Studio tone
  ST 2110-30, L24 48 kHz, 2 channels (ST), 1 ms, level A, 2.30 Mb/s, to 239.10.1.2:5004
  SAP from 192.168.10.50

3 streams found.
NMOS Senders read from 1 Node peer to peer.
Looked for 10 s for SAP announcements to 239.255.255.255:9875 and 224.2.127.254:9875; NMOS registries and Nodes by multicast DNS; NMOS registries by DNS-SD in studio.example.
```

- `st2110 discover` listens for SAP announcements (RFC 2974) to 239.255.255.255 and 224.2.127.254 on port 9875, as AES67 devices make them and `st2110 send --sap` does. Each carries a stream's SDP file. A deletion takes its stream off the list at once; one not heard for three times the interval between its announcements, or 90 s when heard once, is marked as maybe stopped, and one not heard for an hour goes.
- It browses by multicast DNS for registries' Query APIs (`_nmos-query._tcp`) and Nodes' Node APIs (`_nmos-node._tcp`), and asks the system's DNS servers for Query APIs in its search domains, as IS-04 has controllers do. It shares port 5353 with the system's responder to hear every answer, or asks from a port of its own where it cannot. `--dns-server` and `--domain` choose where to ask by unicast DNS, and `--no-dns` asks nowhere.
- It reads the Senders from the registry a controller would choose: one that asks for no authorization first, then one in use before one for development (`pri` of 100 or more), the lowest `pri` first, going on to the next when one does not answer. `--registry URL` names one instead. Where no registry answers, it reads each Node it found, peer to peer through its Node API, and again whenever the version counters the Node advertises change.
- It fetches each RTP Sender's SDP file from its `manifest_href`, as `st2110 nmos` does, but never through a proxy, and reads the registry or the Nodes again every 15 s. A stream that SAP announces and NMOS lists, going to the same addresses from the same sources, is listed once, with both.
- It looks on every port that is up, or those `--interface` names, for `--duration` seconds, 10 by default. Senders announce by SAP every 30 s or so, so give `--duration 35` to hear every one, or `--watch` to keep looking and print each stream as it comes, changes and goes. `--save DIR` writes each stream's SDP file there, named after the stream, to receive, view or check. `--sap`, `--no-sap`, `--no-nmos`, `--mdns` and `--timeout` change where and how it looks, and `--format json` gives everything it found, SDP files included.
- It exits with 0 when it found a stream, 1 when it found none, and 2 when it could not look, as when another program holds a port alone.

It only looks: it answers no queries and registers nothing. It reads IPv4, as ST 2110 networks are, and cannot read a registry or Node that asks for IS-10 authorization, nor encrypted SAP.

To try it on one machine with no ST 2110 equipment, run `python3 scripts/try-discovery.py`. It serves the test facility's Camera 1 as an NMOS Node, advertises it with the system's multicast DNS responder (`dns-sd` on macOS, `avahi-publish` on Linux), sends a tone announced by SAP, and runs `st2110 discover`, which finds Camera 1's two streams and the tone. CI runs it on macOS.

## Send and receive streams

```console
$ st2110 send video 1080p50 --to 239.10.1.1:5004 --to 239.10.2.1:5004 --interface 192.168.10.21 --interface 192.168.20.21 \
    --clock 08-00-11-FF-FE-21-E1-B0:127 --duration 1 --sdp bars.sdp --pcap bars.pcap
st2110: sent 50 frames of 1920x1080p50 YCbCr-4:2:2 10-bit (216000 packets) on 2 legs into bars.pcap
$ st2110 receive bars.sdp --pcap bars.pcap --png bars.png
bars.sdp: 1920x1080p50 YCbCr-4:2:2 10-bit, from the capture bars.pcap
  the capture's clock is taken as UTC, and moved 37 s onto PTP time
  leg 1 239.10.1.1:5004 from 192.168.10.21: 216000 packets
  leg 2 239.10.2.1:5004 from 192.168.20.21: 216000 packets
  merged: 216000 packets in 1.000 s, 2108.2 Mb/s of RTP, none lost
  legs apart: at most 0.0 µs, leg 2 behind leg 1 by 0.0 µs on average: ST 2022-7 class D
  video: 50 frames, all whole, 4320 packets a frame, 50.000 frames a second
  latency from RTP timestamp: 382.2 to 382.2 µs, mean 382.2 µs
bars.sdp: arrived whole
```

- `st2110 send video [FORMAT]` sends EBU colour bars, with a box that moves along the black strip beneath them, as ST 2110-20 video. FORMAT is 1080p50 unless it names another, such as 2160p59.94 or 1280x720p25; video is progressive. `--sampling`, `--depth`, `--colorimetry`, `--tcs`, `--range` and `--packing` choose the rest. `st2110 send audio` sends a 1 kHz tone at −18 dBFS as ST 2110-30 audio; `--channels`, `--sample-rate`, `--bits`, `--packet-time`, `--tone` and `--level` choose it. A packet holds a whole number of samples, so at 44.1 kHz `--packet-time 1` gives 44 of them, 997.7 µs, which the SDP file writes as `a=ptime:1` and a receiver rounds back to 44.
- Each frame starts at its alignment point counted from the SMPTE Epoch, with its RTP timestamp, as ST 2059-1 gives them. Its packets go at the ST 2110-21 read times of the sender type that `--sender-type` declares, from the default read offset and a little ahead of each read, so that the virtual receiver buffer neither runs dry nor overflows. Unless it says `narrow`, `narrow-linear` or `wide`, that is `wide` below 900 000 packets a second and `narrow-linear` from there, where ST 2110-21 defines no wide sender. Each audio packet goes as its last sample falls due.
- `--to` gives the destination, a multicast group or a unicast address; give it twice for the two legs of an ST 2022-7 pair, which carry the same packets. `--interface` gives the address to send from, once for every leg or once for each; otherwise the routing table picks. `--ttl` sets the multicast time to live and `--dscp` the DSCP, AF41 by default, as AES67 marks media.
- It writes the SDP file before it sends, to standard output or to `--sdp`, with `a=group:DUP` for a pair and a source filter for each multicast leg. `st2110 lint` finds no errors in it.
- `--sap` announces the stream by SAP as well, as AES67 devices do, for `st2110 discover` and ST 2110 Viewer to find: to 239.255.255.255:9875, or `--sap=ADDRESS:PORT`, as it starts and every 30 s after, withdrawing the announcement when `--duration` ends. A sender stopped with Ctrl-C cannot withdraw it, so listeners mark the stream as maybe stopped 90 s later.
- It times packets by the system clock, taking TAI to be 37 s ahead of it (`--tai-utc` changes that). On a machine whose clock `phc2sys` keeps to PTP, name the grandmaster with `--clock <grandmaster>:<domain>` or `--clock traceable`, and its streams line up with every other sender's. Otherwise the SDP file names this machine's MAC address as `localmac`, which only Linux can find; elsewhere give `--clock`.
- `--duration` sends for that many seconds, and without it the sender runs until it is stopped. With `--pcap FILE` it writes the packets into a capture instead, as fast as it can make them, each at the time it would have gone out, on UTC as a capture made with the system clock is. `st2110 pcap` measures such a capture, and `st2110 receive --pcap` reads it.
- `st2110 receive SDP` joins each leg's group, from the SDP file's source only when it has a source filter, or takes a unicast leg on its address; `--interface` gives the interface. It merges the legs as ST 2022-7 does, passing on the first copy of each packet, puts the packets back in sequence order and the frames or samples back together. When a packet is missing it waits for it, for a copy on a leg that runs behind or one out of order, for up to `--max-skew` milliseconds: 50 by default, as far as ST 2022-7 class B receivers allow the legs to differ, and up to 1000.
- It reports what each leg lost and what was lost after merging, how far apart the legs' copies arrived and the tightest ST 2022-7 receiver class that allows it, which frames arrived whole, the frame rate, and the latency from each frame's RTP timestamp, which is the sender's and the network's delay when both clocks follow PTP. It follows a sender that restarts, with a new synchronisation source or with sequence numbers or timestamps that start again elsewhere, and leaves out stray packets that fit neither the stream nor a restart. It follows a sender that pauses, too, and counts the frames or audio it never sent. A capture played in a loop restarts the stream each time round when the loop is longer than the packets the receiver remembers, half a second's or twice `--max-skew`; a shorter loop's packets are taken for copies of the ones before. A frame cut off by the start or end of receiving is not a fault.
- `--duration` receives for that many seconds, 5 by default. `--pcap FILE` reads a capture instead of the network, and works out whether its clock is PTP time or UTC. `--png FILE` saves the last frame that arrived whole, and `--wav FILE` the audio, with silence where packets were lost or never sent, up to 10 s a gap. `--format json` gives everything the report holds.
- `receive` exits with 0 when the stream arrived whole, 1 when something was lost or incomplete, and 2 when it cannot receive. `send` exits with 0 when it has sent, and 2 when it cannot.

Both use ordinary sockets, and the sender sends one packet at a time from one thread, waiting for each packet's time. On a quiet machine that keeps a wide sender's pace at HD rates; it does not keep a narrow sender's, and UHD rates need the kernel bypass that Intel MTL brings. The receiver times each datagram by the kernel's receive timestamp on Linux and macOS, and by when it reads it elsewhere. It needs a large socket buffer for video: raise `net.core.rmem_max` on Linux (`sysctl -w net.core.rmem_max=67108864`) or `kern.ipc.maxsockbuf` on macOS; `receive` says when the system allows less than 4 MiB.

## Watch a stream

`st2110 view` shows an ST 2110-20 video stream in a window as it arrives. A Mac with no network at all can play a capture, 600 MB of it here:

```console
$ st2110 send video 720p50 --to 239.10.1.1:5004 --clock traceable --duration 5 --sdp bars.sdp --pcap bars.pcap
st2110: sent 250 frames of 1280x720p50 YCbCr-4:2:2 10-bit (540000 packets) on 1 leg into bars.pcap
$ st2110 view bars.sdp --pcap bars.pcap
```

To watch vizz on the same Mac, run it from its checkout, sending to the Mac itself to keep the stream off the network, and view the SDP file it writes:

```console
$ cargo run --release -- --st2110 127.0.0.1:5004 --st2110-rate 50 --width 1280 --height 720 --st2110-sdp vizz.sdp
$ st2110 view vizz.sdp
```

- It receives the stream as `st2110 receive` does, from its SDP file, with the same `--interface`, `--max-skew` and `--tai-utc`, and shows each frame as it arrives. Where a frame's packets are missing, the frames before it show through, as a receiver hides a loss, and where none has filled the gap yet, the all-zero codes show, which are dark green in YCbCr.
- The title names the stream and counts the frames, the incomplete ones and the packets missing from them, and says when nothing has arrived for a second or more.
- `--pcap FILE` plays a capture instead of receiving, at the pace it was captured, and the window keeps the last frame when it ends.
- Escape or Q closes the window. The report `st2110 receive` gives follows, with its exit codes.
- Colours are worked out with the stream's luma coefficients and range, and shown as the screen's own: HDR (PQ or HLG) is not tone-mapped, and BT.2020 colours are not converted to the screen's.
- A frame is unpacked in bands of rows across the machine's cores, about 9 ms of work for 1080p on one 2.8 GHz Xeon core, and a screen that falls behind skips frames rather than delaying them. The sockets are the limit, as for `receive`, and need the same large buffer.
- The window is [minifb](https://github.com/emoon/rust_minifb)'s. Building with `--no-default-features` leaves out `view`, and minifb with it.

## ST 2110 Viewer

ST 2110 Viewer is an app for the Mac that finds the ST 2110 streams on the network and plays an ST 2110-20 video stream as it arrives, from the network or from a capture, with what has arrived beside the picture. It finds streams as `st2110 discover` does, receives as `st2110 view` does and counts what `st2110 receive` counts, and it keeps going: pick another stream, change the port, stop and start.

- **Find a stream.** The list on the left, which Find streams shows and hides, has the streams on the network as `st2110 discover` finds them, kept current: what each carries, where it goes and how it was found. Click one to play it. Those it cannot play, such as ancillary data, are dimmed with the reason, and so are NMOS Senders that are not sending and announcements that have stopped coming. Refresh asks again at once. Save SDP file, beside the picture, keeps the SDP file of a stream found this way.
- **Open a stream.** Open its SDP file with the button or ⌘O, pick one from Recent, or drop it on the window. Receiving starts at once.
- **Say where it comes from.** Network receives on the port picked beside it, which the app remembers; Any port lets the system route the stream's addresses. Capture plays a pcap or pcapng file at the pace it was captured, with the open SDP file saying what to look for. Drop an SDP file and a capture together to play them.
- **Watch it.** The picture fills the window at the stream's shape. Double-click it for full screen, and Escape to leave. When frames stop coming, the picture keeps the last one and says how long it has been.
- **Read what arrived.** Beside the picture: frames and the incomplete ones, the frame rate, packets and what was lost or came too late, each leg of an ST 2022-7 pair, how far apart the legs arrived and the tightest receiver class that allows it, the latency from RTP timestamps, and for audio the loudest sample on each channel. Problems and notes are the ones `st2110 receive` reports, as they come. The line along the bottom says what receiving is doing.

The first time it looks for streams or receives one, macOS 15 asks whether ST 2110 Viewer may find and connect to devices on the local network. Allow it, or nothing is found and nothing arrives; System Settings, Privacy & Security, Local Network changes the answer later.

### Get it

Each [release](https://github.com/legofsalmon/st2110/releases) has the app for macOS 11 or later, on Apple silicon and Intel, as `st2110-viewer-<version>.app.zip`. Unzip it and move ST 2110 Viewer to Applications. A release signed with a Developer ID and notarized opens with a double-click, and its notes say so; one that is not needs Open Anyway in System Settings, Privacy & Security, the first time.

To build it yourself on a Mac:

```console
$ scripts/make-viewer-app.sh              # for this Mac's processor
$ scripts/make-viewer-app.sh --universal  # for Apple silicon and Intel both
```

That leaves `dist/ST 2110 Viewer.app` and a zip of it, signed with the Developer ID in `APPLE_SIGNING_IDENTITY` when there is one, and ad hoc otherwise. On Linux, `cargo run --release -p st2110-viewer` runs the app itself, which takes an SDP file and `--pcap FILE` on its command line too.

### Releases

The **Release** workflow cuts one: Actions, Release, Run workflow, with the tag to release, such as `v0.1.0`, which it makes at the branch given. It builds the app for both processors, plays a capture in it and checks its version against the tag, then attaches the zip to the release. With these repository secrets, the same ones vizz uses, it signs the app with the Developer ID and has Apple notarize it first:

| Secret | What it is |
|---|---|
| `APPLE_CERT_P12` | The Developer ID Application certificate and its key, exported as a .p12 file, in base64 |
| `APPLE_CERT_PASSWORD` | The .p12 file's password |
| `APPLE_SIGNING_IDENTITY` | The certificate's name, such as `Developer ID Application: Name (TEAMID)` |
| `APPLE_API_KEY_P8` | An App Store Connect API key for notarizing, the .p8 file, in base64 |
| `APPLE_API_KEY_ID` | That key's ID |
| `APPLE_API_ISSUER_ID` | Its issuer ID |

`--exit-after-frames N` closes the app once N frames have arrived, and exits with 0 when they arrived whole, and `--screenshot FILE` saves a picture of the window first. CI runs the app that way on a Mac for every change, and keeps the app and the picture as the run's artifacts.

The app carries the licences of the crates compiled into it, in [crates/viewer/THIRD_PARTY_NOTICES.md](crates/viewer/THIRD_PARTY_NOTICES.md). After changing its dependencies, write that again with `python3 scripts/third-party-notices.py`; CI fails when it is out of date.

## What it checks

The full catalogue, with the clause behind each rule, is in [docs/rules.md](docs/rules.md).

Severities follow the standards' own words. An **error** breaks a "shall" (or an RFC or NMOS "MUST"), so equipment may reject or misread what it describes. A **warning** breaks a "should" or is a known interoperability hazard. An **info** note needs no action on its own.

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

It reads SDP only, so it cannot confirm that a sender does what its SDP says; `st2110 pcap` checks that in a capture. It also leaves out the interlaced `TROFF` defaults, which ST 2110-21:2022 Table 1 misprints for 525 and 625 lines, and the ST 2110-31 levels at 44.1 and 96 kHz.

### NMOS registries

| Area | Checks |
|---|---|
| Resources | The attributes each IS-04 schema requires and their types, `id` and `version` syntax, duplicate ids, parents and references that are not registered, interface and clock names a Node does not have |
| PTP | Unlocked clocks, locked clocks that follow different grandmasters (unless both are traceable to TAI), and a Sender whose `a=ts-refclk` disagrees with its Source's clock |
| Connections | Subscriptions that contradict `active`, active Receivers taking from an inactive Sender, and Receivers whose BCP-004-01 `caps` reject what their Sender sends |
| SDP files | Each Sender's `manifest_href` and whether it answers, every SDP rule above, one interface binding per stream, multicast or unicast addresses to match the transport, the file against the Flow, Source and Sender attributes that the NMOS capabilities register maps to SDP, and against the one its Connection API serves at `/transportfile` |

It reads resources registered at any IS-04 version from v1.0 to v1.3, and reports an attribute as missing only when every version that could have registered the resource requires it.

### PTP messages

| Area | Checks |
|---|---|
| ST 2059-2 attributes | `domainNumber`, and the Announce, Sync and Delay_Req rates the profile allows |
| Timestamps | Nanoseconds below a second |
| Grandmaster | `clockAccuracy` not Unknown, a defined `timeSource`, `clockClass` locked rather than in holdover or free-running and agreeing with `ptpTimescale`, a valid `currentUtcOffset` of at least 37 s, and a note for an arbitrary timescale |
| Synchronization metadata | Carried in a Management COMMAND to all ports, a `lengthField` of 48, the frame rate, locking status and reserved bits, jams on a whole 10 minutes of Local Time, jumps with both a size and a time, and time-zone offsets in range |
| TLVs | Even lengths that end within the message, and PATH_TRACE lengths of whole clock identities |

It follows ST 2059-1:2021 and ST 2059-2:2021, with IEEE 1588-2008 and -2019.

### Captures

| Area | Checks |
|---|---|
| RTP | Lost packets, with 32-bit sequence numbers where ST 2110-20 and -40 extend them; packets out of order or repeated; SSRC changes; the SDP file's payload type |
| ST 2110-10 | IP fragments, and datagrams over 1460 octets or the `MAXUDP` signalled |
| Video and ancillary data | Marker bits on the last packet of each frame or field, timestamps on the frame grid, packets that arrive before the time their timestamp names, and latency over JT-NM's 1 ms (35 ms for ancillary data) as a note |
| ST 2110-21 | CINST over CMAX for the sender type in `TP`, or the `CMAX` signalled, and the virtual receiver buffer's overflows and underflows |
| ST 2110-22 | The same number of packets in every frame |
| ST 2110-30, -31 | Packets holding the samples `ptime` gives and the channels `a=rtpmap` gives, and TS-DF within a packet time |
| PTP | One grandmaster through the capture, one port announcing at a time, Announce and Sync rates to match `logMessageInterval`, and a Follow_Up for every two-step Sync and a Delay_Resp for every Delay_Req |

It follows RP 2110-25:2023 for what it measures, with ST 2110-21:2022 for the models and EBU Tech 3337 for TS-DF.

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

For PTP, decode and check a message, or do the ST 2059-1 arithmetic directly:

```rust
use st2110_ptp::epoch::{self, Signal};
use st2110_ptp::PtpTime;
use st2110_sdp::Rational;

let message = st2110_ptp::decode(&udp_payload)?;
for line in st2110_ptp::describe::summary(&message) {
    println!("{line}");
}
for f in st2110_ptp::check(&message) {
    println!("{} {}: {}", f.severity, f.rule, f.message);
}

let now = PtpTime::parse("1790510437.123456789").unwrap();
let rate = Rational::new(60000, 1001).unwrap();
let (frame, at) = epoch::next_alignment(now, Signal::Video(rate)).unwrap();
println!("frame {frame} starts at {at}, RTP {:?}", epoch::frame_rtp_timestamp(frame, rate, 90_000));
```

`st2110_ptp::timing::at` gathers everything `st2110 time` prints, and `timecode::timecode_at` gives the time code for any rate and daily jam.

For a capture, give the SDP files and read the file as it goes:

```rust
use st2110_pcap::{Options, SdpFile};

let options = Options { sdp: vec![SdpFile { name: "camera1.sdp".into(), text: sdp }], ..Options::default() };
let report = st2110_pcap::analyse(std::io::BufReader::new(std::fs::File::open("studio.pcap")?), &options)?;
for flow in &report.flows {
    let fpt = flow.video.as_ref().and_then(|v| v.fpt);
    println!("{} {}: {} packets, {} lost, first packet time {:?}", flow.destination, flow.essence.standard(), flow.packets, flow.lost, fpt);
}
for f in &report.findings {
    println!("{:?} {} {}: {}", f.flow, f.severity, f.rule, f.message);
}
```

`st2110_pcap::Analyser` takes one frame at a time instead, for captures that arrive some other way.

To send a stream, describe it, write its SDP file and send it (the `net` feature). This sends ten seconds of bars from 192.168.10.21:

```rust
use st2110_media::describe::{Clock, Description, Leg, Media};
use st2110_media::format::VideoFormat;
use st2110_media::net::{self, Transmitter};
use st2110_media::send::Sender;

let stream = Description {
    name: "Bars".into(),
    media: Media::Video(VideoFormat::from_name("1080p50")?),
    payload_type: 96,
    legs: vec![Leg { destination: "239.10.1.1:5004".parse()?, source: Some("192.168.10.21".parse()?) }],
    clock: Some(Clock::Traceable),
    ttl: 32,
};
std::fs::write("bars.sdp", stream.sdp(1))?;
let mut transmitter = Transmitter::new(&stream.legs, &["192.168.10.21".parse().ok()], 32, 34, 37)?;
let start = net::tai_now(37) + 100_000_000;
Sender::new(&stream, 1000, -18.0, 0x1234_5678, 0)?.run(&mut transmitter, start, start + 10_000_000_000)?;
```

To receive one, read its SDP file and listen on each leg. This receives two seconds of it, on another machine or in another process while it sends:

```rust
use st2110_media::describe::Description;
use st2110_media::net;
use st2110_media::receive::Session;

let (stream, _notes) = Description::parse(&std::fs::read_to_string("bars.sdp")?)?;
let mut session = Session::new(&stream)?;
let sockets = stream.legs.iter().map(|leg| Ok(net::listen(leg, None)?.0)).collect::<std::io::Result<Vec<_>>>()?;
net::receive(&mut session, sockets, net::tai_now(37) + 2_000_000_000, 37, &mut ())?;
println!("{:?}", session.report().problems);
```

`Sender` sends to any `send::Output`, and `receive::Session` takes datagrams from anywhere, so without the `net` feature the crate works on captures and in tests. `video::Packetiser` and `video::Depacketiser`, `audio::AudioPacketiser` and `audio::AudioDepacketiser`, `merge::Merger` and `merge::Playout` work on their own too.

To send pictures of your own, such as a renderer's, give `send::VideoSender` a `send::FrameSource`. It asks for each frame just before the frame's packets are due, and leaves out any frame whose time passed while it was behind, without asking for it. `pixels::Converter::pack_frame` packs 8-bit pictures into pixel groups, with their octets in RGB or BGRA order and their rows padded as GPUs read them back: a 1080-line frame takes under 10 ms on one 2.1 GHz Xeon core.

To make connections, read the registry without the SDP files, which are fetched as they are needed, and give the controller the routes (the `client` feature):

```rust
use st2110_connect::client::{ConnectionClient, Options};
use st2110_connect::controller::{Route, Settings, Take, connect};
use st2110_nmos::client::{self, QueryClient};

let registry = QueryClient::connect("http://registry.example:8080", &client::Options { fetch_sdp: false, ..Default::default() })?;
let routes = [
    Route { receiver: "MON 1 video".into(), take: Take::Sender("CAM 2 video".into()) },
    Route { receiver: "MON 1 audio".into(), take: Take::Sender("CAM 2 audio".into()) },
];
let client = ConnectionClient::new(&Options::default());
let outcome = connect(&registry.snapshot()?, &routes, &client, Some(&registry), &Settings::default())?;
for c in &outcome.connections {
    println!("{} ← {}: {} {:?}", c.receiver.describe(), c.describe_take(), c.state.describe(), c.problems);
}
```

Without the `client` feature, `st2110_connect::Plan::connect` plans one connection from an SDP file and a Receiver's constraints, and `Plan::verify` checks what its `/active` endpoint shows after; `st2110_nmos::routing` finds Senders and Receivers by name and builds the crosspoint matrix.

## Use it from JavaScript

```console
$ rustup target add wasm32-unknown-unknown
$ cargo build -p st2110-wasm --target wasm32-unknown-unknown --release
$ wasm-bindgen --target web --out-dir crates/wasm/pkg target/wasm32-unknown-unknown/release/st2110_wasm.wasm
```

`wasm-pack build crates/wasm --target web` does the same in one step. The package exports `lint(sdp)`, `checkRegistry(snapshot)`, `routingMatrix(snapshot)`, `planConnection(options)`, `verifyConnection(plan, active)`, `decodePtp(bytes)`, `timing(options)`, `analyseCapture(bytes, options)` and `rules()`, and ships TypeScript types for what they return:

```js
import init, { lint, checkRegistry, routingMatrix, planConnection, verifyConnection, decodePtp, timing, analyseCapture }
  from "./pkg/st2110_wasm.js";

await init();
const report = lint(sdpText);
for (const d of report.diagnostics) console.log(d.line, d.severity, d.rule, d.message);

const registry = checkRegistry(snapshot);
for (const f of registry.findings) console.log(f.resource?.label, f.severity, f.rule, f.message);

const plan = planConnection({ sdp: senderSdp, constraints: receiverConstraints, senderId });
// PATCH plan.request to the Receiver's /staged endpoint; once it is done:
console.log(verifyConnection(plan, await (await fetch(activeUrl)).json()));

const ptp = decodePtp(udpPayload);
for (const f of ptp.findings) console.log(f.severity, f.rule, f.message);

const now = timing({ video: ["60000/1001"], audio: [48000], localOffset: 3563 });
console.log(now.video[0].next_frame, now.video[0].next_rtp, now.video[0].timecode?.address);

const capture = analyseCapture(new Uint8Array(await file.arrayBuffer()), { sdp: [{ name: "camera1.sdp", text: sdpText }] });
for (const f of capture.findings) console.log(f.flow, f.at, f.severity, f.rule, f.message);
```

`checkRegistry` and `routingMatrix` take a snapshot as an object or as JSON text, in the format `st2110 nmos --save` writes. The page fetches the resources and SDP files itself. `planConnection` takes the Sender's SDP file and the Receiver's `/constraints` as the page fetched them, with `senderId`, and `at` or `in` as `st2110 connect` takes them; without `sdp` it plans a disconnection. It returns the request to send and the problems the constraints would raise, and `verifyConnection` lists where the Receiver's `/active` endpoint differs from the plan. `decodePtp` takes a `Uint8Array` and throws when it is not a PTP message. `timing` takes the options `st2110 time` does, with `at` as PTP time or a UTC time such as `new Date().toISOString()` gives; without `at` it uses the page's clock. `analyseCapture` takes a capture's bytes, with the options `st2110 pcap` takes as `sdp`, `timescale` and `taiUtc`; it analyses from memory, so a page can take a capture as large as it can hold.

## Development

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
```

To add an SDP rule, add it to the catalogue in `crates/sdp/src/rules.rs`, raise it from the check in `crates/sdp/src/lint/`, and add a case to `crates/sdp/tests/rules.rs`. A registry rule goes in `crates/nmos/src/rules.rs`, is raised from `crates/nmos/src/check.rs`, and needs a case in `crates/nmos/tests/checks.rs`. A PTP rule goes in `crates/ptp/src/rules.rs`, is raised from `crates/ptp/src/check.rs`, and needs a case in `crates/ptp/tests/decode.rs`. A capture rule goes in `crates/pcap/src/rules.rs`, is raised from the flow, video, audio or PTP modules beside it, and needs a capture that raises it in `crates/pcap/tests/captures.rs`. A test fails for any rule without one. Then regenerate the docs, which another test compares:

```console
$ cargo run -q -p st2110-cli -- rules --format markdown > docs/rules.md
```

## Roadmap

These are the first six steps of the plan in the September 2026 standards review: the SDP model and linter, the read-only NMOS client, PTP decoders with ST 2059-1 arithmetic, the RP 2110-25 capture analyser, the IS-05 controller, and senders and receivers on ordinary sockets, and stream discovery after them. Next, the same senders and receivers on Intel MTL, behind the same interface, for UHD rates and a narrow sender's pace.

None of it has yet met another maker's equipment. [docs/bench.md](docs/bench.md) is the plan for the first bench test, with two Blackmagic converters, a grandmaster and a Mac.

## Licence

st2110 is source available under the [Elastic License 2.0](LICENSE), with
LeTissier Creative Studios Ltd as the licensor. You can read, build and
modify it, but you may not offer it to others as a hosted service. The
third-party crates it depends on keep their own licences.
