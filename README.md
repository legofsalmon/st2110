# st2110

Tools for SMPTE ST 2110 media over IP, written in Rust. There are seven so far:

- an SDP linter, which reads the session description a sender publishes, describes
  each stream in it and checks it against ST 2110 and the documents it builds on;
- an NMOS registry checker, which reads a facility's IS-04 registry and checks its
  resources, PTP clocks and connections, and every Sender's SDP file;
- an IS-05 connection controller, which connects Receivers to Senders one at a time
  or as a salvo that switches at one PTP time, checking each against the Receiver's
  constraints and capabilities first and on the Receiver and in the registry after,
  with a router panel that does the same from a browser;
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
  video or tone as ST 2110-30 or ST 2110-31 audio, paced by ST 2110-21 and lined up with the SMPTE
  Epoch, on one leg or an ST 2022-7 pair, and receive a stream from its SDP file,
  merging the legs, putting the packets back in order and the frames and samples back
  together, and reporting what arrived, or showing the video in a window as it arrives,
  from the command line or in ST 2110 Viewer, an app for the Mac that lists the streams
  discovery finds. Either can run as an NMOS Node, registered with the facility's
  registry, for a controller to route.

Every finding cites the clause behind it.

| Crate | What it is |
|---|---|
| [`crates/sdp`](crates/sdp) (`st2110-sdp`) | RFC 8866 parser, ST 2110 stream model and the linter's 105 rules. No dependencies; `serde` is an optional feature. |
| [`crates/nmos`](crates/nmos) (`st2110-nmos`) | IS-04 resource model, BCP-004-01 and BCP-004-02 capability matching, BCP-002-01 natural groups, the registry checker's 36 rules (with what IS-11, IS-08, IS-09 and IS-12 APIs report), the IS-12 and MS-05-02 control model with the BCP-008 monitors, and the crosspoint matrix of which Senders each Receiver can take. The Query API client is the optional `client` feature. |
| [`crates/connect`](crates/connect) (`st2110-connect`) | IS-05 connection planning: an SDP file's streams as a Receiver's legs, its constraints, the request that connects it and the check of what it shows after. The Connection API client, the controller that makes salvos and rolls them back, IS-11 Sender constraints and IS-08 channel maps are the optional `client` feature. |
| [`crates/ptp`](crates/ptp) (`st2110-ptp`) | IEEE 1588 message decoder, the ST 2059-2 profile's 20 rules, and ST 2059-1 arithmetic: alignment points, RTP timestamps, and daily-jam time code with colour framing and the ST 309 date. `serde` is an optional feature. |
| [`crates/pcap`](crates/pcap) (`st2110-pcap`) | pcap and pcapng reader, RP 2110-25 measurements, the ST 2110-21 network compatibility and virtual receiver models, and the analyser's 59 rules, with ST 2022-7 pairs measured merged. `serde` is an optional feature. |
| [`crates/media`](crates/media) (`st2110-media`) | ST 2110-20 and -30 packetisers and depacketisers, ST 2110-21 pacing, ST 2022-7 merging and reordering, colour bars and tone, the SDP files senders write, and PNG, WAV and pcap writers. The sockets are the optional `net` feature, and `serde` is another. |
| [`crates/discover`](crates/discover) (`st2110-discover`) | Stream discovery: SAP (RFC 2974) listening and announcing, a DNS-SD browser over multicast and unicast DNS for NMOS registries and Nodes, and the reader that lists their Senders' streams with those SAP announces, each once. |
| [`crates/cli`](crates/cli) (`st2110`) | The command line: `st2110 lint`, `st2110 nmos`, `st2110 connect`, `st2110 router`, `st2110 ptp`, `st2110 pcap`, `st2110 time`, `st2110 discover`, `st2110 send`, `st2110 receive` and `st2110 view`. The window `view` opens is the default `view` feature. |
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
nodes:
  "Camera 1" (a0de0001)
    eth0 c8-00-84-10-00-01 → switch a4-6c-2a-00-0a-00 port Ethernet1/1
    eth1 c8-00-84-10-00-02 → switch a4-6c-2a-00-0b-00 port Ethernet1/1
  "Monitor 1" (a0de0002)
    eth0 c8-00-84-10-01-01 → switch a4-6c-2a-00-0a-00 port Ethernet1/2
    eth1 c8-00-84-10-01-02 → switch a4-6c-2a-00-0b-00 port Ethernet1/2
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
  - Where the registry returned older resources too, it reads each collection again without them, to learn which resources are at the version it reads through.
  - It reads each Sender's and Receiver's IS-05 `/active` parameters from its Device's Connection API, to compare them with the registry's `subscription`.
  - Where a Device advertises an IS-12 control endpoint (`urn:x-nmos:control:ncp/v1.0`), it reads the Device model's root block over the WebSocket, finds each status monitor by class, and reads it with `Get`, with its packet or transmission error counters. Each Sender and Receiver a monitor watches (BCP-008-01, BCP-008-02) gets a line under it: `monitor: healthy`, or `monitor: unhealthy: no packets arrive` with any counter that is not 0, in amber when partly healthy and red when unhealthy.
  - Where a Device advertises an IS-11 Stream Compatibility Management API, it reads each Sender's and Receiver's `status`, and each Sender's active and supported constraints; the state is shown after each one, such as `IS-11 constrained to 1 constraint set`. Where a Device advertises an IS-08 Channel Mapping API, it reads `/io` and `/map/active`, and lists the map under `channel maps:` with channels counted from 1, as `Speakers (out1): 1 ← in1:2, 2 silent`.
- Each Node is listed with its interfaces: the LLDP port ID it sends and, where it says (TR-1001-1), the switch and port it is plugged into.
- `--system=URL` also reads an IS-09 System API's `/global`, or `--system` alone finds one by DNS-SD (`_nmos-system._tcp`). It shows the PTP domain, announce timeout and heartbeat interval every Node is to use, and checks each Sender's `a=ts-refclk` domain against it.
  - It goes through the proxy in `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` unless `NO_PROXY` names the host, and checks HTTPS certificates against the system's trust store.
- `--save FILE` keeps what it read as a JSON snapshot. `st2110 nmos FILE` checks a snapshot again without the network, and `-` reads one from standard input.
- `--no-sdp` skips the SDP files, and `--timeout` sets the seconds allowed for each response (5 by default).
- `--format json`, `--quiet` and `--deny-warnings` work as they do for `lint`.
- It exits with 0 when nothing is an error, 1 when something is, and 2 when the registry or file cannot be read.

It only reads; `st2110 connect` makes connections. Give it a Node's address, or its Node API URL such as `http://camera.example/x-nmos/node/`, to check that Node alone where there is no registry. Where the registry asks for IS-10 access tokens, see [IS-10 access tokens](#is-10-access-tokens).

### Finding the registry

Given no URL, `st2110 nmos`, `st2110 connect` and `st2110 router` find the registry by DNS-SD, as IS-04 has a controller do, and say on standard error which one they chose and how it was found:

```console
$ st2110 nmos --quiet
Registry: http://192.168.10.5:80 (Registry, found by DNS in studio.example)
```

- They ask the system's DNS servers for `_nmos-query._tcp` in its search domains first (`--dns-server` and `--domain` to choose), and only when that finds none do they ask by multicast DNS, for up to three seconds (`--mdns` to ask a responder's own address instead).
- Of the registries found, they take the one IS-04's procedure prefers: those found by unicast DNS, then one that asks for no authorization unless a token can be given, then one in use before one for development, the lowest `pri` first, going on to the next when one does not answer.
- `st2110 router --demo` answers DNS-SD questions on its own address and port over UDP, for its registry's Query and Registration APIs and, with `--demo-auth`, its Authorization Server, in any domain: `st2110 nmos --dns-server 127.0.0.1:8110 --domain demo.test` finds it with no network.

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
- `--group` takes the rest of each Receiver's BCP-002-01 natural group with it, together: `--receiver "MON 3 video" --sender "CAM 2 video" --group` takes the monitor's audio from the camera's audio too. Each other Receiver of the group takes the Sender of its format with the same role in the Sender's group, or else the next of its format in role order, when it can; with `--disconnect` the group is disconnected. A Receiver left as it is, because the Sender is in no group or the group has nothing it can take, is named on standard error with why.
- Each connection follows IS-05 v1.2 as a controller should:
  - it reads the Receiver's `/active` endpoint, its `/constraints` and the Sender's SDP file, fetched afresh from `manifest_href` or else its `/transportfile`;
  - it stages the SDP file with every leg's `transport_params` spelled out (group, source, port and `rtp_enabled`), `master_enable` and `sender_id`. A two-leg ST 2022-7 Receiver given a one-leg stream has leg 2 turned off; a one-leg Receiver given a pair joins path 1;
  - it sends nothing the Receiver's constraints or capabilities would reject, unless `--force` is given. `--dry-run` shows what it would send.
- One connection takes effect at once. Several are scheduled for one PTP time `--lead` seconds ahead (2 by default), so that every Receiver switches together. `--at` sets the time (`now`, a PTP time or a UTC time), and `--in` a delay each Device counts from when it has the request. `--align RATE`, such as `--align 50`, moves a PTP time on to the next frame boundary at that rate, so that the switch falls between frames; it is off unless given, since a salvo may mix rates.
- Receivers that share a Connection API get one `/bulk/receivers` request, or one `PATCH` each when the API has no bulk interface. A salvo's requests have half the lead to be answered, so that when a Connection API refuses its part, fails or does not answer, the rest can be cancelled before they are due. A Receiver that switched all the same is put back as its `/active` endpoint showed it, and one that another controller has changed since is left alone.
- After, it waits for each connection to come due, checks the Receiver's `/active` endpoint shows it, and checks the registry for the Receiver's new subscription and version, which IS-05 requires the Node to update; a registry that lags is a warning. `--wait` sets how long each check may take (5 s), and a connection due later than that is reported as scheduled. `--cancel` cancels an activation scheduled on a Receiver.
- A Receiver taken to an `rtp.ucast` Sender needs the Sender pointed at it first. It points the Sender at the Receiver's interface addresses (from its `/active` `interface_ip`, else its constraints), with `receiver_id` naming the Receiver and the Receiver's port, checks the Sender's `/active` endpoint shows it, and connects the Receiver to the SDP file the Sender serves then. When the Receiver's part fails, the Sender is put back as it was.
- `--sender` without `--receiver` changes the Sender itself, as IS-05 v1.2 has a controller do: `--disable` turns it off and `--enable` on (`master_enable`), and `--destination` (once for each leg, `GROUP[:PORT]` or `ADDRESS[:PORT]`) changes where it sends, in the same request, with `rtp_enabled` on each leg given one and off on a leg past the last; `--receiver-id` names the Receiver a unicast Sender sends to, and is otherwise `null`. A multicast Sender is refused a unicast address and the other way round, as its constraints are checked, unless `--force`. It takes effect at once, unless `--at` or `--in`, and is checked on the Sender's `/active` endpoint and on its IS-04 `subscription.active` in the registry.

```console
$ st2110 connect http://127.0.0.1:8110 --sender "CAM 1 video" --destination 239.10.1.9:5004 --destination 239.20.1.9:5004
sender "CAM 1 video" (5e0d0001) on: done at 2026-10-20 12:00:02.113542817 UTC
  leg 1: to 239.10.1.9:5004
  leg 2: to 239.20.1.9:5004
$ st2110 connect http://127.0.0.1:8110 --sender "CAM 1 audio" --disable
sender "CAM 1 audio" (5e0d0002) off: done at 2026-10-20 12:00:04.832702143 UTC
```

- An IS-07 event Receiver (`websocket` or `mqtt`) taken to a registered Sender is told where the Sender's events are, from the Sender's `/active`: its `connection_uri` over WebSocket, or its broker and `broker_topic` over MQTT, with the other parameters the Receiver's constraints list. It is sent no SDP file, and refused one. Its `caps.event_types` are checked against the Flow's `event_type`, `*` wildcards and all.
- `--sender` with `--constrain-for RECEIVER` (once for each Receiver) holds the Sender to what those Receivers can all take, through its Device's IS-11 Stream Compatibility Management API. It reads the Sender's `/constraints/supported`, combines the Receivers' enabled BCP-004-01 constraint sets with each other and with the Sender's own BCP-004-02 capabilities, leaves out the constraints the Sender cannot be held to (and says which), `PUT`s the sets to `/constraints/active` and shows the Sender's IS-11 state after. `--unconstrain` takes them away. A Device may refuse while the Sender is sending; turn it off first.
- `--device` with `--map OUT:CH=IN:CH` (once for each channel, counted from 1, each Output and Input named by its id or name; `OUT:CH=-` for silence) changes a Device's IS-08 audio channel map. The routes are checked against the Device's `/io` first: the channels exist, and the Output can take the Input (`routable_inputs`). It takes effect at once and is checked on `/map/active`, or is left scheduled with its activation id when `--at` or `--in` says when. A Device refuses a map while another activation waits on the same Outputs; `--device` with `--cancel` cancels those.

```console
$ st2110 connect http://127.0.0.1:8110 --sender "CAM 1 video" --constrain-for "MON 1 video" --constrain-for "MON 2 video"
sender "CAM 1 video" (5e0d0001) held to 1 constraint set: done, now constrained
  set 1: frame_width 1920, frame_height 1080, grain_rate 50
$ st2110 connect http://127.0.0.1:8110 --device "Monitor 1" --map Speakers:1=mic:2 --map Speakers:2=mic:1
device "Monitor 1" (de710002) map: done
  out1: 1 ← in1:2, 2 ← in1:1
```

- TARGET may also be a snapshot saved with `st2110 nmos --save`, when the registry is out of reach; the registry check is then skipped.
- It exits with 0 when every connection was made, scheduled or planned, 1 when one was refused, failed or differs, and 2 when the registry or a file cannot be read, or a name finds no Sender or Receiver or more than one.

Like `st2110 nmos` it [finds the registry by DNS-SD](#finding-the-registry) when given none, and it takes the same [IS-10 options](#is-10-access-tokens).

## Route from a browser

`st2110 router` serves a router panel: a crosspoint grid with a row for each Receiver and a column for each Sender, grouped into video, audio and data levels.

```console
$ st2110 router http://registry.example:8080 --open
Router: http://127.0.0.1:8110/
Registry: http://registry.example:8080
Ctrl-C stops the router.
```

- A lit crosspoint is the Sender a Receiver takes now. A plain one can be taken: click it and the Receiver switches at once. A hatched one cannot, by transport, format or BCP-004-01 capabilities, and clicking it says why.
- In Salvo mode, clicks arm crosspoints (and Off, to disconnect), and Take switches them together at one PTP time, `--lead` seconds ahead. Check only plans and checks them without sending anything.
- Where the registry's Receivers give BCP-002-01 groups, With its group takes the rest of a Receiver's group with each click or salvo, as `st2110 connect --group` does, such as a monitor's audio with its video; each crosspoint's label says so. It is off until turned on, and then kept in the browser. What of a group is left as it is shows in the log with why.
- The connections are made by this command, exactly as `st2110 connect` makes them: checked against each Receiver's constraints and capabilities first, rolled back when one fails, and checked on each `/active` endpoint and in the registry after. Each outcome, with its problems and notes, is listed under the grid.
- Above the grid, a card for each Sender shows its stream live: a picture of video, a meter for each audio channel, and what arrived (bit rate, frame rate, packets lost, the ST 2022-7 class of a pair). It says which Receivers take the Sender. Clicking the card opens the Sender's details: its Flow and Source, where it sends as its Connection API reads it back, every leg of its SDP file with the file's checks, and what this machine receives of it. There it can be turned off and on, and sent to other groups or addresses, as `st2110 connect --sender` does; Stop, and a move while it is on, arm first and say which Receivers lose the stream. Each video Receiver's row shows a small picture of what it takes.
- Under the grid, Channel maps lists each Device that advertises an IS-08 Channel Mapping API (`urn:x-nmos:control:cm-ctrl/v1.0`). Opening one shows a crosspoint grid for each of its Outputs: the Output's channels down the side, every Input's channels across (with the Receiver that feeds an Input, where it names one), and Silent; the lit crosspoint is the Input channel each takes now, as `/map/active` reads it back, read again every 5 seconds while it is open. A click arms a change, whatever the mode above, and Take sends every change armed on the Device in one activation, at once, as `st2110 connect --device --map` does, so that swapping two channels never leaves both on one input; Esc or Clear releases them, and Check only checks without sending. An Input an Output's `routable_inputs` leave out is hatched, and clicking it says what the Output takes. An Output that a scheduled activation is waiting to change is locked until it takes effect, as IS-08 has a Device refuse other changes to it (423): it shows a padlock and when the activation is due, and Cancel, which arms first, takes the activation away. Each change, refusal and cancel is in the log.
- The previews are received by `st2110 router` itself, from the Senders' SDP files, only while the page is open and shows them, and at most `--previews` at once (8 unless set; `--previews 0` turns them off). Each takes its stream's full bandwidth on this machine's link, whatever the size of its picture, so they start off for a real facility; tick Live previews to turn them on, and `--interface` names the interface to join the multicast groups on. The browser receives only small PNG pictures and numbers.
- The browser talks only to `st2110 router`, which talks to the registry and the Devices. So Devices need not accept requests from a web page (most refuse them), and no ST 2110 stream reaches the browser.
- Where a Device lists an IS-12 control endpoint, the router reads its BCP-008 status monitors, subscribes to them, and passes each change to the page as it hears it: it never polls them. A Receiver whose monitor is not healthy shows why under its name in the grid, in amber when partly healthy and red when unhealthy; a healthy one shows nothing. A Sender's details show its monitor's every domain and the counters that are not 0.
- The page hears of each change as it happens. The router subscribes to the registry's Query API for every type of resource (IS-04 Query API subscriptions, over WebSockets) and pushes each change to every open page over a WebSocket of its own, with each connection made from any page. The status at the top right says `Live` when the registry tells the router of each change; a registry without subscriptions is read every 3 seconds while a page is open (`every 3 s`), and a page that cannot hold a WebSocket reads every 3 seconds itself (`Read at`).
- The connections log is the router's, not the page's: every page shows each take from any page, and it is kept, with the demo facility's connections, in a small file (`--state FILE`; by default `~/Library/Application Support/st2110/router.json` on a Mac, `~/.local/state/st2110/router.json` on Linux; `--no-state` keeps nothing), so a restart loses neither. Crosspoints armed for a salvo are kept in the browser, per registry, and come back armed after a reload.
- `st2110 router --demo` serves a demo facility instead: an IS-04 registry and each Node's IS-05 Connection API, with four cameras, a graphics machine, a PTZ camera that sends by unicast and starts off, and four monitors, one of which takes only the graphics machine's smaller picture and one of which also takes a unicast stream. An audio Node, Audio 1, has a Receiver of up to 8 channels and an IS-08 Channel Mapping API: an 8-channel Input fed by that Receiver and a stereo tone, routed to a stereo Monitor Output, which takes either, and an 8-channel Program Output, which takes only the Receiver's channels or silence. Its map changes at once or at a time, and is kept with its connections. Its Senders can be turned on and off and sent elsewhere, and its streams follow. Each camera's video and audio, and each monitor's, are a BCP-002-01 group (the graphics machine gives none), and every Node and Device gives its BCP-002-02 asset tags. The demo sends each Sender's stream from this machine on the loopback interface (small 25 fps pictures, an ST 2022-7 pair for each camera, and a tone at its own level for each camera's sound), so its previews are live on a Mac with no network at all. It is a registry like any other, so `st2110 nmos` and `st2110 connect` work on it too, at `http://127.0.0.1:8110`, and Nodes register with it, such as [`st2110 send --nmos`](#as-nmos-nodes). Its Query API takes subscriptions, and with `--demo-auth` it asks for IS-10 tokens too (below).

Anyone who can reach the page can make connections. It listens on `127.0.0.1:8110` unless `--listen` says otherwise (`0.0.0.0:8110` lets other machines in), answers only requests addressed to an IP address or `localhost`, and takes connections only from its own page, so another web site cannot make them through a visitor's browser. The page's WebSocket is held to the same rules: addressed by IP address or `localhost`, and opened only by the router's own page.

### IS-10 access tokens

Where a registry or the Devices ask for IS-10 access tokens, `st2110 nmos`, `st2110 connect`, `st2110 router` and `st2110 discover` send one with every request, including the router's subscriptions and its IS-12 connections to status monitors:

```console
$ ST2110_CLIENT_SECRET=… st2110 router https://registry.example --auth https://auth.example/ --client-id st2110-router
```

- `--auth URL --client-id ID` gets tokens from the Authorization Server whose issuer is URL, found from its RFC 8414 metadata, with the OAuth 2.0 Client Credentials grant (`client_secret_basic`) and the scopes `query node connection channelmapping ncp` (`--scope` to change them): reading the registry, and Nodes peer to peer, making connections, changing IS-08 channel maps and reading IS-12 status monitors, since IS-10 has each API ask for its own scope. The secret comes from `--client-secret-file` or `ST2110_CLIENT_SECRET`, never the command line. A token is renewed half way to expiring, and at once when a server refuses it.
- Without `--auth`, the Authorization Server is found by DNS-SD (`_nmos-auth._tcp`), unicast first, as IS-10 Discovery has clients do, the lowest `pri` first, its issuer from its address and `api_selector`.
- `--register`, instead of `--client-id`, registers with the Authorization Server by OAuth 2.0 Dynamic Client Registration (RFC 7591), with a `client_name` unique to this run of this machine, for the Client Credentials grant and the scopes asked for. An initial access token the server gave for registering goes in `--registration-token-file` or `ST2110_REGISTRATION_TOKEN`. What the server issues is kept in a file only this user can read (`--client-file`; `clients.json` beside the router's state file by default), so the next run uses it rather than registering again, as IS-10 asks, and registers again only when the server no longer knows it.
- `st2110 router --register --private-key-jwt` registers for `private_key_jwt` instead (RFC 7523), as IS-10 recommends a confidential client do: it signs an ES256 assertion for each token request with a key kept with the registrations, and publishes the public key at `http://<--listen>/.well-known/jwks.json`, its `jwks_uri`, so `--listen` has to be an address the Authorization Server can reach. `st2110 nmos` and `st2110 connect` cannot publish a key while they run so briefly, so they register for a secret.
- `st2110 router --sign-in --auth URL --client-id ID` gets its tokens from a person instead, who signs in on the page with the OAuth 2.0 Authorization Code grant and PKCE (RFC 6749 §4.1, RFC 7636 `S256`). Until someone has, the page shows Sign in and nothing else. Sign in sends the browser to the Authorization Server's `authorization_endpoint` (from its RFC 8414 metadata) with a fresh `state`, kept in a cookie in that browser, and a code challenge; the server sends it back to `http://<the address the page was opened at>/auth/callback`, where the router checks the `state` against the cookie and the sign-ins it began in the last five minutes, swaps the code for a token with the code verifier, and goes back to the page. The header then says it is signed in (and as whom, when the token is a JWT with a `sub`), with Sign out, which forgets the token. The token is renewed with the refresh token the server gives, if it gives one; otherwise, when it runs out, someone signs in again. `--client-id` is a client the Authorization Server has registered for the Authorization Code grant with that redirect URI (RFC 8252 lets a loopback one take any port); a public client needs no secret, and a confidential one's goes in `--client-secret-file` or `ST2110_CLIENT_SECRET`.
- `--token-file FILE` sends the token a file holds instead, read again whenever it changes, for a token another program keeps fresh.
- A token is sent only over `https://` (and `wss://`), or to this machine, as IS-10 expects TLS.
- `st2110 send --nmos` and `st2110 receive --nmos` ask for tokens on their own APIs with [`--require-token`](#as-nmos-nodes), and check each against the Authorization Server's keys.
- `st2110 router --demo --demo-auth` tries it with no equipment: the demo asks for tokens and serves an Authorization Server whose tokens last a minute, to client `st2110-demo` with secret `demo-secret`, and to any client that registers with the initial access token `demo-registration`, for a secret or for `private_key_jwt`. The router registers itself for `private_key_jwt` and signs with a key of its own. `st2110 connect http://127.0.0.1:8110 --auth http://127.0.0.1:8110/ --client-id st2110-demo` works too, with the secret in `ST2110_CLIENT_SECRET`, and so does `ST2110_REGISTRATION_TOKEN=demo-registration st2110 connect --dns-server 127.0.0.1:8110 --domain demo.test --register`, which finds the registry and the Authorization Server by DNS-SD and registers. Its tokens are JWTs as IS-10 has them: issued by `http://127.0.0.1:8110/`, for any host (`aud` `*`, where a real server names the facility's), with the client, the scopes granted and an `x-nmos-<scope>` claim for each that reads and writes everything, and signed with a key it makes when it starts and publishes at its `jwks_uri`. It signs with ES256, where IS-10 has a server sign with RSA (the Nodes here take RS256, RS384, RS512 and ES256). Each of its APIs asks for its own scope: the Query API `query`, the Registration API `registration`, the Connection APIs `connection` and the Channel Mapping API `channelmapping`. A Node of this program's checks its tokens for itself: `st2110 receive --nmos=http://127.0.0.1:8110 --require-token --auth http://127.0.0.1:8110/ --client-id st2110-demo --interface 127.0.0.1`, with the secret in `ST2110_CLIENT_SECRET`, registers with the demo and refuses any request without one of the demo's tokens, and the router's takes go through. `st2110 router --demo --demo-auth --sign-in` tries signing in: the demo's `authorization_endpoint` signs in anyone at once, for its public client `st2110-sign-in`, sends them back only to this machine, and takes each code once and only with the verifier its challenge was made from; its refresh tokens are each taken once, for a new one.

What signing in does not do: the router holds one token, the last person's to sign in, and acts with it for everyone who can reach the page, so a registry that grants by person sees every take as theirs, and the connections log does not say who made each one. Nor does it keep anyone signed in across a restart: the token is held in memory and never written to the state file, so a restarted router asks again. Sign out forgets the token without revoking it at the server. A router that is one controller for everyone, as the NMOS controllers on a broadcast network usually are, is better served by the Client Credentials grant.

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
    virtual receiver buffer peaked at 5 of VRXFULL 8 and averaged 3.1 (3.4, and at least 2, in each frame's steady state), gapped reads from TROFFSET 764.4 µs; Margin 18.4 µs (17.0 to 19.8); packets arrived 17.0 µs or more before their reads; by residence time, 3.8 to 4.5 read intervals from arrival to read
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
- For video and ancillary data it measures, frame by frame, the first packet time from each frame's reference time counted from the SMPTE Epoch, the RTP offset and the latency, as RP 2110-25 does. It runs the ST 2110-21 network compatibility model (CINST against each sender type's CMAX) and the virtual receiver buffer (against VRXFULL, with underflows), by event history: its peak, its minimum and its average before each read, over the whole capture and in each frame's steady state from the first read to the last packet, with RP 2110-25's Margin for each frame, and by residence time: each packet's read less its arrival, in read intervals. It checks each ST 2110-20 packet's sample row data headers against the format, and that ST 2110-22 frames keep one size, at the rate `b=AS` gives. For audio it measures latency, packet intervals and the timestamped delay factor (TS-DF) of each 200 ms, counting latency from the `a=mediaclk:direct=` offset that AES67 allows. Each audio and ancillary data flow is lined up with a video flow, the one from the same sender or else the first: the audio or ANC video differential latency (AVDL, ANC VDL) and, for ancillary data, the relative RTP offset. `--format json` gives the video and audio measurements for each second of the capture as well as overall.
- It follows each PTP domain: grandmasters and a timeline of their quality, ports, message rates, Sync messages without a Follow_Up, Delay_Req messages without a Delay_Resp, two ports announcing at once, and the synchronization metadata TLV's rate and locking status. Every message also gets the checks `st2110 ptp` makes, each reported once for its port. Each SDP file's `a=ts-refclk` is checked against the grandmaster and domain the capture's Announce messages give, and a `traceable` clock against their clock quality.
- The flows of an SDP file's `DUP` group are merged as an ST 2022-7 receiver merges them: the packet time differential and the receiver class it needs, over the capture and for each second, the packets no leg delivered, and when each leg went and came back.
- The timing measurements need the capture's timestamps on PTP time. A capture timestamped by a NIC whose clock ptp4l disciplines, as `tcpdump -j adapter_unsynced` does, counts PTP time; one timestamped by the system clock counts UTC, which it moves 37 s onto PTP time (`--tai-utc` changes that). It works out which from the capture's PTP Sync messages, or else from the RTP timestamps, and says why; `--timescale ptp` or `utc` says so outright. When it cannot tell, it skips what needs PTP time and measures the rest.
- `--quiet` and `--deny-warnings` work as they do for `lint`.
- It exits with 0 when nothing is an error, 1 when something is or a file ends partway through, and 2 when a file cannot be read or is not a capture.

It measures what arrived where the capture was made, so a capture from a switch's mirror port also shows that switch's queuing. It does not reassemble IP fragments, which ST 2110-10 forbids; it reports them. Each leg of an ST 2022-7 pair is also a flow of its own, checked on its own; the pair needs an SDP file with its `DUP` group to be measured merged. It measures the first 10,000 flows and follows the first 10,000 PTP ports, and counts the packets and messages of any more.

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
  ST 309 date 2026-09-27 (MJD 61310)

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
- `--color-frame` aligns 25 and 29.97 time code to the colour frame sequence, as a grandmaster's `colorFrameIdentificationMode` asks (ST 2059-1 §9.3.2.1): the jam waits for the sequence's first codeword, and the time code carries the Color Frame Flag. Each time code comes with its ST 309 date, which changes as the time address passes midnight.
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
- It reads the Senders from the registry a controller would choose: only those found by unicast DNS when there are any, then one that asks for no authorization first (unless it has a token to give, with the [IS-10 options](#is-10-access-tokens)), then one in use before one for development (`pri` of 100 or more), the lowest `pri` first and one picked at random among equals, going on to the next when one does not answer. `--registry URL` names one instead. Where no registry answers, it reads each Node it found, peer to peer through its Node API, and again whenever the version counters the Node advertises change.
- It fetches each RTP Sender's SDP file from its `manifest_href`, as `st2110 nmos` does, but never through a proxy, and reads the registry or the Nodes again every 15 s. A stream that SAP announces and NMOS lists, going to the same addresses from the same sources (where both SDP files name them), is listed once, with both.
- It looks on every port that is up, and on each one that comes up while it looks, or on those `--interface` names, for `--duration` seconds, 10 by default. Senders announce by SAP every 30 s or so, so give `--duration 35` to hear every one, or `--watch` to keep looking and print each stream as it comes, changes and goes. `--save DIR` writes each stream's SDP file there, named after the stream, to receive, view or check. `--sap`, `--no-sap`, `--no-nmos`, `--mdns` and `--timeout` change where and how it looks, and `--format json` gives everything it found, SDP files included.
- It exits with 0 when it found a stream, 1 when it found none, and 2 when it could not look, as when another program holds a port alone.

It only looks: it answers no queries and registers nothing. It reads IPv4, as ST 2110 networks are, and cannot read encrypted SAP. A registry or Node that asks for IS-10 authorization is read with a token from the [IS-10 options](#is-10-access-tokens).

To try it on one machine with no ST 2110 equipment, run `python3 scripts/try-discovery.py`. It serves the test facility's Camera 1 as an NMOS Node, advertises it with the system's multicast DNS responder (`dns-sd` on macOS, `avahi-publish` on Linux), sends a tone announced by SAP, and runs `st2110 discover`, which finds Camera 1's two streams and the tone. CI runs it on macOS.

On macOS 15, `st2110` can send to the network only once the terminal app has Local Network access (System Settings, Privacy & Security, Local Network); until then, its sends fail with "No route to host". Sending with `--interface 127.0.0.1` keeps a stream on this Mac and needs no permission.

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

- `st2110 send video [FORMAT]` sends EBU colour bars, with a box that moves along the black strip beneath them, as ST 2110-20 video. FORMAT is 1080p50 unless it names another, such as 2160p59.94 or 1280x720p25. 1080i50 and 1080i59.94 send interlaced video, named by its fields a second as broadcast names it, and 1080psf25 progressive segmented frames; 720x486i59.94 and 576i50 send 525- and 625-line video. Each field goes in packets of its own, the second with the F bit set, its rows numbered within the field and a marker on the last packet of each field; the second field of an interlaced frame carries the timestamp of the next field period, half a frame on, and both segments of a PsF frame the frame's, with the marker at its end only. The ST 2110-21 read offsets and active rasters are the 525, 625 and 1125-line ones of ST 2110-21:2017, and a narrow sender reads the second field from half a frame after the first. `--sampling` (YCbCr-4:2:2, YCbCr-4:4:4, YCbCr-4:2:0, RGB or KEY), `--depth` (8, 10, 12 or 16 bits, or `16f` for 16-bit floating point), `--colorimetry`, `--tcs`, `--range` and `--packing` choose the rest. 4:2:0 pixel groups cover two rows each, as ST 2110-20 Table 3 has them, and each packet's row headers name the first row of each pair. 16-bit floating-point samples carry the values themselves, 0 to 1 for Y' and R'G'B' and −½ to ½ for the colour differences, whatever `--range` says. `st2110 send audio` sends a 1 kHz tone at −18 dBFS as ST 2110-30 audio; `--channels`, `--sample-rate`, `--bits`, `--packet-time`, `--tone` and `--level` choose it. A packet holds a whole number of samples, so at 44.1 kHz `--packet-time 1` gives 44 of them, 997.7 µs, which the SDP file writes as `a=ptime:1` and a receiver rounds back to 44. `--am824` sends the channels as ST 2110-31 AES3 signals instead, a pair to each, in AM824 subframes: B on the first subframe of every 192-frame block, F on each frame's first subframe, even parity, and channel status for professional linear PCM, with the sampling frequency at 44.1 and 48 kHz and its CRC. It needs an even number of channels and 24 bits, and takes the packet times of ST 2110-31 Table 1, 1, 0.125 or 0.083 ms, which the SDP file writes as Table 1 does: `a=ptime:0.12` for 125 µs, and `1.09` for 48 samples at 44.1 kHz.
- Each frame starts at its alignment point counted from the SMPTE Epoch, with its RTP timestamp, as ST 2059-1 gives them. Its packets go at the ST 2110-21 read times of the sender type that `--sender-type` declares, from the default read offset and a little ahead of each read, so that the virtual receiver buffer neither runs dry nor overflows. Unless it says `narrow`, `narrow-linear` or `wide`, that is `wide` below 900 000 packets a second and `narrow-linear` from there, where ST 2110-21 defines no wide sender. Each audio packet goes as its last sample falls due.
- `--to` gives the destination, a multicast group or a unicast address; give it twice for the two legs of an ST 2022-7 pair, which carry the same packets. `--interface` gives the address to send from, once for every leg or once for each; otherwise the routing table picks. `--ttl` sets the multicast time to live and `--dscp` the DSCP, AF41 by default, as AES67 marks media.
- It writes the SDP file before it sends, to standard output or to `--sdp`, with `a=group:DUP` for a pair and a source filter for each multicast leg. `st2110 lint` finds no errors in it. Audio's says `TSMODE=SAMP`, as its timestamps are the sampling instants, with the packet time as `TSDELAY`.
- `--sap` announces the stream by SAP as well, as AES67 devices do, for `st2110 discover` and ST 2110 Viewer to find: to 239.255.255.255:9875, or `--sap=ADDRESS:PORT`, as it starts and every 30 s after, withdrawing the announcement when `--duration` ends. A sender stopped with Ctrl-C cannot withdraw it, so listeners mark the stream as maybe stopped 90 s later.
- It times packets by the system clock, taking TAI to be 37 s ahead of it (`--tai-utc` changes that). On a machine whose clock `phc2sys` keeps to PTP, name the grandmaster with `--clock <grandmaster>:<domain>` or `--clock traceable`, and its streams line up with every other sender's. Otherwise the SDP file names this machine's MAC address as `localmac`, which only Linux can find; elsewhere give `--clock`.
- `--duration` sends for that many seconds, and without it the sender runs until it is stopped. With `--pcap FILE` it writes the packets into a capture instead, as fast as it can make them, each at the time it would have gone out, on UTC as a capture made with the system clock is. `st2110 pcap` measures such a capture, and `st2110 receive --pcap` reads it.
- `st2110 receive SDP` joins each leg's group, from the SDP file's source only when it has a source filter, or takes a unicast leg on its address; `--interface` gives the interface. It merges the legs as ST 2022-7 does, passing on the first copy of each packet, puts the packets back in sequence order and the frames or samples back together, an interlaced or PsF frame from its two fields. When a packet is missing it waits for it, for a copy on a leg that runs behind or one out of order, for up to `--max-skew` milliseconds: 50 by default, as far as ST 2022-7 class B receivers allow the legs to differ, and up to 1000.
- It reports what each leg lost and what was lost after merging, how far apart the legs' copies arrived and the tightest ST 2022-7 receiver class that allows it, which frames arrived whole, the frame rate, for AES3 the whole blocks of channel status, what the first signal's says and any parity, CRC, B or F bit faults, and the latency from each frame's RTP timestamp, which is the sender's and the network's delay when both clocks follow PTP. It follows a sender that restarts, with a new synchronisation source or with sequence numbers or timestamps that start again elsewhere, and leaves out stray packets that fit neither the stream nor a restart. It follows a sender that pauses, too, and counts the frames or audio it never sent. With two legs it counts the copies whose RTP header or payload differ from the first, which ST 2022-7 has identical, and notes when a leg went for longer than it waits (at least 10 ms) and came back, when the stream had no protection. A capture played in a loop restarts the stream each time round when the loop is longer than the packets the receiver remembers, half a second's or twice `--max-skew`; a shorter loop's packets are taken for copies of the ones before. A frame cut off by the start or end of receiving is not a fault.
- `--duration` receives for that many seconds, 5 by default. `--pcap FILE` reads a capture instead of the network, and works out whether its clock is PTP time or UTC. `--png FILE` saves the last frame that arrived whole, and `--wav FILE` the audio, with silence where packets were lost or never sent, up to 10 s a gap. `--format json` gives everything the report holds.
- `receive` exits with 0 when the stream arrived whole, 1 when something was lost or incomplete, and 2 when it cannot receive. `send` exits with 0 when it has sent, and 2 when it cannot.

Both use ordinary sockets, and the sender sends one packet at a time from one thread, waiting for each packet's time. On a quiet machine that keeps a wide sender's pace at HD rates; it does not keep a narrow sender's, and UHD rates need the kernel bypass that Intel MTL brings. The receiver times each datagram by the kernel's receive timestamp on Linux and macOS, and by when it reads it elsewhere. It needs a large socket buffer for video: raise `net.core.rmem_max` on Linux (`sysctl -w net.core.rmem_max=67108864`) or `kern.ipc.maxsockbuf` on macOS; `receive` says when the system allows less than 4 MiB.

Not yet: ST 2110-22 JPEG XS, sent from pre-encoded codestreams or received to files; 4:2:0 interlaced video; and AES3 channel status other than professional linear PCM, or user data.

### As NMOS Nodes

With `--nmos`, `st2110 send` and `st2110 receive` are NMOS Nodes, so a facility's controller sees the Sender or Receiver in its registry and can route it:

```console
$ st2110 send audio --to 239.10.60.1:5004 --clock traceable --label "Test tone" --nmos
NMOS: Sender 643981d8-be06-4efe-9d87-8cf309d06ba6 at http://192.168.10.21:39749/x-nmos/node/v1.3/, its Connection API at http://192.168.10.21:39749/x-nmos/connection/v1.2/, its IS-12 control at ws://192.168.10.21:39749/x-nmos/ncp/v1.0/
NMOS: registered with http://registry.example/x-nmos/registration/v1.3/ (Registry, found by DNS in studio.example)
$ st2110 receive --nmos --media audio --label "Test monitor"
$ st2110 connect --receiver "Test monitor" --sender "Test tone"
```

- Each serves an IS-04 v1.3 Node API and an IS-05 v1.2 Connection API, on `--nmos-port` or a port the system picks, and registers its Node, Device, Source, Flow and Sender or Receiver with the registry at `--nmos=URL`, or with the one it [finds by DNS-SD](#finding-the-registry) (`_nmos-register._tcp`) as IS-04 has a Node do. It describes the stream as it is sent: the Flow's format, picture or sampling, the Sender's transport and ST 2110-21 sender type, and its PTP clock. `--label` names it. The ids stay the same from one run to the next, for the same stream from the same machine.
- It heartbeats every 5 s, registers everything again when the registry has forgotten it, goes on to the next registry DNS-SD finds when one stops answering, and deletes what it registered when it finishes. Stopped with Ctrl-C it cannot, and the registry lets it expire after 12 s, as IS-04 has registries do.
- The Connection API serves `staged`, `active`, `constraints`, `transporttype` and the bulk interface, and activates at once or at a scheduled time, absolute or relative. A Sender's `transportfile` is its SDP file as it sends now.
- An activation on a Sender takes effect on the stream as it runs: a new `destination_ip` or `destination_port` moves it from the next packet, from the same source port, and `master_enable` false sends nothing while keeping the stream's time, so it comes back lined up; the `--sdp` file, the SAP announcement and the IS-04 `version` follow. A multicast Sender is refused a unicast address and the other way round. An activation on a Receiver takes the SDP file in `transport_file`, joins the groups it names (or those `transport_params` give) and reports what arrived from each Sender in turn. `receive --nmos` receives until stopped, unless `--duration`; given an SDP file, it starts with that stream.
- Its Device has an IS-12 v1.0.1 control endpoint, a WebSocket on the same port, listed in its `controls`. The Device model is MS-05-02's: a root block with the DeviceManager, the ClassManager (every class and datatype it uses) and one BCP-008 monitor, an `NcReceiverMonitor` or `NcSenderMonitor` whose touchpoint names the Receiver or Sender. Controllers subscribe to it and hear each property change.
  - A Receiver's connection status comes from what arrives every half second: nothing, or packets lost or too late, is unhealthy; a leg that brings nothing, or loses what the other leg makes good, is partly healthy. Its stream status says whether what arrives is the stream the SDP file describes. It counts lost and late packets, for each leg too with two.
  - A Sender's transmission status says whether every packet goes out: any the system had no room for, or nothing sent, is unhealthy; any more than 100 µs late is partly healthy. Its essence is always healthy, and its counters are the late and refused packets.
  - Link is unhealthy when no interface has the stream's address any more. Synchronization is taken as locked to a PTP grandmaster that `--clock` names, since the system clock is said to follow it; it is not checked. Otherwise it is not used, from `internal`.
  - The statuses follow BCP-008: an activation makes them healthy at once and holds back anything worse for the status reporting delay (3 s, which a controller can set from 0 to 3600); after that, worse is reported at once and better only once it has lasted the delay; deactivating makes them inactive at once. Counters and messages reset on each activation unless `autoResetCountersAndMessages` is false.
- With no registry to register with, none found by DNS-SD or none that answers, the one named included, it advertises the Node by multicast DNS for IS-04 peer-to-peer discovery: `_nmos-node._tcp`, with `api_proto=http`, `api_ver=v1.3`, `api_auth=false` (`true` with `--require-token`) and the version counters `ver_slf`, `ver_src`, `ver_flw`, `ver_dvc`, `ver_snd` and `ver_rcv`, each starting at 0 and going round from 255 to 0. An activation goes up `ver_snd` or `ver_rcv`, and the TXT record is announced again. IS-04 has a Node advertise peer to peer only while it finds no registry, so it says goodbye once it registers, and advertises again when it loses the registry and finds no other. `st2110 discover` finds it, and reads it peer to peer.
  - The multicast DNS responder is the program's own, sharing port 5353 with the system's where the system allows that, as macOS's mDNSResponder does. It names the instance after the label and the host `<this machine>-nmos-<port>.local`, probes for both three times, a quarter of a second apart, and takes `Label (2)` and so on when another responder has them; then it announces its records twice, a second apart, answers PTR, SRV, TXT and A questions about them, by unicast to a querier that asks from a port of its own, and says goodbye when the command ends. Stopped with Ctrl-C it cannot, and browsers forget the Node when its records' time is up, two minutes for the SRV and A records. `--mdns` gives another multicast group and port to advertise at. It is kept simple: IPv4 only, answers sent at once rather than after a random delay, and no tie-break between two responders that probe for one name at the same moment.
- The Node API takes IS-04's `POST /receivers/{id}/target`, which IS-04 v1.3 keeps for older controllers and deprecates in favour of IS-05: given a Sender, the Receiver fetches the SDP file at its `manifest_href` and is connected as an IS-05 immediate activation of that file would connect it, its transport parameters from the file and a leg the stream lacks turned off; given `{}`, it is disconnected. It answers 202 (Accepted) with what it was given.
- It finds the registry with the [IS-10 options](#is-10-access-tokens), asking for the `registration` scope.
- `--require-token` has its own APIs ask for an IS-10 token, as IS-10 v1.0.1 and BCP-003-02 have a Resource Server do: every request to the Node API, the Connection API and the IS-12 endpoint, below each API's version (the paths above it only list what is served, and a browser's preflight `OPTIONS` carries none), in `Authorization: Bearer`, or as `access_token` in the query of the IS-12 WebSocket. The Authorization Server is the one at `--auth`, or the one DNS-SD finds (`_nmos-auth._tcp`); the Node needs `--client-id` or `--register` as well only where the registry asks for a token too.
  - A token is a JWT the server signed, with RS256, RS384, RS512 or ES256. The Node reads the server's RFC 8414 metadata for its `issuer` and `jwks_uri`, and its keys from there, over `https://` or from this machine only, when it starts; it keeps them, and reads them again when a token names a key it does not have, at most every 5 s. The token must be issued by that server (`iss`), current (`exp`, and `nbf` where it gives one, with 30 s either way for clocks that differ), for this machine (`aud` names its host name or address, or a pattern such as `*.studio.example` that matches one), and its `x-nmos-node`, `x-nmos-connection` or `x-nmos-ncp` claim must list the path below the API's version, `*` standing for anything, under `read` for `GET` and `HEAD` and under `write` for the rest; a `scope` claim, where it gives one, must include the API.
  - A request with no token, or one that is not good, is answered 401, and one whose token does not reach the path 403, each with `WWW-Authenticate: Bearer` and the RFC 6750 error (`invalid_request`, `invalid_token` or `insufficient_scope`) and why.
  - On the IS-12 endpoint a token that lets a controller read lets it connect, `Get`, search and subscribe; it may `Set`, change a sequence or reset the monitor's counters only where the token lets it write as well, and is answered 401 (`Unauthorized`) otherwise. The Node closes the connection (1008) when the token runs out, for the controller to connect again with a fresh one.
  - The Node then gives `authorization: true` on its Node API endpoint and its Device's controls, and `api_auth=true` peer to peer.

Try it on one machine with `st2110 router --demo`, and `--nmos=http://127.0.0.1:8110 --interface 127.0.0.1` on each, or with no registry: `st2110 receive --nmos --media audio` and `st2110 discover`; with `--demo-auth`, [the demo's tokens](#is-10-access-tokens) work on a Node with `--require-token`. Not yet: TLS on the Node's own APIs. A controller that sends tokens only over `https://`, as this program's own do except to this machine, cannot reach a Node that asks for them from another machine without a TLS proxy in front of it; and the Node has no IS-08 Channel Mapping API of its own, only the demo's Audio 1 does.

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
- Colours are worked out with the stream's luma coefficients and range, and shown as the screen's own: HDR (PQ or HLG) is not tone-mapped, and BT.2020 colours are not converted to the screen's. 4:2:0 chroma is shared by each square of four pixels, and 16-bit floating-point values beyond 0 to 1 are clipped.
- A frame is unpacked in bands of rows across the machine's cores, about 9 ms of work for 1080p on one 2.8 GHz Xeon core, and a screen that falls behind skips frames rather than delaying them. The sockets are the limit, as for `receive`, and need the same large buffer.
- The window is [minifb](https://github.com/emoon/rust_minifb)'s. Building with `--no-default-features` leaves out `view`, and minifb with it.

## ST 2110 Viewer

ST 2110 Viewer is an app for the Mac that finds the ST 2110 streams on the network and plays an ST 2110-20 video stream as it arrives, from the network or from a capture, with what has arrived beside the picture. It finds streams as `st2110 discover` does, receives as `st2110 view` does and counts what `st2110 receive` counts, and it keeps going: pick another stream, change the port, stop and start.

- **Find a stream.** The list on the left, which Find streams shows and hides, has the streams on the network as `st2110 discover` finds them, kept current: what each carries, where it goes and how it was found. Click one to play it. Those it cannot play, such as ancillary data, are dimmed with the reason, and so are NMOS Senders that are not sending and announcements that have stopped coming. Refresh asks again at once. Save SDP file, beside the picture, keeps the SDP file of a stream found this way.
- **Open a stream.** Open its SDP file with the button or ⌘O, pick one from Recent, or drop it on the window. Receiving starts at once.
- **Say where it comes from.** Network receives on the port picked beside it, which the app remembers; Any port lets the system route the stream's addresses. Capture plays a pcap or pcapng file at the pace it was captured, with the open SDP file saying what to look for. Drop an SDP file and a capture together to play them.
- **Watch it.** The picture fills the window at the stream's shape. Double-click it for full screen, and Escape to leave. When frames stop coming, the picture keeps the last one and says how long it has been.
- **Read what arrived.** Beside the picture: frames and the incomplete ones, the frame rate, packets and what was lost or came too late, each leg of an ST 2022-7 pair, how far apart the legs arrived and the tightest receiver class that allows it, the latency from RTP timestamps, and for audio the loudest sample on each channel. Problems and notes are the ones `st2110 receive` reports, as they come. The line along the bottom says what receiving is doing.

It follows the Mac's light or dark appearance, and its Reduce motion setting (Accessibility, Display): with it on, menus open with a shorter fade and lists jump rather than glide. `ST2110_MOTION=reduced` or `full` overrides the setting, for a show machine short of GPU or a screen recording.

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
| ST 2022-7, RP 2110-23 | `DUP` legs that match and are addressed apart, `MULTI-2SI` stream counts and addresses, one format and `TROFF` for a multi-stream group's streams (a should for `PHASED`) and `DUP` for all of them or none, `FID` without ANC |
| ST 2110-20, -21 | Required parameters and their values, the `SSN` edition rule, interlace and PsF, pixel groups, block packing, `TP`, default `TROFF` (for interlaced 525- and 625-line video, the ST 2110-21:2017 values that the 2022 edition's Table 1 misprints), RFC 4175 look-alikes |
| RP 2110-24 | SD sampling, width, height and pixel aspect ratio |
| ST 2110-22 | `b=AS`, `TP`, frame rate, JPEG XS `packetmode`, profile, level, sublevel, depth and bits a pixel (VSF TR-08) |
| ST 2110-30, -31 | Sampling rate, `ptime`, conformance levels (the -31 X levels at 44.1 and 96 kHz too), packet size against the standard UDP limit (-30) or `MAXUDP` (-31), `channel-order`, AM824 channel pairs |
| ST 2110-40, -41, -43 | The media type on the `m=` line; ANC `SSN`/`TM`/`exactframerate`, `DID_SDID` (and embedded audio or EDH in it), `VPID_Code`; FMX `SSN`, `DIT` and the audio clock of MGA metadata (ST 2127-2); TTML clock and `codecs` |

It follows the editions current on pub.smpte.org in September 2026: ST 2110-10:2022, -20:2022, -21:2022, -22:2022, -30:2025, -31:2022, -40:2023, -41:2024 (whose SSN the 2026 edition keeps), -43:2021, RP 2110-23:2019, RP 2110-24:2023 and ST 2022-7:2019, with VSF TR-08:2026 for JPEG XS.

It reads SDP only, so it cannot confirm that a sender does what its SDP says; `st2110 pcap` checks that in a capture. It also leaves out the JPEG XS level that a picture's size and rate call for (TR-08 asks for the lowest that fits).

### NMOS registries

| Area | Checks |
|---|---|
| Resources | The attributes each IS-04 schema requires and their types, `id` and `version` syntax, duplicate ids, parents and references that are not registered, interface and clock names a Node does not have |
| Interfaces | LLDP `port_id` and `chassis_id` written as IS-04 writes a MAC address, a `chassis_id` of `null`, and, at v1.3, interfaces that do not say which switch port they are plugged into (`attached_network_device`), as notes |
| PTP | Unlocked clocks, locked clocks that follow different grandmasters (unless both are traceable to TAI), and a Sender whose `a=ts-refclk` disagrees with its Source's clock |
| Tags | BCP-002-01 `grouphint` values that are not `<group>:<role>[:<scope>]`, and two Senders or two Receivers with one role in one group; Nodes and Devices that give BCP-002-02 asset tags but not the Manufacturer, Product Name and Instance Identifier (and a Device's Function), or give the same three as another |
| Connections | Subscriptions that contradict `active`, or the IS-05 `/active` parameters (`master_enable`, `sender_id`, `receiver_id`); active Receivers taking from an inactive Sender; Receivers whose BCP-004-01 `caps` reject what their Sender sends, and constraint sets without `caps.version` or with nothing but `meta` attributes in them |
| Capabilities | BCP-004-02 Sender `caps`: `caps.version` with `constraint_sets`, no empty sets, and a stream the Sender's own sets accept; IS-07 `event_types` against the Flow's `event_type` |
| Control APIs | IS-11 Senders in `active_constraints_violation` or `no_essence` and active Receivers in `non_compliant_stream`, active constraints the Sender's `/constraints/supported` leaves out or its stream breaks; IS-08 active maps that name Outputs, Inputs or channels `/io` does not have, or route an Input an Output's `routable_inputs` leave out |
| Status monitoring | IS-12 control endpoints that are not WebSocket URLs, cannot be read, or lack a `root` block with a DeviceManager and ClassManager; BCP-008 monitors whose touchpoints do not name exactly one of their own Device's registered Senders or Receivers, or name one another monitor watches; monitors that say `Unhealthy` or `PartiallyHealthy`, with the Device's message; and monitors `Inactive` while the registry has their Sender or Receiver active, or the other way round |
| System | With `--system`, an IS-09 System API that cannot be read or gives a heartbeat interval, PTP domain or announce timeout out of range, and Senders whose `a=ts-refclk` domain is not the system's. IS-04 Nodes do not report their heartbeat interval, so it is shown but not compared |
| SDP files | Each Sender's `manifest_href` and whether it answers, every SDP rule above, one interface binding per stream, multicast or unicast addresses to match the transport, the file against the Flow, Source and Sender attributes that the NMOS capabilities register maps to SDP (with BCP-006-01's JPEG XS `profile`, `level` and `sublevel`, which a Flow leaves out for Unrestricted), and against the one its Connection API serves at `/transportfile` |

It reads resources registered at any IS-04 version from v1.0 to v1.3. It holds a resource to the schema of the version it reads through when the registry says the resource is at that version, by returning it without a downgrade query, or when it reads a Node's own API; otherwise it reports an attribute as missing only when every version that could have registered the resource requires it.

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
| ST 2110-10 | IP fragments, and datagrams over 1460 octets or the `MAXUDP` signalled (PCM audio, ancillary data and fast metadata keep to 1460 whatever `MAXUDP` says) |
| Video and ancillary data | Marker bits on the last packet of each frame or field, timestamps on the frame grid, packets that arrive before the time their timestamp names, and latency over JT-NM's 1 ms (35 ms for ancillary data) as a note |
| ST 2110-20 | Up to three sample row data headers, with lengths of whole pixel groups, rows and offsets that only increase, and segments within the SDP file's `width` and `height`; 180-octet blocks in block packing, and datagrams under 1000 octets only at the end of a field or frame in general packing |
| ST 2110-21 | CINST over CMAX for the sender type in `TP`, or the `CMAX` signalled, and the virtual receiver buffer's overflows and underflows |
| ST 2110-22 | The same number of packets and octets in every frame, at the rate `b=AS` gives; the RFC 9134 payload header: T and K held, L with M, fields only in interlaced video, each field with its own timestamp; JPEG XS payloads in multiples of 8 octets but for the last of a frame or field (VSF TR-08) |
| RP 2110-23 | The same timestamp for each frame across the streams of a `MULTI-2SI` or `MULTI-SD` group |
| ST 2110-30, -31 | Packets holding the samples `ptime` gives and the channels `a=rtpmap` gives, TS-DF within a packet time (a warning) and under AES67's 17 packet times or 17 ms (an error); for -31, the marker bit and CSRC count at 0, and each AM824 subframe's leading 0 bits and the F and B bits of AES3 framing, its P bit's even parity, a B bit every 192 frames, and the CRC that ends each block of professional channel status |
| ST 2110-40 | The RFC 8331 payload: Length and ANC_Count against the packets carried, the reserved bits, no F field of 0b01, and each packet's parity bits and checksum; packet types against `DID_SDID`, with embedded audio and EDH as warnings; exact locations only with `VPID_Code`, rising through each frame; a packet for every frame or field; send times inside the window of the CTM or LLTM that `TM` names |
| ST 2110-41, -43 | Fast metadata: the marker bit at 0, a packet at least every 500 ms, and Data Item Packages that fill each payload with no Data Item Length of 0. Timed text: the RFC 8759 payload header, one timestamp a document with the marker on its last packet and another for the next, keep-alives only between documents and with the marker set, and the documents a lost packet takes with it |
| PTP | Each domain kept apart by its number and sdoId (gPTP and AES67 on domain 0 are two), with ST 2059-2's checks only for its own profile over UDP; one grandmaster through the capture, one port announcing at a time, Announce and Sync rates to match `logMessageInterval`, and a Follow_Up for every two-step Sync and a Delay_Resp for every Delay_Req |
| ST 2059-2 across messages | The same Announce interval on every port of a domain (§6.5.2), `logMinDelayReqInterval` within `logSyncInterval` to five more (§6.5.3), Announce, Sync, Follow_Up and the synchronization metadata all multicast or all unicast and each Delay_Resp in its Delay_Req's mode (§6.10), the synchronization metadata TLV about once a second (§6.12), and changes of its locking status and of the grandmaster's quality as notes |
| SDP against PTP | A `ts-refclk` grandmaster or domain the Announce messages do not give, and a `traceable` clock whose grandmaster is not on the PTP timescale, traceable and within 250 ns (ST 2110-10 §8.2, RP 2110-25 §4.1) |
| ST 2022-7 | For each `DUP` group: the packet time differential and Table 1 class, merged loss for each second, and when a leg went and came back (Annex B) |

It follows RP 2110-25:2023 for what it measures, with ST 2110-21:2022 for the models and EBU Tech 3337 for TS-DF. It gives both of RP 2110-25 Annex A's ways to model the virtual receiver buffer, event history and residence time, and names them in `--format json`.

The payload checks of ST 2110-31, -40, -41 and -43 need the stream's SDP file. The ANC send window is widened to hold any T_EPO, since the exact one needs the line timing of an SDI format the SDP file does not give, and it is checked only against its late end when `TROFF` moves the frame start. It checks the CRC of professional channel status only, and takes a CRC of 0 for a minimum implementation that sends none. It leaves out the ST 2110-41 network compatibility model.

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
    rtp_offset: 0,
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

To add an SDP rule, add it to the catalogue in `crates/sdp/src/rules.rs`, raise it from the check in `crates/sdp/src/lint/`, and add a case to `crates/sdp/tests/rules.rs`. A registry rule goes in `crates/nmos/src/rules.rs`, is raised from `crates/nmos/src/check.rs`, and needs a case in `crates/nmos/tests/checks.rs`. A PTP rule goes in `crates/ptp/src/rules.rs`, is raised from `crates/ptp/src/check.rs`, and needs a case in `crates/ptp/tests/decode.rs`. A capture rule goes in `crates/pcap/src/rules.rs`, is raised from the flow, video, audio, data or PTP modules beside it, and needs a capture that raises it in `crates/pcap/tests/captures.rs`. A test fails for any rule without one. Then regenerate the docs, which another test compares:

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
