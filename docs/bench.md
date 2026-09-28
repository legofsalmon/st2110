# Bench test

Everything here has been tested against fixtures written from the standards, and
the sender and receiver against each other. None of it has yet met another maker's
equipment. This is the plan for the first bench: two Blackmagic converters, a switch,
a grandmaster and a Mac, which between them make a real sender, receiver, NMOS Node
and PTP follower. It says what to get, how to set it up, and the checks in the order
to run them, with what each one settles and what to keep from it.

## What it settles

| Question | Check |
|---|---|
| Do the PTP checks read a real ST 2059-2 grandmaster and its followers fairly? | [2](#2-the-clock) |
| Does `st2110 nmos` read a real IS-04 v1.3.2 Node, and judge its Senders' SDP files fairly? | [3](#3-the-registry), [4](#4-the-sdp-files) |
| Does `st2110 connect` switch a real IS-05 v1.1.2 Receiver, alone and in a salvo? | [5](#5-routing) |
| Does `st2110 receive` take a real narrow sender's video, and Level C audio at 8000 packets a second, on macOS? Does `st2110 pcap` measure them? | [6](#6-the-converters-streams-on-the-mac) |
| Does a real receiver take what `st2110 send` and vizz send: the SDP file, the packing, the pacing and the clock? | [7](#7-the-macs-streams-on-the-converters), [8](#8-vizz) |
| Does crewbox read the registry and judge the clock on real equipment? | [9](#9-crewbox) |

## The kit

| What | For | Price |
|---|---|---|
| Blackmagic 2110 IP Converter 3x3G | Three SDI inputs and three SDI outputs: senders and receivers of ST 2110-20 video, -30 audio and -40 ancillary data. One NMOS Node, and a PTP port that can follow or lead. | $675 |
| Blackmagic 2110 IP SDI to HDMI 12G | A receiver you can watch on an HDMI screen, and a second Node. | $585 |
| A managed switch | Three 10GBASE-T ports, and IGMPv3 snooping with a querier. Better still if it is an ST 2059-2 boundary clock, as the Netgear M4350 is with its "Audio Video SMPTE" profile. | |
| A grandmaster | A Meinberg microSync Broadcast, or another ST 2059-2 grandmaster. Without one, a converter can lead ([check 2](#2-the-clock)). | |
| The Mac | A 10 GbE port for video: a Mac Studio, a Mac mini with 10 Gb Ethernet, or a Thunderbolt 10 GbE adapter. On 1 GbE, everything but video works. | |
| An SDI source | A camera or player with a 3G-SDI output, set to 1080p50 or 720p50. Without one, [check 7](#7-the-macs-streams-on-the-converters) makes one. | |
| An HDMI screen, Cat 6a leads and BNC leads | | |

By Blackmagic's specifications and prices as of 27 September 2026:

- Both converters have 10GBASE-T ports (RJ45, which also run at 1 Gb/s).
- They implement ST 2110-20, -21, -30 and -40, ST 2059-2, NMOS IS-04 v1.3.2 and IS-05 v1.1.2.
- Their senders are narrow (`2110TPN`), and their receivers take wide senders too, as `st2110 send` and vizz are.
- Their audio is Level C.

Video needs the 10 GbE port. 1080p50 at 10 bits 4:2:2 is 2.1 Gb/s, and even 720p50,
at 0.94 Gb/s of RTP, fills a 1 GbE port.

## The network

One VLAN on the switch carries everything: the streams, PTP and NMOS. These are the
addresses the checks below use; any will do.

| Address | What |
|---|---|
| 10.21.10.1 | the grandmaster |
| 10.21.10.2 | the switch |
| 10.21.10.11 | the 3x3G |
| 10.21.10.12 | the SDI to HDMI 12G |
| 10.21.10.100 | the Mac's 10 GbE port, set by hand with no router, so that its internet stays on Wi-Fi |
| 239.21.10.1 to .99 | the converters' streams, set in each one's Multicast Address settings |
| 239.21.10.101 to .199 | the Mac's streams |

On the switch:

- **IGMP snooping** on the VLAN, IGMPv3, with the switch as the querier, and multicast that nobody has joined dropped rather than flooded. Without a querier some switches stop forwarding a stream a few minutes after it was joined, and others send every stream to every port. Either spoils a bench, and flooding puts 2 Gb/s of video on any 1 GbE port.
- **Energy Efficient Ethernet off** on the bench ports: its sleep states add delay variation to PTP.
- **PTP:** an ST 2059-2 boundary clock on domain 127, if the switch can be one. Otherwise PTP crosses it as multicast, which [check 2](#2-the-clock) joins.

Every PTP device goes on domain 127, ST 2059-2's default, with the same Announce
interval and timeout. On each converter, in Blackmagic's setup utility, set the
Domain Number to 127 and turn on Follower Only Mode, so that it never contends to lead.

## Before the bench

On the Mac, with Rust, Docker and jq installed:

```console
$ git clone https://github.com/legofsalmon/st2110 && cd st2110
$ cargo install --path crates/cli --locked
$ sudo sysctl -w kern.ipc.maxsockbuf=16777216
```

The last line lets `st2110 receive` have an 8 MiB socket buffer; it says when it has
less than 4 MiB. CI builds and tests st2110 on macOS as well as Linux, sending and
receiving over the loopback interface. [Check 6](#6-the-converters-streams-on-the-mac)
is the first time it joins a multicast group on a Mac's network port.

- Update both converters with Blackmagic's utility, and write down the firmware versions: every result is for that firmware.
- If macOS asks whether `st2110` may accept incoming network connections, allow it.
- On macOS 15 or later, if nothing goes out or nothing arrives, check that the terminal app has Local Network access (System Settings → Privacy & Security → Local Network).

## The checks

Run them in this order: each needs the ones before it. For every error and warning,
decide whose it is:

- **the equipment's**, breaking the clause the finding cites (`st2110 rules RULE` shows it);
- **or the checks'**, misreading the clause or the equipment.

Write down which, and why. A finding that is the checks' is a bug, and this bench's
files are its test. One that is the equipment's is what crewbox will report on a real rig.

### 1. Wiring

- Connect the converters, the grandmaster and the Mac to the switch.
- Put the SDI source into the 3x3G's first input, and the HDMI screen on the other converter.
- Give each device its address. On the Mac: System Settings → Network → the 10 GbE port → Details → TCP/IP, Manually, with no router.
- `ping` each device from the Mac, and check that the switch shows 10 Gb/s links.
- `route get 10.21.10.11 | grep interface` names the Mac's 10 GbE port, `en7` in the commands below.
- Set the SDI source to a progressive format: `st2110 receive` does not take interlaced video yet.

### 2. The clock

A snooping switch forwards PTP only to ports that have joined its group, 224.0.1.129,
and tcpdump joins nothing. So join it for the capture:

```console
$ python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton("224.0.1.129")+socket.inet_aton(sys.argv[1])); time.sleep(3600)' 10.21.10.100 &
$ sudo tcpdump -i en7 -w ptp.pcap -G 60 -W 1 'udp port 319 or udp port 320'
$ st2110 pcap ptp.pcap
```

Leave the join running through [check 6](#6-the-converters-streams-on-the-mac);
`kill %1` ends it. A boundary clock's own messages need no join, but joining does no
harm.

Look for:

- one grandmaster on domain 127, announced by one port: a converter that announces too has Follower Only Mode off;
- Announce and Sync messages at rates the profile allows, and a Follow_Up for each Sync when the grandmaster is two-step;
- Delay_Req messages from both converters, each answered with a Delay_Resp, unless the switch is a boundary clock, which keeps each port's exchange to that port;
- a UTC offset of 37 s, marked valid;
- synchronization metadata, if the grandmaster sends it;
- both converters showing PTP Lock in the setup utility.

A forum post in 2025 reported a 3x3G that would not lock as a follower, where other
makers' devices on the same network did. If that happens, note the firmware.

Keep the grandmaster's identity from the report, such as `08-00-11-FF-FE-21-E1-B0`:
checks 7 and 8 name it.

**Without a grandmaster**, let the 3x3G lead:

- On the 3x3G, turn Master on and Follower Only Mode off, and give it the best (lowest) Priority.
- Leave Follower Only Mode on for the other converter.
- Expect warnings that it runs free.
- Its time may be nowhere near TAI, which matters in checks 6 to 8.
- Run this check again when a grandmaster arrives.

**Keep:** `ptp.pcap`, a few hundred kilobytes.

### 3. The registry

Run nmos-cpp's registry on the Mac, from the image its builders publish:

```console
$ docker run -d --name nmos-registry -p 8010:8010 rhastie/nmos-cpp:latest
```

Its DNS-SD announcements do not leave Docker's virtual machine, so the converters
cannot find it by themselves. Point both at it by address, in their NMOS Registry
setting. On Linux, the image runs with `--net=host --privileged` instead, which puts
its announcements on the network. Then:

```console
$ st2110 nmos http://10.21.10.100:8010 --save registry.json
```

Look for:

- the converters' two Nodes: the 3x3G's Senders and Receivers, and the other converter's Receivers, each Sender with its Flow and Source;
- both Nodes' PTP clocks locked to the grandmaster;
- every Sender's SDP file fetched and checked;
- no finding that the registry itself causes: a fault in nmos-cpp is not the converters'.

Where this disagrees with a converter, the AMWA NMOS Testing Tool
(<https://github.com/AMWA-TV/nmos-testing>) is an independent judge. Its IS-05-01 suite
tests a converter's Connection API by its URL, and IS-04-02 tests the registry.

**Keep:** `registry.json`, which holds every Sender's SDP file too. Before it is
committed, check that its labels and descriptions carry nothing private.

### 4. The SDP files

Write each Sender's SDP file out of the snapshot, named by its label:

```console
$ mkdir -p sdp
$ jq -r '.senders[] | [.id, (.label | gsub("[^A-Za-z0-9._-]+"; "-"))] | @tsv' registry.json |
    while IFS=$'\t' read -r id name; do
      jq -j --arg id "$id" '.manifests[$id].sdp // empty' registry.json > "sdp/$name-${id:0:8}.sdp"
    done
$ find sdp -empty -delete
$ st2110 lint sdp/*.sdp
```

`st2110 nmos` has already checked them. This gives each file on its own, for checks 6
and 9 and as fixtures. Beyond the findings, look at what Blackmagic's specifications
lead one to expect:

- **Video:** `TP=2110TPN`, `a=mediaclk:direct=0`, an `a=ts-refclk` that names the grandmaster on domain 127, and an `a=source-filter`.
- **Audio:** `a=ptime:0.125`, as Level C allows, and its channel order.
- **Ancillary data:** the DID and SDID it carries.

**Keep:** `sdp/`.

### 5. Routing

```console
$ st2110 connect http://10.21.10.100:8010
$ st2110 connect http://10.21.10.100:8010 --receiver "HDMI VIDEO RECEIVER" --sender "3X3G VIDEO 1" --dry-run
$ st2110 connect http://10.21.10.100:8010 --receiver "HDMI VIDEO RECEIVER" --sender "3X3G VIDEO 1"
```

The first command lists which Senders each Receiver can take; use its names, or the
start of an id, in place of the capitals.

- The SDI source's picture appears on the HDMI screen. The command reports the connection done, on the Receiver's `/active` endpoint and in the registry.
- A salvo, `--salvo` with a file like the README's, switches the HDMI converter's video and audio together at one PTP time, worked out from the Mac's clock. That time means something to the converters when the grandmaster keeps TAI from GNSS. With a converter leading, add `--in 2`, which has each converter switch 2 s after it has the request.
- `--disconnect` takes the picture away.
- The converters serve IS-05 v1.1.2. When one refuses a request, the report shows its answer: decide whether the request or the converter is wrong.

**Keep:** what each command printed.

### 6. The converter's streams on the Mac

This needs the 10 GbE port. Receive the 3x3G's first video and audio streams, and
capture them at the same time. `sdp/VIDEO.sdp` and `sdp/AUDIO.sdp` stand for their files
from check 4, and the capture filter takes the groups those files give:

```console
$ sudo -v
$ sudo tcpdump -i en7 -w bm.pcap -G 10 -W 1 'dst 239.21.10.1 or dst 239.21.10.11 or udp port 319 or udp port 320' &
$ st2110 receive sdp/VIDEO.sdp --interface 10.21.10.100 --duration 10 --png bm.png &
$ st2110 receive sdp/AUDIO.sdp --interface 10.21.10.100 --duration 10 --wav bm.wav
$ wait
$ st2110 pcap bm.pcap --sdp sdp/VIDEO.sdp --sdp sdp/AUDIO.sdp
```

Look for:

- **From `receive`:** both streams arrived whole, `bm.png` is the SDI source's picture, and `bm.wav` its sound. Level C audio, at 8000 packets a second, is the hard case for a software receiver.
- **From `pcap`:** each flow matched to its SDP file, with nothing lost, and the video's packets a frame and the audio's packet interval as the SDP files give them.
- **From tcpdump:** when it stops, it must report 0 packets dropped by the kernel, or the capture lost what the network delivered. If it dropped some, raise macOS's limit on capture buffers (`sudo sysctl -w debug.bpf_maxbufsize=16777216`) and give tcpdump `-B 16384`, or capture the audio alone.

What the Mac cannot measure:

- Its timestamps come from its system clock, to the microsecond, kept to UTC by NTP.
- So the latency from RTP timestamps, the first packet time and the virtual receiver buffer are all out by the Mac's clock error: milliseconds at best, and anything at all when a converter leads PTP.
- CINST counts the packets one interrupt delivers together as a burst, so it overstates.
- Treat the ST 2110-21 figures as a rough upper bound. The loss, sequence, RTP, payload and frame checks are exact.
- Measuring a narrow sender properly needs a capture timestamped on PTP time by the network card: Linux, ptp4l and `tcpdump -j adapter_unsynced`, on a card like the Intel E810 that the MTL step is waiting for.

**Keep:** `bm.png`, `bm.wav`, the reports, and a few seconds' capture of the audio
alone, which is small: 16 channels of Level C are about 3 MB a second. A second of
1080p50 is about 270 MB, so keep its report, not its capture.

### 7. The Mac's streams on the converters

This needs the 10 GbE port too. Send colour bars, and route the HDMI converter to
them. GRANDMASTER stands for the identity check 2 reported:

```console
$ st2110 send video 720p50 --to 239.21.10.101:5004 --interface 10.21.10.100 --clock GRANDMASTER:127 --sdp bars.sdp --duration 120 &
$ sleep 1; st2110 connect http://10.21.10.100:8010 --receiver "HDMI VIDEO RECEIVER" --sdp bars.sdp
```

Look for:

- **The bars:** EBU bars on the HDMI screen, with the white box stepping steadily along the black strip beneath them. A stutter, a frozen frame or black is the finding, and the converter's setup utility may say why.
- **1080p50 next,** at 2.1 Gb/s. On a quiet Linux machine the sender keeps a wide sender's pace at HD, and this is its first run on macOS.
- **Audio last,** to the HDMI converter's audio Receiver, in 1 ms packets and then in Level C's 125 µs:

  ```console
  $ st2110 send audio --to 239.21.10.111:5004 --interface 10.21.10.100 --clock GRANDMASTER:127 --sdp tone.sdp --duration 120 &
  $ sleep 1; st2110 connect http://10.21.10.100:8010 --receiver "HDMI AUDIO RECEIVER" --sdp tone.sdp
  ```

  Then again with `--packet-time 0.125`.

`--clock GRANDMASTER:127` says that the Mac's clock follows that grandmaster. It does
not quite:

- macOS keeps UTC by NTP: within milliseconds of PTP time when the grandmaster is on GNSS, and nowhere near it when a converter leads.
- A receiver that plays out by RTP timestamp may take the stream, drop it, or stutter because of that.
- If the screen shows nothing, try `--clock localmac=$(ifconfig en7 | awk '/ether/ {print toupper($2)}' | tr : -)`, the Mac's MAC address written as SDP files write it. That says the stream follows no PTP clock. Note which of the two the converter takes.

**No SDI source?** Route a 3x3G Receiver to the bars, and loop that SDI output into one
of the 3x3G's SDI inputs with a BNC lead. That input's Sender then carries the bars as
the converter's own stream, for checks 4 to 6.

**Keep:** `bars.sdp`, `tone.sdp`, and what the screen showed (a phone video will do).

### 8. vizz

vizz sends its output as ST 2110-20 video through `st2110-media`. From a vizz checkout:

```console
$ cargo run --release -- --st2110 239.21.10.121:5004 --st2110-interface 10.21.10.100 --st2110-rate 50 \
    --st2110-clock GRANDMASTER:127 --st2110-sdp vizz.sdp --width 1280 --height 720
$ st2110 connect http://10.21.10.100:8010 --receiver "HDMI VIDEO RECEIVER" --sdp vizz.sdp
```

- vizz's picture should appear on the HDMI screen, steady at 50 frames a second, even while vizz is busy. When rendering falls behind, it repeats the last frame rather than stopping.
- Then try it at 1920×1080.

**Keep:** `vizz.sdp`, and what the screen showed.

### 9. crewbox

crewbox's box runs these same checks, built in as WebAssembly, on what it overhears
(crewbox's `docs/NETWATCH.md`). They reached crewbox's main branch on 28 September 2026,
so until a release carries them, run a box from a crewbox checkout. Point its media
watch at the bench port, and name the registry, whose own announcements stay inside
Docker:

```console
$ npm ci
$ CREWBOX_WATCH=1 CREWBOX_WATCH_IFACE=10.21.10.100 CREWBOX_NMOS_REGISTRY=http://10.21.10.100:8010 npm run dev
```

Look for:

- **The clock:** "Video clock (ST 2059-2)", on Admin → media and on the Network page's media card, names check 2's grandmaster, with what check 2 found.
- **The registry:** as an admin, Run deep probe on the Network page. It reads the registry and lists what check 3 found. That ticks the box crewbox's `docs/NETWORK_AUDIT.md` leaves open.
- **The tools:** on a phone, the Network page's Check an SDP file takes a file from check 4, and Check a capture takes the audio capture from check 6. Each should say what the command line said.
- **SAP:** "ST 2110 streams" lists streams announced over SAP. If it stays empty, the converters announce only through NMOS, which is worth knowing too.

## What to bring back

Put everything in one folder named for the date. Add the firmware versions, and the
converters' settings (screenshots of Blackmagic's utility will do).

| File | From | Becomes |
|---|---|---|
| `ptp.pcap` | check 2 | PTP fixtures as hex, beside `crates/ptp/tests/fixtures/grandmaster.hex` (`tshark -r ptp.pcap -Y "ptp && udp" -T fields -e udp.payload`), and a capture test |
| `registry.json` | check 3 | a registry fixture, beside `crates/nmos/tests/fixtures/facility.json` |
| `sdp/` | check 4 | SDP fixtures, in `crates/sdp/tests/fixtures` |
| the audio capture | check 6 | a capture fixture, for `pcap` and `receive` |
| `bm.png`, `bm.wav` and the reports | checks 5 to 9 | the record of what passed |

The next change turns them into fixtures, each with a test that pins what the checks
say about it. It also fixes whatever the bench showed to be the checks' fault.

## What this bench cannot test

- **ST 2110-21 timing to the microsecond:** see [check 6](#6-the-converters-streams-on-the-mac).
- **ST 2022-7:** these two converters have one port each. The 2110 IP SDI to HDMI 12G-10 ($1,125) has two.
- **UHD, and a narrow sender's pace, from the Mac:** they need MTL.
- **What the converters lack:** ST 2110-22 as JPEG XS, -31 (AES3), IS-07 events and IS-12 control. Their -22 codecs, IP10 and ProRes, are Blackmagic's own.
- **Interlaced and PsF video in `st2110 receive`:** it does not take them yet. `lint`, `nmos` and `pcap` do.
