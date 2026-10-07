#!/usr/bin/env python3
"""Try stream discovery on this machine alone, with no ST 2110 equipment.

    python3 scripts/try-discovery.py                      # show what it finds
    python3 scripts/try-discovery.py --check              # fail unless it finds them all
    python3 scripts/try-discovery.py --st2110 PATH        # use an st2110 already built

It stands in for two devices, through the machine's own network services:

- an NMOS Node: the test facility's Camera 1, its Node API served over HTTP on a
  free port and advertised as _nmos-node._tcp by the system's multicast DNS
  responder, with dns-sd on macOS or avahi-publish on Linux. Nothing registers it
  anywhere, so st2110 reads its two Senders peer to peer;
- an AES67-style sender: `st2110 send audio --sap`, a tone that it announces by SAP,
  with a multicast time to live of 1 so that it stays on the local link.

Then it runs `st2110 discover`, which should list Camera 1's two streams and the
tone. The first run on macOS 15 may ask whether Terminal may find devices on the
local network: allow it, or nothing arrives.

Uses nothing but the Python standard library, cargo, and the responder's tool.
"""

import argparse
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACILITY = os.path.join(ROOT, "crates", "nmos", "tests", "fixtures", "facility.json")
TONE = "Discovery test tone"
NODE = "Camera 1"
LOOK = 8


def camera_node(host, path):
    """Camera 1's Node API, with its SDP files at /sdp/<id>: the status and body."""
    facility = json.load(open(FACILITY))
    node = facility["nodes"][0]
    device = next(d for d in facility["devices"] if d["node_id"] == node["id"])
    device["controls"] = [{"type": "urn:x-nmos:control:sr-ctrl/v1.1", "href": f"http://{host}/x-nmos/connection/v1.1/"}]
    mine = lambda collection: [r for r in facility[collection] if r.get("device_id") == device["id"]]
    senders = mine("senders")
    for sender in senders:
        sender["manifest_href"] = f"http://{host}/sdp/{sender['id']}"
    routes = {
        "/x-nmos/node/": ["v1.3/"],
        "/x-nmos/node/v1.3/self/": node,
        "/x-nmos/node/v1.3/devices/": [device],
        "/x-nmos/node/v1.3/sources/": mine("sources"),
        "/x-nmos/node/v1.3/flows/": mine("flows"),
        "/x-nmos/node/v1.3/senders/": senders,
        "/x-nmos/node/v1.3/receivers/": mine("receivers"),
    }
    if path in routes:
        return 200, "application/json", json.dumps(routes[path])
    if path.startswith("/sdp/"):
        manifest = facility["manifests"].get(path[len("/sdp/"):])
        if manifest:
            return 200, "application/sdp", manifest["sdp"]
    return 404, "text/plain", "not found"


class NodeApi(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status, kind, body = camera_node(self.headers.get("Host", "127.0.0.1"), self.path.split("?")[0])
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def advertise(port):
    """Advertises the Node API by the system's multicast DNS responder."""
    txt = ["api_proto=http", "api_ver=v1.3", "api_auth=false"]
    if shutil.which("dns-sd"):
        command = ["dns-sd", "-R", NODE, "_nmos-node._tcp", "local", str(port), *txt]
    elif shutil.which("avahi-publish"):
        command = ["avahi-publish", "-s", NODE, "_nmos-node._tcp", str(port), *txt]
    else:
        sys.exit("error: no dns-sd (macOS) or avahi-publish (Linux, in avahi-utils) to advertise the Node with")
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail unless it finds every stream")
    parser.add_argument("--st2110", help="the st2110 binary to use, rather than building it")
    args = parser.parse_args()
    st2110 = args.st2110
    if not st2110:
        print("Building st2110...", flush=True)
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "st2110-cli"], cwd=ROOT, check=True)
        st2110 = os.path.join(ROOT, "target", "release", "st2110")

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), NodeApi)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    advertiser = advertise(port)
    print(f"Serving {NODE}'s Node API on port {port}, and advertising it as _nmos-node._tcp", flush=True)
    discover = subprocess.Popen(
        [st2110, "discover", "--duration", str(LOOK), "--format", "json"], stdout=subprocess.PIPE, text=True
    )
    # The tone starts once discover is listening, as its first announcement goes at once.
    time.sleep(1)
    print("Sending a tone and announcing it by SAP", flush=True)
    sender = subprocess.Popen(
        [st2110, "send", "audio", "--to", "239.10.1.2:5004", "--ttl", "1", "--clock", "traceable", "--sap",
         "--name", TONE, "--duration", str(LOOK + 5)],
        stdout=subprocess.DEVNULL,
    )
    try:
        out, _ = discover.communicate(timeout=LOOK + 30)
    finally:
        for process in (sender, advertiser):
            process.terminate()
            process.wait()
        server.shutdown()
    found = json.loads(out)
    for stream in found["streams"]:
        by = "; ".join(describe(o) for o in stream["by"])
        print(f"  {stream['name']}: found by {by}")
    for note in found["notes"]:
        print(f"  note: {note}")
    names = {s["name"] for s in found["streams"]}
    wanted = {"CAM 1 video", "CAM 1 audio", TONE}
    missing = sorted(wanted - names)
    if missing:
        print(f"Not found: {', '.join(missing)}")
        if args.check:
            print(json.dumps(found, indent=2))
            sys.exit(1)
    else:
        print("Found all three: two NMOS Senders peer to peer, and one stream announced by SAP.")


def describe(origin):
    if origin["by"] == "sap":
        return f"SAP from {origin['announcer']}"
    return f"NMOS Node {origin.get('node') or origin['api']}"


if __name__ == "__main__":
    main()
