#!/usr/bin/env python3
"""Check that the design system's copies in this repository are as its
scripts/sync.mjs vendored them, and say how to bring them up to date.

    python3 scripts/design-system.py --check   # fail if a copy was edited by hand
    python3 scripts/design-system.py --sync    # refill them from ../design-system

The design system (legofsalmon/design-system, private) gives the router page
its colours, inlined between /* ds:tokens:start */ and /* ds:tokens:end */,
and the viewer its tokens.rs. Each copy carries a hash of what it holds, so
a hand edit is caught here with nothing but the copy: that edit is a fix the
design-system repository should get, and the next sync would drop it.
Whether a copy is behind the design system needs a checkout of it beside
this one: --sync, then git diff.

Uses nothing but Python, so it adds no tool to the build.
"""

import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGES = [os.path.join("crates", "cli", "src", "router", "page.html")]
COPIES = [os.path.join("crates", "viewer", "src", "tokens.rs")]
BLOCK = re.compile(r"/\* ds:(tokens|base|components):start([^*]*)\*/\n?([\s\S]*?)/\* ds:\1:end \*/")
STAMP = re.compile(r"^(?:/\*|//) @letissier/design-system (\S+) · (\S+) · (sha256-[0-9a-f]{16}) · ")


def digest(text):
    return "sha256-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def problems():
    found = []
    for page in PAGES:
        with open(os.path.join(ROOT, page), encoding="utf-8") as f:
            text = f.read()
        blocks = list(BLOCK.finditer(text))
        if not blocks:
            found.append(f"{page}: no ds:tokens block")
        for m in blocks:
            declared = re.search(r"sha256-[0-9a-f]{16}", m.group(2))
            if not declared:
                found.append(f"{page} (ds:{m.group(1)}): never synced")
            elif digest(m.group(3)) != declared.group(0):
                found.append(f"{page} (ds:{m.group(1)}): edited by hand since it was synced")
    for copy in COPIES:
        with open(os.path.join(ROOT, copy), encoding="utf-8") as f:
            first, _, rest = f.read().partition("\n")
        m = STAMP.match(first)
        if not m:
            found.append(f"{copy}: not written by the design system's sync.mjs")
        elif digest(rest) != m.group(3):
            found.append(f"{copy}: edited by hand since it was vendored")
    return found


def sync():
    script = os.path.join(ROOT, "..", "design-system", "scripts", "sync.mjs")
    if not os.path.exists(script):
        sys.exit("design-system.py: needs a checkout of legofsalmon/design-system beside this one")
    for page in PAGES:
        subprocess.run(["node", script, "--inline", page], cwd=ROOT, check=True)
    dirs = sorted({os.path.dirname(c) for c in COPIES})
    for d in dirs:
        names = ",".join(os.path.basename(c) for c in COPIES if os.path.dirname(c) == d)
        subprocess.run(["node", script, "--to", d, "--files", names], cwd=ROOT, check=True)


def main():
    if "--sync" in sys.argv:
        sync()
        return 0
    if "--check" in sys.argv:
        found = problems()
        for p in found:
            print(p, file=sys.stderr)
        if not found:
            print("ok: the design system's copies are as they were vendored")
        return 1 if found else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
