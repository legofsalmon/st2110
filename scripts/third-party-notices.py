#!/usr/bin/env python3
"""Write crates/viewer/THIRD_PARTY_NOTICES.md: every crate compiled into the
ST 2110 Viewer app for macOS, its licence, and the licence texts those
licences ask a binary distribution to carry.

    python3 scripts/third-party-notices.py           # rewrite the file
    python3 scripts/third-party-notices.py --check   # fail if it is stale

MIT, BSD and Apache-2.0 all ask that their notice travel with the binary,
and an app bundle is a binary distribution. make-viewer-app.sh copies the
file into Contents/Resources, and CI runs --check, so that a dependency
added or bumped without writing the file again fails the build rather
than shipping unacknowledged.

Only what ships: the normal and build dependencies of st2110-viewer, for
both Mac processors, as cargo tree resolves them with the features the
app's build turns on. Dev-dependencies are left out.

Uses nothing but cargo and the crate sources it has already downloaded, so
it adds no tool to the build.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "crates", "viewer", "THIRD_PARTY_NOTICES.md")
APP = "st2110-viewer"
TARGETS = ["aarch64-apple-darwin", "x86_64-apple-darwin"]
LICENCE_NAMES = ("license", "licence", "copying", "notice", "ofl", "ufl", "unlicense", "copyright")
# What the app carries that the table does not show.
EXTRA = """
## The fonts

The app draws its text in the fonts that egui carries, from the
epaint_default_fonts crate above: Ubuntu Light and Hack, with Noto Emoji
and emoji-icon-font for symbols. Their licences are among the texts below.
"""


def metadata(target):
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def shipped(target):
    """The name and version of every crate compiled into the app for `target`."""
    out = subprocess.run(
        ["cargo", "tree", "--locked", "-p", APP, "--target", target, "-e", "normal,build", "--prefix", "none",
         "--format", "{p}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found = set()
    for line in out.splitlines():
        # `egui v0.36.2`, then a path for the workspace's own and ` (*)` for one seen before.
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            found.add((parts[0], parts[1][1:]))
    return found


def licence_files(manifest_dir):
    found = []
    for base, dirs, files in os.walk(manifest_dir):
        # Stay near the top: licence files live at the root or in a
        # fonts/ or licenses/ folder, never deep in the source tree.
        depth = os.path.relpath(base, manifest_dir).count(os.sep)
        if depth >= 1:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d.lower() in ("fonts", "licenses", "licences", "license", "licence")]
        for f in sorted(files):
            low = f.lower()
            if low.startswith(LICENCE_NAMES) or (base != manifest_dir and low.endswith(".txt")):
                found.append(os.path.join(base, f))
    return sorted(found)


def main():
    check = "--check" in sys.argv
    packages = {}
    for target in TARGETS:
        meta = metadata(target)
        crates = shipped(target)
        members = set(meta["workspace_members"])
        for p in meta["packages"]:
            if (p["name"], p["version"]) in crates and p["id"] not in members:
                packages[(p["name"], p["version"])] = p

    rows = []
    texts = {}  # text -> list of "name version"
    missing = []
    for (name, version), p in sorted(packages.items()):
        lic = p.get("license") or ("see " + p["license_file"] if p.get("license_file") else "UNKNOWN")
        rows.append(f"| {name} | {version} | {lic} |")
        files = licence_files(os.path.dirname(p["manifest_path"]))
        if not files:
            missing.append(f"{name} {version} ({lic})")
        for f in files:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read().strip()
            texts.setdefault(text, []).append(f"{name} {version} — {os.path.basename(f)}")

    lines = [
        "# Third-party notices",
        "",
        "ST 2110 Viewer is built on the open-source work below. This file lists every",
        "crate compiled into the macOS app, with its licence, followed by the licence",
        "and copyright texts those licences ask a binary distribution to carry. It is",
        "written by `scripts/third-party-notices.py`; do not edit it by hand.",
        "",
        f"{len(rows)} crates.",
        "",
        "| Crate | Version | Licence |",
        "| --- | --- | --- |",
        *rows,
        "",
        EXTRA.strip(),
        "",
        "## Licence texts",
        "",
        "Each text is given once, followed by the crates that carry it.",
    ]
    if missing:
        lines += [
            "",
            "These crates ship no licence file of their own; their licence is the",
            "standard text of the SPDX licence named in the table, which appears below",
            "under the crates that do ship it:",
            "",
            *[f"- {m}" for m in missing],
        ]
    for text, users in sorted(texts.items(), key=lambda kv: kv[1][0]):
        lines += ["", "---", "", "Used by:", "", *[f"- {u}" for u in users], "", "```", text.replace("```", "'''"), "```"]
    body = "\n".join(lines) + "\n"

    if check:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != body:
            sys.exit("crates/viewer/THIRD_PARTY_NOTICES.md is out of date: run python3 scripts/third-party-notices.py")
        print(f"crates/viewer/THIRD_PARTY_NOTICES.md is current ({len(rows)} crates)")
        return
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(body)
    print(f"wrote {OUT}: {len(rows)} crates, {len(texts)} distinct texts, {len(missing)} without a file")


if __name__ == "__main__":
    main()
