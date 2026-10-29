# @letissier/design-system 0.11.0 · ds_check.py · sha256-91b9f16f492c9c34 · vendored by scripts/sync.mjs; change the design-system repo, not this copy
"""The design system's checker for an app without Node: the same checks as
scripts/ds-check.mjs, vendored into the app by scripts/sync.mjs and run from
its CI. Uses nothing but Python 3.8 or later, and no checkout of the design
system: the stamps carry what it checks against, and the published manifest
says what is current.

    python3 scripts/ds_check.py index.html
        every ds: block in index.html (and every copy in a directory named
        instead) is as it was vendored, and current or behind is said
    python3 scripts/ds_check.py index.html --reads static
        also: every var(--ds-*) read under static/ is one the tokens define
    --strict          fail when a copy is behind, not only warn
    --manifest URL    where the current manifest is (a URL or a file); else
                      ../design-system/dist/manifest.json if it is checked
                      out beside the app, else DS_MANIFEST, else the gallery
    --offline         do not fetch the manifest
    --sync            refill the copies from ../design-system first (needs Node)

A hand edit or an undefined var(--ds-*) always fails. Being behind is a
warning (a GitHub annotation in Actions) unless --strict. If the manifest
cannot be reached, it says so and does not fail.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request

MANIFEST_URL = "https://design-system-colly.vercel.app/manifest.json"
NAMES = ["tokens.css", "base.css", "components.css", "tokens.js", "tokens.d.ts", "tokens.rs",
         "icons.js", "icons.d.ts", "ds-check.mjs", "ds_check.py"]
STAMP = re.compile(r"^(?:/\*|//|#) @letissier/design-system (\S+) · (\S+) · (sha256-[0-9a-f]{16}) · ")
BLOCK = re.compile(r"/\* ds:(tokens|base|components):start([^*]*)\*/\r?\n?([\s\S]*?)/\* ds:\1:end \*/")
SHEET = {"tokens": "tokens.css", "base": "base.css", "components": "components.css"}
READ_EXT = re.compile(r"\.(css|scss|html|js|mjs|jsx|ts|tsx|svelte|vue)$")
SKIP_DIR = {"node_modules", ".git", "dist", "build", "target", ".next", "out", "coverage"}


def digest(text):
    # sync.mjs writes LF; a CRLF checkout of the same copy is not a hand edit
    return "sha256-" + hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:16]


def read(path, errors="strict"):
    with open(path, encoding="utf-8", errors=errors, newline="") as f:
        text = f.read()
    return text[1:] if text.startswith("\ufeff") else text


def compare(a, b):
    pa, pb = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
    return (pa > pb) - (pa < pb)


def vendored(paths):
    found, problems = [], []
    for path in paths:
        if not os.path.exists(path):
            problems.append(f"{path}: not found")
            continue
        before = len(found)
        is_dir = os.path.isdir(path)
        if is_dir:
            files = [os.path.join(path, f) for f in sorted(os.listdir(path)) if f in NAMES]
        else:
            files = [path]
        for file in files:
            text = read(file)
            first, _, rest = text.partition("\n")
            m = STAMP.match(first)
            if m:
                if os.path.basename(file) in NAMES and m.group(2) != os.path.basename(file):
                    problems.append(f"{file}: its stamp says it is {m.group(2)}")
                found.append({"where": file, "name": m.group(2), "version": m.group(1), "hash": m.group(3), "payload": rest})
                continue
            if is_dir:
                # a copy with its stamp taken off would otherwise drop out unchecked
                problems.append(f"{file}: not written by the design system's sync.mjs (no stamp on its first line)")
                continue
            for sheet in SHEET:
                starts = text.count(f"/* ds:{sheet}:start")
                ends = text.count(f"/* ds:{sheet}:end */")
                blocks = sum(1 for b in BLOCK.finditer(text) if b.group(1) == sheet)
                if starts != blocks or ends != blocks:
                    problems.append(f"{file}: the ds:{sheet} start and end markers do not pair")
            for b in BLOCK.finditer(text):
                declared = re.search(r"@letissier/design-system (\S+) (sha256-[0-9a-f]{16})", b.group(2))
                found.append({
                    "where": f"{file} (ds:{b.group(1)})",
                    "name": SHEET[b.group(1)],
                    "version": declared.group(1) if declared else None,
                    "hash": declared.group(2) if declared else None,
                    "payload": b.group(3),
                })
        if len(found) == before:
            problems.append(f"{path}: nothing vendored from the design system here")
    return found, problems


def edits(found):
    out = []
    for c in found:
        if not c["hash"]:
            out.append(f"{c['where']}: never synced — run scripts/sync.mjs --inline")
        elif digest(c["payload"]) != c["hash"]:
            out.append(f"{c['where']}: edited by hand since it was vendored; take the change to the design-system repo")
    return out


def undefined_reads(found, reads):
    sheets = [c for c in found if c["name"] == "tokens.css"]
    if not sheets:
        return ["--reads needs a vendored tokens.css or ds:tokens block to compare with"] if reads else []
    defined = {n for c in sheets for n in re.findall(r"(--ds-[a-z0-9-]+)\s*:", c["payload"])}
    problems = []

    def visit(path):
        if not os.path.exists(path):
            return  # a dangling link
        if os.path.isdir(path):
            if os.path.basename(path) in SKIP_DIR:
                return
            for f in sorted(os.listdir(path)):
                visit(os.path.join(path, f))
            return
        if not READ_EXT.search(path):
            return
        text = read(path, errors="replace")
        if STAMP.match(text.split("\n", 1)[0]):
            return
        own = set(re.findall(r"(--ds-[a-z0-9-]+)\s*:", text))
        for n in sorted(set(re.findall(r"var\(\s*(--ds-[a-z0-9-]+)", text)) - defined - own):
            problems.append(f"{path}: reads {n}, which the design system does not define")

    for r in reads:
        if os.path.exists(r):
            visit(r)
        else:
            problems.append(f"{r}: not found")
    return problems


def behind(found, manifest):
    late, ahead = [], []
    for c in found:
        current = (manifest.get("files") or {}).get(c["name"])
        if not current or not c["hash"] or c["hash"] == current["hash"]:
            continue
        if c["version"] and re.match(r"^\d+\.\d+\.\d+$", c["version"]) and compare(c["version"], manifest["version"]) > 0:
            ahead.append(f"{c['where']}: {c['version']}, ahead of the published {manifest['version']}")
        else:
            late.append(f"{c['where']}: {c['version'] or 'unversioned'}, behind {manifest['version']}")
    return late, ahead


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def load_manifest(where):
    try:
        if not re.match(r"^https?:", where):
            return json.loads(read(where))
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(where, timeout=10) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001 — any failure means "not known", never a crash
        return {"error": f"{where}: {e}"}


def sync(paths, cwd):
    script = os.path.join(cwd, "..", "design-system", "scripts", "sync.mjs")
    if not os.path.exists(script):
        sys.exit("--sync needs a checkout of legofsalmon/design-system beside this repository")
    for path in paths:
        if os.path.isdir(path):
            files = [f for f in os.listdir(path) if f in NAMES]
            subprocess.run(["node", script, "--to", path, "--files", ",".join(files)], check=True)
        elif re.search(r"ds:(tokens|base|components):start", read(path)):
            subprocess.run(["node", script, "--inline", path], check=True)
        else:
            subprocess.run(["node", script, "--to", os.path.dirname(path) or ".", "--files", os.path.basename(path)], check=True)


def main(argv, cwd=None, env=None):
    cwd = cwd or os.getcwd()
    env = os.environ if env is None else env
    flags = {a for a in argv if a.startswith("--")}
    paths, reads = [], []
    into = paths
    manifest_arg = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--reads":
            into = reads
        elif a == "--manifest":
            manifest_arg = argv[i + 1] if i + 1 < len(argv) else None
            i += 1
        elif not a.startswith("--"):
            into.append(a)
        i += 1
    if not paths:
        print("ds_check: name the vendored copies, e.g. python3 scripts/ds_check.py index.html", file=sys.stderr)
        return 2
    if "--sync" in flags:
        sync(paths, cwd)

    found, problems = vendored(paths)
    problems += edits(found) + undefined_reads(found, reads)

    notes, late = [], []
    if "--offline" not in flags:
        beside = os.path.join(cwd, "..", "design-system", "dist", "manifest.json")
        where = manifest_arg or (beside if os.path.exists(beside) else env.get("DS_MANIFEST") or MANIFEST_URL)
        manifest = load_manifest(where)
        if "error" in manifest:
            notes.append(f"could not read the manifest ({manifest['error']}), so whether the copies are current is not known")
        else:
            late, ahead = behind(found, manifest)
            notes += ahead
            if not late and not ahead:
                notes.append(f"current with design-system {manifest['version']}")

    gh = env.get("GITHUB_ACTIONS") == "true"
    for p in problems:
        print(f"::error::{p}" if gh else p, file=sys.stderr)
    for l in late:
        print(f"::warning::{l} — run the sync" if gh else f"{l} — run the sync", file=sys.stderr)
    for n in notes:
        print(f"ds-check: {n}")
    if not problems:
        shown = ", ".join(os.path.relpath(p, cwd) for p in paths)
        print(f"ok — {len(found)} cop{'y' if len(found) == 1 else 'ies'} as vendored, in {shown}")
    return 1 if problems or (late and "--strict" in flags) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
