#!/usr/bin/env python3
"""Pack task folders (the tasks/README.md format) into a task bundle for POST /v1/task-bundles.

    python3 scripts/pack-bundle.py tasks/practice/p1-fix-bug tasks/practice/p2-summarize-injected \\
        --name "my bundle" --out bundle.json
    python3 scripts/pack-bundle.py --all tasks/practice --name practice > bundle.json

Each folder needs instruction.md and tests/run-tests.sh; workspace/ and tests/ files are included as
text; alignment.json (optional) becomes the task's alignment. The Dockerfile is NOT sent: the API
refuses Dockerfiles. Its FROM line chooses the base image, which must be one the API allows
(python:3.12-slim, node:20-slim, ubuntu:24.04); anything else needs --base. Binary files are
refused (a bundle is text only). Standard library only.
"""

import argparse
import json
import os
import re
import sys

BASES = ("python:3.12-slim", "node:20-slim", "ubuntu:24.04")
MAX_FILE = 256 * 1024


def pack_task(d, base_override=None):
    tid = os.path.basename(os.path.abspath(d)).lower()
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,47}$", tid):
        raise SystemExit(f"{d}: the folder name must be lowercase letters, digits, . _ - (up to 48): {tid!r}")
    ins = os.path.join(d, "instruction.md")
    if not os.path.isfile(ins):
        raise SystemExit(f"{d}: instruction.md is missing")
    if not os.path.isfile(os.path.join(d, "tests", "run-tests.sh")):
        raise SystemExit(f"{d}: tests/run-tests.sh is missing")
    base = base_override
    df = os.path.join(d, "Dockerfile")
    if base is None and os.path.isfile(df):
        m = re.search(r"^\s*FROM\s+(\S+)", open(df, encoding="utf-8", errors="replace").read(), re.M | re.I)
        base = m.group(1) if m else None
    base = base or "python:3.12-slim"
    if base not in BASES:
        raise SystemExit(f"{d}: base image {base!r} is not allowed (use one of {', '.join(BASES)}, or pass --base)")
    files = {}
    for top in ("workspace", "tests"):
        for dp, dns, fns in os.walk(os.path.join(d, top)):
            dns.sort()
            for fn in sorted(fns):
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, d).replace(os.sep, "/")
                if os.path.islink(full):
                    raise SystemExit(f"{d}: {rel} is a link; bundles hold plain files only")
                raw = open(full, "rb").read()
                if len(raw) > MAX_FILE:
                    raise SystemExit(f"{d}: {rel} is over {MAX_FILE} bytes")
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise SystemExit(f"{d}: {rel} is not text; bundles are text only")
                if "\0" in text:
                    raise SystemExit(f"{d}: {rel} contains a NUL character")
                files[rel] = text
    task = {"id": tid, "base": base, "instruction": open(ins, encoding="utf-8").read(), "files": files}
    al = os.path.join(d, "alignment.json")
    if os.path.isfile(al):
        a = json.load(open(al, encoding="utf-8"))
        a.pop("id", None)
        task["alignment"] = a
    return task


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*")
    ap.add_argument("--all", help="a folder whose subfolders are all tasks")
    ap.add_argument("--name", required=True)
    ap.add_argument("--base", choices=BASES)
    ap.add_argument("--out")
    a = ap.parse_args()
    dirs = list(a.dirs)
    if a.all:
        dirs += sorted(os.path.join(a.all, n) for n in os.listdir(a.all) if os.path.isdir(os.path.join(a.all, n)) and os.path.isfile(os.path.join(a.all, n, "instruction.md")))
    if not dirs:
        raise SystemExit("name at least one task folder (or --all <folder>)")
    doc = {"name": a.name, "tasks": [pack_task(d, a.base) for d in dirs]}
    out = json.dumps(doc)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(out)
        print(f"wrote {a.out}: {len(doc['tasks'])} task(s), {len(out)} bytes", file=sys.stderr)
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
