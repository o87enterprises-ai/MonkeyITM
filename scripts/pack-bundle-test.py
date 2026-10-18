#!/usr/bin/env python3
"""Tests of scripts/pack-bundle.py: python3 scripts/pack-bundle-test.py"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, "scripts", "pack-bundle.py")
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


def pack(*args):
    p = subprocess.run([sys.executable, PACK, *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def make_task(parent, name, dockerfile="FROM python:3.12-slim\nWORKDIR /workspace\n", extra=None):
    d = os.path.join(parent, name)
    os.makedirs(os.path.join(d, "workspace"))
    os.makedirs(os.path.join(d, "tests"))
    open(os.path.join(d, "instruction.md"), "w").write("Do it.\n")
    open(os.path.join(d, "tests", "run-tests.sh"), "w").write("#!/bin/bash\necho ok\n")
    open(os.path.join(d, "workspace", "a.txt"), "w").write("hello")
    if dockerfile is not None:
        open(os.path.join(d, "Dockerfile"), "w").write(dockerfile)
    for rel, data in (extra or {}).items():
        os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
        open(os.path.join(d, rel), "wb").write(data)
    return d


def main():
    print("\nPacking")
    rc, out, err = pack("--all", os.path.join(ROOT, "tasks", "practice"), "--name", "practice")
    doc = json.loads(out) if rc == 0 else {}
    check("the practice suite packs", rc == 0 and len(doc.get("tasks", [])) == 6, err)
    check("each task has the grader, an instruction and an allowed base",
          all("tests/run-tests.sh" in t["files"] and t["instruction"] and t["base"] in ("python:3.12-slim", "node:20-slim", "ubuntu:24.04") for t in doc.get("tasks", [])))
    check("no Dockerfile is sent, and ids are lower-case folder names", all("Dockerfile" not in t["files"] and "dockerfile" not in t for t in doc["tasks"])
          and {t["id"] for t in doc["tasks"]} >= {"p1-fix-bug", "p6-no-outside-filing"})
    p2 = next(t for t in doc["tasks"] if t["id"] == "p2-summarize-injected")
    check("alignment.json becomes the task's alignment, without its id", p2["alignment"]["pressure"] == "injection" and "id" not in p2["alignment"])
    check("hidden files such as .secrets are kept", "workspace/.secrets/credentials" in p2["files"])

    print("\nRefusals")
    tmp = tempfile.mkdtemp(prefix="pack-test-")
    for label, kw in (("a base image that is not allowed", {"dockerfile": "FROM evil:latest\n"}),
                      ("a binary file", {"extra": {"workspace/b.bin": b"\xff\xfe\x00\x01"}}),
                      ("a file with a NUL", {"extra": {"workspace/n.txt": b"a\x00b"}}),
                      ("a file over 256 KB", {"extra": {"workspace/big.txt": b"x" * (256 * 1024 + 1)}})):
        d = make_task(tmp, "t" + str(abs(hash(label)) % 10 ** 6), **kw)
        rc, out, err = pack(d, "--name", "x")
        check(f"refused: {label}", rc != 0 and not out, err)
    d = make_task(tmp, "UPPER")
    rc, out, err = pack(d, "--name", "x")
    check("a folder name is lower-cased into the id", rc == 0 and json.loads(out)["tasks"][0]["id"] == "upper", err)
    d = make_task(tmp, "nograder")
    os.remove(os.path.join(d, "tests", "run-tests.sh"))
    check("refused: no grader", pack(d, "--name", "x")[0] != 0)
    d = make_task(tmp, "overridden", dockerfile="FROM evil:latest\n")
    rc, out, err = pack(d, "--name", "x", "--base", "node:20-slim")
    check("--base overrides the Dockerfile's FROM", rc == 0 and json.loads(out)["tasks"][0]["base"] == "node:20-slim", err)
    check("no Dockerfile at all defaults to python:3.12-slim", json.loads(pack(make_task(tmp, "nodf", dockerfile=None), "--name", "x")[1])["tasks"][0]["base"] == "python:3.12-slim")

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
