#!/usr/bin/env python3
"""Run every test suite this machine can run, and print one summary.

    python3 scripts/test-all.py              # everything available here
    python3 scripts/test-all.py --list       # what would run, and what is skipped and why
    python3 scripts/test-all.py --only runner cli    # suites whose name contains one of these words
    python3 scripts/test-all.py --fast       # leave out the slow ones (the 100 s Rust campaign test)

What runs where:
  Linux / WSL / macOS : the Rust workspace tests, the broker's live and group tests, the runner, the
                        gateway, the hosted-host tests, plus everything cross-platform below.
  anywhere with Python: scoring, policy, eval-job, task-bundle packer, command line client.
  anywhere with Node and wrangler: the API tests (site/api-test.mjs: a real local Worker and database).
  with Docker (Linux)  : the workbench test.
A suite whose tool is missing is skipped, never failed. Exit status 0 only if nothing that ran failed.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSIX = os.name == "posix"
PY = sys.executable


def has(tool):
    return shutil.which(tool) is not None


def docker_ok():
    if not has("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# (name, command, cwd, needs, slow)
SUITES = [
    ("rust workspace (broker, policy, log chain, capability, intent)", ["cargo", "test", "-q"], ROOT, ("posix", "cargo"), True),
    ("broker live tests (the real broker process)", [PY, "scripts/broker-live-tests.py"], ROOT, ("posix", "broker"), False),
    ("multi-agent / groups", [PY, "scripts/multi-agent-test.py"], ROOT, ("posix", "broker"), False),
    ("group attacks", [PY, "scripts/group-attack-test.py"], ROOT, ("posix", "broker"), False),
    ("agent format", [PY, "scripts/agent-format-test.py"], ROOT, ("posix", "broker"), False),
    ("evaluation policy generator", [PY, "scripts/eval-policy-test.py"], ROOT, ("posix", "broker"), False),
    ("scoring", [PY, "scripts/score-test.py"], ROOT, (), False),
    ("eval-job", [PY, "scripts/eval-job-test.py"], ROOT, (), False),
    ("task-bundle packer", [PY, "scripts/pack-bundle-test.py"], ROOT, (), False),
    ("command line client", [PY, "cli/cli-test.py"], ROOT, (), False),
    ("guard (agent sandbox in front of a session; needs bubblewrap)", [PY, "cli/guard-test.py"], ROOT, ("posix",), False),
    ("runner (fake control plane; real broker when built)", [PY, "runner/runner-test.py"], ROOT, ("posix",), False),
    ("gateway (shape B)", [PY, "gateway/gateway-test.py"], ROOT, ("posix", "broker"), False),
    ("hosted host", [PY, "hosted/hosted-test.py"], ROOT, ("posix", "broker"), False),
    ("hosted monitor", [PY, "hosted/monitor-test.py"], ROOT, ("posix",), False),
    ("workbench (needs Docker)", [PY, "scripts/workbench-test.py"], ROOT, ("posix", "broker", "docker"), False),
    ("API: a real local Worker + database (needs Node, wrangler)", ["node", "api-test.mjs"], os.path.join(ROOT, "site"), ("node", "wrangler"), False),
]


def missing(needs):
    for n in needs:
        if n == "posix" and not POSIX:
            return "needs Linux, WSL or macOS"
        if n == "cargo" and not has("cargo"):
            return "cargo is not installed"
        if n == "node" and not has("node"):
            return "node is not installed"
        if n == "wrangler" and not (has("wrangler") or os.path.exists(os.path.join(ROOT, "site", "node_modules", "wrangler"))):
            return "wrangler is not installed"
        if n == "broker" and not os.path.exists(os.path.join(ROOT, "target", "debug", "broker")):
            return "the broker is not built (cargo build -p broker)"
        if n == "docker" and not docker_ok():
            return "Docker is not available"
    return None


def count(output):
    """(passed, failed) from a suite's output: 'N passed, M failed' lines, or cargo's 'test result' lines."""
    p = f = 0
    for m in re.finditer(r"(\d+) passed, (\d+) failed", output):
        p, f = int(m.group(1)), int(m.group(2))        # the last such line is the suite's total
    if p or f:
        return p, f
    for m in re.finditer(r"test result: \w+\. (\d+) passed; (\d+) failed", output):
        p += int(m.group(1))
        f += int(m.group(2))
    return p, f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--fast", action="store_true")
    a = ap.parse_args()
    if POSIX and has("cargo") and not a.list and not os.path.exists(os.path.join(ROOT, "target", "debug", "broker")):
        print("building the broker first (cargo build -p broker) ...", flush=True)
        subprocess.run(["cargo", "build", "-q", "-p", "broker"], cwd=ROOT)
    rows = []
    for name, cmd, cwd, needs, slow in SUITES:
        if a.only and not any(w.lower() in name.lower() for w in a.only):
            continue
        why = missing(needs)
        if why is None and a.fast and slow:
            why = "left out by --fast"
        if a.list or why:
            rows.append((name, "skipped" if why else "would run", why or "", 0, 0, 0.0))
            continue
        print(f"== {name}", flush=True)
        t0 = time.time()
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1200)
            out, code = r.stdout + r.stderr, r.returncode
        except subprocess.TimeoutExpired as e:
            out, code = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")), "timeout"
        p, f = count(out)
        ok = code == 0 and f == 0 and (p > 0)
        rows.append((name, "PASS" if ok else "FAIL", "" if ok else f"exit {code}", p, f, time.time() - t0))
        if not ok:
            print("   " + "\n   ".join(out.strip().splitlines()[-12:]), flush=True)
    print()
    w = max((len(r[0]) for r in rows), default=10)
    for name, status, note, p, f, secs in rows:
        print(f"{name:<{w}}  {status:<9} {p:>4} passed {f:>3} failed  {secs:5.0f}s  {note}")
    ran = [r for r in rows if r[1] in ("PASS", "FAIL")]
    total_p, total_f = sum(r[3] for r in ran), sum(r[4] for r in ran)
    bad = [r for r in ran if r[1] == "FAIL"]
    skipped = [r for r in rows if r[1] == "skipped"]
    print(f"\n{len(ran)} suite(s) ran: {total_p} checks passed, {total_f} failed; {len(skipped)} skipped; {len(bad)} suite(s) failed")
    for r in skipped:
        print(f"  skipped: {r[0]}: {r[2]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
