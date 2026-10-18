#!/usr/bin/env python3
"""Health and safety check for the nucleus host. Run it from cron or a systemd timer.

    python3 hosted/monitor.py            # prints one JSON line; exit 0 ok, 1 warn, 2 critical

Looks for: the service not answering, a halt in force, a nearly full disk, runs stuck past
their time limit, agent processes that no run accounts for (orphans), and an unusual rate of
failed runs. Prints findings; sends them nowhere unless you set MONITOR_WEBHOOK to a URL you
choose (then a non-ok result is POSTed there as JSON). Settings come from the environment or
/etc/nucleus/nucleus.env: NUCLEUS_ROOT, NUCLEUS_PORT, NUCLEUS_RUN_SECONDS, NUCLEUS_MAX_RUNS.
"""

import json
import os
import shutil
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from halt import load_env  # noqa: E402

OK, WARN, CRIT = 0, 1, 2


def check_health(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
            doc = json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        return [(CRIT, f"the service does not answer on 127.0.0.1:{port}: {e}")]
    return [(WARN, "the service is halted (HALT is in force)")] if doc.get("halted") else []


def check_disk(root, min_free_pct=15):
    try:
        u = shutil.disk_usage(root)
    except OSError as e:
        return [(CRIT, f"cannot read the disk at {root}: {e}")]
    free = 100 * u.free / u.total
    if free < 5:
        return [(CRIT, f"disk almost full: {free:.0f}% free")]
    return [(WARN, f"disk getting full: {free:.0f}% free")] if free < min_free_pct else []


def read_runs(root):
    runs, d = [], os.path.join(root, "runs")
    try:
        names = os.listdir(d)
    except OSError:
        return runs
    for n in names:
        try:
            runs.append(json.load(open(os.path.join(d, n, "status.json"))))
        except (OSError, ValueError):
            continue
    return runs


def check_runs(runs, run_seconds, now, failed_warn=5):
    out = []
    stuck = [r["run_id"] for r in runs if r.get("status") in ("queued", "running")
             and now - (r.get("started_at") or r.get("created_at") or now) > run_seconds + 120]
    if stuck:
        out.append((CRIT, f"runs past their time limit: {', '.join(stuck)}"))
    recent_failed = [r for r in runs if r.get("status") in ("failed", "interrupted") and now - (r.get("finished_at") or 0) < 3600]
    if len(recent_failed) >= failed_warn:
        out.append((WARN, f"{len(recent_failed)} runs failed or were interrupted in the last hour"))
    return out


def agent_processes(proc="/proc"):
    """(pid, age in seconds) of every process whose command line mentions agent.py."""
    found, hz = [], os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    try:
        up = float(open(f"{proc}/uptime").read().split()[0])
    except OSError:
        return found
    for pid in filter(str.isdigit, os.listdir(proc)):
        try:
            cmd = open(f"{proc}/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
            if "agent.py" not in cmd or "monitor.py" in cmd:
                continue
            start = int(open(f"{proc}/{pid}/stat").read().rsplit(")", 1)[1].split()[19])
            found.append((int(pid), up - start / hz))
        except (OSError, ValueError, IndexError):
            continue
    return found


def check_orphans(runs, procs, run_seconds, max_runs):
    active = sum(1 for r in runs if r.get("status") in ("queued", "running"))
    old = [p for p, age in procs if age > run_seconds + 300]
    out = []
    if old:
        out.append((CRIT, f"agent processes older than any run may be: pids {old}"))
    if not active and procs:
        out.append((WARN, f"{len(procs)} agent process(es) with no run in progress"))
    if len(procs) > max_runs * 3 + 3:
        out.append((WARN, f"{len(procs)} agent processes for at most {max_runs} runs"))
    return out


def run_checks(env, now=None, procs=None):
    now = time.time() if now is None else now
    root = env.get("NUCLEUS_ROOT", "/var/lib/nucleus")
    run_seconds = int(env.get("NUCLEUS_RUN_SECONDS", "600"))
    max_runs = int(env.get("NUCLEUS_MAX_RUNS", "2"))
    runs = read_runs(root)
    findings = (check_health(env.get("NUCLEUS_PORT", "8099")) + check_disk(root)
                + check_runs(runs, run_seconds, now)
                + check_orphans(runs, agent_processes() if procs is None else procs, run_seconds, max_runs))
    level = max([OK] + [lv for lv, _ in findings])
    return {"status": ["ok", "warn", "critical"][level], "time": int(now),
            "findings": [{"level": ["ok", "warn", "critical"][lv], "message": m} for lv, m in findings]}, level


def main():
    env = load_env(os.environ.get("NUCLEUS_ENV_FILE", "/etc/nucleus/nucleus.env"))
    doc, level = run_checks(env)
    print(json.dumps(doc))
    hook = env.get("MONITOR_WEBHOOK", "")
    if hook and level:
        try:
            urllib.request.urlopen(urllib.request.Request(hook, data=json.dumps(doc).encode(), method="POST",
                                                          headers={"Content-Type": "application/json"}), timeout=10)
        except Exception as e:  # noqa: BLE001
            print(json.dumps({"webhook_error": str(e)}), file=sys.stderr)
    return level


if __name__ == "__main__":
    sys.exit(main())
