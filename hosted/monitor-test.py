#!/usr/bin/env python3
"""Tests of hosted/monitor.py: each check fires when it should and stays quiet when it should.

    python3 hosted/monitor-test.py

No host, broker or sandbox needed: fake run folders, fake process lists and a tiny local
health server stand in for the real thing.
"""

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monitor as m  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:160]}]" if detail and not ok else ""))


def health_server(halted):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"ok": True, "halted": halted}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def write_run(root, rid, **rec):
    d = os.path.join(root, "runs", rid)
    os.makedirs(d, exist_ok=True)
    json.dump({"run_id": rid, **rec}, open(os.path.join(d, "status.json"), "w"))


def main():
    now = 1_800_000_000
    print("\nHealth")
    srv = health_server(False)
    check("a healthy service gives no finding", m.check_health(srv.server_port) == [])
    srv.shutdown()
    srv = health_server(True)
    f = m.check_health(srv.server_port)
    check("a halt in force is a warning", [lv for lv, _ in f] == [m.WARN], f)
    srv.shutdown()
    f = m.check_health(1)
    check("a service that does not answer is critical", [lv for lv, _ in f] == [m.CRIT], f)

    print("\nDisk")
    with tempfile.TemporaryDirectory() as t:
        check("a disk with room gives no finding", m.check_disk(t, min_free_pct=0) == [])
        f = m.check_disk(t, min_free_pct=101)
        check("a disk below the threshold warns", [lv for lv, _ in f] == [m.WARN], f)
        f = m.check_disk(os.path.join(t, "no", "such"))
        check("an unreadable disk path is critical", [lv for lv, _ in f] == [m.CRIT], f)

    print("\nRuns")
    with tempfile.TemporaryDirectory() as t:
        write_run(t, "a" * 16, status="running", started_at=now - 60, created_at=now - 70)
        write_run(t, "b" * 16, status="running", started_at=now - 5000, created_at=now - 5010)
        write_run(t, "c" * 16, status="done", started_at=now - 9000, created_at=now - 9010, finished_at=now - 8900)
        runs = m.read_runs(t)
        check("all three runs are read", len(runs) == 3, len(runs))
        f = m.check_runs(runs, 600, now)
        check("a run past its limit is critical and named",
              len(f) == 1 and f[0][0] == m.CRIT and "b" * 16 in f[0][1] and "a" * 16 not in f[0][1], f)
        for i in range(5):
            write_run(t, f"{i:016x}", status="failed", created_at=now - 600, finished_at=now - 300)
        f = m.check_runs(m.read_runs(t), 600, now)
        check("five failures in an hour warn", any(lv == m.WARN and "failed" in msg for lv, msg in f), f)
        check("an unreadable status file is skipped, not fatal",
              len(m.read_runs(os.path.join(t, "nothing-here"))) == 0)

    print("\nOrphans")
    runs_idle = []
    runs_busy = [{"status": "running"}]
    f = m.check_orphans(runs_idle, [(10, 5000)], 600, 2)
    check("an agent process older than any run is critical", any(lv == m.CRIT for lv, _ in f), f)
    f = m.check_orphans(runs_idle, [(10, 30)], 600, 2)
    check("a young agent process with no run in progress warns", [lv for lv, _ in f] == [m.WARN], f)
    check("agent processes that a run accounts for are fine", m.check_orphans(runs_busy, [(10, 30), (11, 30)], 600, 2) == [])
    check("no processes and no runs is fine", m.check_orphans(runs_idle, [], 600, 2) == [])
    f = m.check_orphans(runs_busy, [(i, 10) for i in range(12)], 600, 2)
    check("far more processes than runs could start warns", any(lv == m.WARN and "12" in msg for lv, msg in f), f)

    print("\nWhole check")
    srv = health_server(False)
    with tempfile.TemporaryDirectory() as t:
        env = {"NUCLEUS_ROOT": t, "NUCLEUS_PORT": str(srv.server_port), "NUCLEUS_RUN_SECONDS": "600", "NUCLEUS_MAX_RUNS": "2"}
        doc, level = m.run_checks(env, now=now, procs=[])
        check("a quiet, healthy host reports ok", doc["status"] == "ok" and level == 0 and doc["findings"] == [], doc)
        write_run(t, "d" * 16, status="running", started_at=now - 5000, created_at=now - 5000)
        doc, level = m.run_checks(env, now=now, procs=[])
        check("a stuck run turns it critical, exit code 2", doc["status"] == "critical" and level == 2, doc)
        check("the result is one JSON document", json.loads(json.dumps(doc)) == doc)
    srv.shutdown()

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
