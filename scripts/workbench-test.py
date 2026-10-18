#!/usr/bin/env python3
"""Live test of the brokered workbench: a real container, the benchmark policy.

    cargo build -p broker
    IMAGE=python:3.12-slim python3 scripts/workbench-test.py

Needs a working `docker` (or BROKER_DOCKER=podman). No model and no agent
sandbox are involved: the script plays the agent and sends intents to the
broker over its socket, the way agent/agent.py does.

Phase 1 starts a container with no network, runs the broker with
policies/benchmarks/default.yaml (unattended, tripwire off) and checks what is
allowed and refused. Phase 2 starts a fresh container and broker with the
tripwire set to 3, sends three refused requests, and checks that the run halts
and the container is killed.

Every check is a rule being tested (workspace-only exec and writes, no
network inside the container, container tools denied, symlink and traversal
refusals). Nothing here tries to get out of the container.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCK = "/tmp/broker.sock"
BROKER = os.path.join(ROOT, "target", "debug", "broker")
POLICY = os.environ.get("BENCH_POLICY") or os.path.join(ROOT, "policies", "benchmarks", "default.yaml")
DOCKER = os.environ.get("BROKER_DOCKER", "docker")
IMAGE = os.environ.get("IMAGE", "python:3.12-slim")
HALTED = "run halted by tripwire"


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


class Run:
    """One container plus one broker."""

    def __init__(self, tag, tripwire):
        self.name = f"monkeyitm-wbtest-{tag}-{os.getpid()}"
        self.tmp = tempfile.mkdtemp(prefix="wbtest-")
        self.ws = os.path.join(self.tmp, "workspace")
        os.makedirs(self.ws)
        os.chmod(self.ws, 0o777)
        self.db = os.path.join(self.tmp, "broker.db")
        sh(DOCKER, "rm", "-f", self.name, check=False)
        sh(DOCKER, "run", "-d", "--name", self.name, "--network", "none",
           "-v", f"{self.ws}:/workspace", IMAGE, "sleep", "infinity")
        if os.path.exists(SOCK):
            os.remove(SOCK)
        env = dict(os.environ, BROKER_POLICY=POLICY, BROKER_LOG=self.db,
                   BROKER_UNATTENDED="1", BROKER_TRIPWIRE=str(tripwire),
                   BROKER_WORKBENCH=self.name, BROKER_WORKBENCH_DIR=self.ws,
                   BROKER_DOCKER=DOCKER)
        self.broker = subprocess.Popen([BROKER], env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL,
                                       stderr=open(os.path.join(self.tmp, "broker.err"), "w"))
        for _ in range(100):
            if os.path.exists(SOCK):
                break
            time.sleep(0.1)
        else:
            raise SystemExit("broker did not start")
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        self.f = self.s.makefile("rwb")

    def ask(self, action, params, why="workbench-test"):
        intent = {"id": str(uuid.uuid4()), "action": action, "params": params,
                  "justification": why}
        self.f.write((json.dumps(intent) + "\n").encode())
        self.f.flush()
        return json.loads(self.f.readline())

    def running(self):
        out = sh(DOCKER, "inspect", "-f", "{{.State.Running}}", self.name, check=False)
        return out.stdout.strip() == "true"

    def close(self):
        try:
            self.broker.terminate()
            self.broker.wait(timeout=5)
        except Exception:
            self.broker.kill()
        sh(DOCKER, "rm", "-f", self.name, check=False)
        if os.path.exists(SOCK):
            os.remove(SOCK)


results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))


def verdict_is(name, r, want, reason_has=None):
    ok = r["verdict"] == want and (reason_has is None or reason_has in (r.get("reason") or ""))
    check(name, ok, f"got {r['verdict']}: {r.get('reason')}")
    return r


def res(r):
    return r.get("result") or {}


def phase1():
    print("\nPhase 1: boundaries (container with no network, benchmark policy, tripwire off)")
    run = Run("p1", 0)
    try:
        r = run.ask("exec", {"argv": ["echo", "hi"], "cwd": "/workspace"})
        verdict_is("exec in /workspace is allowed", r, "allow")
        check("  ... and ran inside the container", res(r).get("stdout", "").strip() == "hi")

        r = run.ask("exec", {"argv": ["python3", "-c",
                    "import socket; socket.create_connection(('1.1.1.1', 443), 3)"],
                    "cwd": "/workspace"})
        check("container has no network (connect fails)", res(r).get("exit_code") not in (0, None),
              json.dumps(res(r))[:120])
        r = run.ask("exec", {"argv": ["python3", "-c", "import socket; socket.gethostbyname('example.com')"],
                    "cwd": "/workspace"})
        check("container has no DNS (lookup fails)", res(r).get("exit_code") not in (0, None),
              json.dumps(res(r))[:120])

        verdict_is("exec docker is denied", run.ask("exec", {"argv": ["docker", "ps"], "cwd": "/workspace"}), "deny")
        verdict_is("exec sudo is denied", run.ask("exec", {"argv": ["sudo", "id"], "cwd": "/workspace"}), "deny")
        verdict_is("exec with cwd / is denied", run.ask("exec", {"argv": ["ls"], "cwd": "/"}), "deny")
        verdict_is("exec with cwd /workspace/../tmp is denied",
                   run.ask("exec", {"argv": ["ls"], "cwd": "/workspace/../tmp"}), "deny")

        verdict_is("write in /workspace is allowed",
                   run.ask("write_file", {"path": "/workspace/a.txt", "content": "alpha"}), "allow")
        r = run.ask("read_file", {"path": "/workspace/a.txt"})
        verdict_is("read back from /workspace is allowed", r, "allow")
        check("  ... with the right content", res(r).get("content") == "alpha")
        verdict_is("write outside /workspace is denied",
                   run.ask("write_file", {"path": "/tmp/x.txt", "content": "x"}), "deny")
        verdict_is("write with .. out of /workspace is denied",
                   run.ask("write_file", {"path": "/workspace/../etc/x", "content": "x"}), "deny")
        verdict_is("write over 1 MB is refused",
                   run.ask("write_file", {"path": "/workspace/big.txt", "content": "a" * (1024 * 1024 + 1)}), "deny")

        verdict_is("read of /etc/hostname is denied (no human)",
                   run.ask("read_file", {"path": "/etc/hostname"}), "deny", "no human approver")
        verdict_is("read with .. out of /workspace is denied",
                   run.ask("read_file", {"path": "/workspace/../etc/passwd"}), "deny")

        # A symlink made inside the container that points outside it.
        run.ask("exec", {"argv": ["ln", "-s", "/etc/passwd", "/workspace/link"], "cwd": "/workspace"})
        verdict_is("read through a symlink pointing out is refused",
                   run.ask("read_file", {"path": "/workspace/link"}), "deny")
        verdict_is("write through a symlink is refused",
                   run.ask("write_file", {"path": "/workspace/link", "content": "x"}), "deny")
        os.remove(os.path.join(run.ws, "link")) if os.path.islink(os.path.join(run.ws, "link")) else None

        verdict_is("http_get is denied", run.ask("http_get", {"url": "https://example.com"}), "deny")

        r = run.ask("exec", {"argv": ["sleep", "5"], "cwd": "/workspace", "timeout_s": 1})
        check("a command past its time limit is stopped", res(r).get("timed_out") is True,
              json.dumps(res(r))[:120])
        r = run.ask("exec", {"argv": ["bash", "-c", "head -c 300000 /dev/zero | tr '\\0' a"], "cwd": "/workspace"})
        check("command output is capped at 64 KB", len(res(r).get("stdout", "")) <= 65536 + 64,
              f"stdout length {len(res(r).get('stdout', ''))}")

        check("container is still running", run.running())
        out = sh(BROKER, "export", "--db", run.db, "--format", "json", "--out", "/dev/stdout",
                 check=False).stdout
        try:
            doc = json.loads(out[out.index("{"):])
            denies = [e for e in doc["events"] if e["final_verdict"] == "deny"]
            check("every request was logged with a verdict",
                  all(e["final_verdict"] for e in doc["events"]), f"{len(doc['events'])} events")
            check("refusals are in the log", len(denies) >= 12, f"{len(denies)} denied")
        except Exception as e:
            check("log export parses", False, str(e))
    finally:
        run.close()


def phase2():
    print("\nPhase 2: tripwire (limit 3) halts the run and kills the container")
    run = Run("p2", 3)
    try:
        check("container starts running", run.running())
        for i, path in enumerate(["/etc/hostname", "/etc/shadow", "/root/.ssh/id_rsa"], 1):
            run.ask("read_file", {"path": path})
        r = run.ask("exec", {"argv": ["echo", "after"], "cwd": "/workspace"})
        check("a request that would be allowed is refused after the halt",
              r["verdict"] == "deny" and HALTED in (r.get("reason") or ""), f"{r['verdict']}: {r.get('reason')}")
        time.sleep(1)
        check("the workbench container was killed", not run.running())
        out = sh(BROKER, "export", "--db", run.db, "--format", "json", "--out", "/dev/stdout",
                 check=False).stdout
        doc = json.loads(out[out.index("{"):])
        check("the halt is in the log", any(e["kind"] == "tripwire" for e in doc["run_events"]))
        check("the refused request is in the log too",
              any(e["action"] == "exec" and e["final_verdict"] == "deny" for e in doc["events"]))
    finally:
        run.close()


def main():
    if not os.path.exists(BROKER):
        raise SystemExit("build the broker first: cargo build -p broker")
    if sh(DOCKER, "info", check=False).returncode != 0:
        raise SystemExit(f"{DOCKER} is not usable here (is the daemon running?)")
    phase1()
    phase2()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
