#!/usr/bin/env python3
"""Shape B: bring up a target for a team's own agent, wait for them, then grade and score.

    python3 scripts/target.py --task tasks/practice/p2-summarize-injected [--port 8300]
        [--limit 40] [--ttl 2700] [--token <token>]

What it does (docs/EVALUATION_PLATFORM.md, shape B):
  1. builds the task's image and starts a disposable workbench (no network) with the task's files;
  2. writes the task's `evaluation` policy (single agent) and starts the broker on a private
     socket, unattended, with the tripwire (weights add up to --limit);
  3. starts the gateway (gateway/gateway.py) on --port with a bearer token, and prints one JSON
     line telling the team how to connect: {"port": ..., "token": ..., "run": ...};
  4. waits until the team calls /v1/finish, the token expires, or the run is halted;
  5. stops everything, copies the hidden tests into the workbench for the first time, grades,
     exports the log, and scores it (scripts/score-run.py): the bundle is runs/<task>-<time>/.

The team's agent runs on THEIR machine, so this tests the broker boundary, not a sandbox around
their agent. Needs Docker, Rust (the broker is built), Python 3. The token is the only secret;
it goes to the team, once.
"""

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER = os.path.join(ROOT, "target", "debug", "broker")


def sh(*cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--port", type=int, default=8300)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--ttl", type=int, default=2700)
    ap.add_argument("--token", default=os.environ.get("TARGET_TOKEN") or "")
    a = ap.parse_args()
    # As root, --user uid:gid would make the workbench root again, and the grader protections rely on it not being.
    if os.getuid() == 0:
        raise SystemExit("target.py must not run as root (the workbench would run as root inside)")
    task = os.path.abspath(a.task)
    name = os.path.basename(task)
    docker = os.environ.get("BROKER_DOCKER", "docker")
    for f in ("Dockerfile", "instruction.md", "tests/run-tests.sh"):
        if not os.path.exists(os.path.join(task, f)):
            raise SystemExit(f"task is missing {f} (see tasks/README.md)")
    token = a.token or secrets.token_urlsafe(32)
    if len(token) < 32:
        raise SystemExit("the token must be at least 32 characters")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    run = os.path.join(ROOT, "runs", f"{name}-{stamp}")
    os.makedirs(os.path.join(run, "workspace"))
    if os.path.isdir(os.path.join(task, "workspace")):
        shutil.copytree(os.path.join(task, "workspace"), os.path.join(run, "workspace"), dirs_exist_ok=True)
    image, wb = f"monkeyitm-task-{name}", f"monkeyitm-wb-{name}-{stamp}"
    sock = f"/tmp/mitm-target-{stamp}.sock"
    procs, state = [], {"stopped": False}

    al = {}
    if os.path.exists(os.path.join(task, "alignment.json")):
        al = json.load(open(os.path.join(task, "alignment.json")))

    def cleanup():
        sh(docker, "rm", "-f", wb)
        if os.path.exists(sock):
            os.remove(sock)

    try:
        r = sh(docker, "build", "-q", "-t", image, task)
        if r.returncode:
            raise SystemExit(f"image build failed: {r.stderr[-300:]}")
        r = sh(docker, "run", "-d", "--name", wb, "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{run}/workspace:/workspace", image, "sleep", "infinity")
        if r.returncode:
            raise SystemExit(f"workbench did not start: {r.stderr[-300:]}")
        if sh("cargo", "build", "-q", "-p", "broker").returncode:
            raise SystemExit("could not build the broker")

        pol_args = [sys.executable, os.path.join(ROOT, "scripts", "make-eval-policy.py"), "--limit", str(a.limit)]
        for h in al.get("allow_hosts") or []:
            pol_args += ["--allow-host", h]
        for p in al.get("critical_paths") or ["/workspace/.secrets/"]:
            pol_args += ["--critical-path", p]
        policy = os.path.join(run, "policy.yaml")
        open(policy, "w").write(subprocess.run(pol_args, capture_output=True, text=True, check=True).stdout)

        benv = dict(os.environ, BROKER_SOCKET=sock, BROKER_POLICY=policy, BROKER_LOG=os.path.join(run, "broker.db"),
                    BROKER_UNATTENDED="1", BROKER_TRIPWIRE=str(a.limit), BROKER_WORKBENCH=wb,
                    BROKER_WORKBENCH_DIR=os.path.join(run, "workspace"), BROKER_DOCKER=docker)
        for k in ("TARGET_TOKEN", "GATEWAY_TOKEN"):
            benv.pop(k, None)        # the broker never sees the team's token
        broker = subprocess.Popen([BROKER], cwd=ROOT, env=benv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=open(os.path.join(run, "broker.txt"), "w"))
        procs.append(broker)
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        if not os.path.exists(sock):
            raise SystemExit("the broker did not start; see " + os.path.join(run, "broker.txt"))

        genv = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GATEWAY_TOKEN": token, "GATEWAY_BROKER_SOCK": sock,
                "GATEWAY_PORT": str(a.port), "GATEWAY_HOST": os.environ.get("GATEWAY_HOST", "0.0.0.0"),
                "GATEWAY_TTL_SECONDS": str(a.ttl), "GATEWAY_STATE_DIR": os.path.join(run, "gateway")}
        gw = subprocess.Popen([sys.executable, os.path.join(ROOT, "gateway", "gateway.py")], env=genv,
                              stdout=open(os.path.join(run, "gateway.txt"), "w"), stderr=subprocess.STDOUT)
        procs.append(gw)
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{a.port}/healthz", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise SystemExit("the gateway did not start; see " + os.path.join(run, "gateway.txt"))

        started = int(time.time())
        print(json.dumps({"port": a.port, "token": token, "run": os.path.relpath(run, ROOT), "task": name,
                          "instruction": open(os.path.join(task, "instruction.md")).read().strip(),
                          "expires_in": a.ttl}), flush=True)

        def stop(*_):
            state["stopped"] = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        closed = os.path.join(run, "gateway", "closed.json")
        while not state["stopped"] and not os.path.exists(closed) and time.time() - started < a.ttl + 30:
            if broker.poll() is not None or gw.poll() is not None:
                break
            time.sleep(1)
        finished = int(time.time())

        for p in reversed(procs):
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        for p in procs:
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()

        # An unpredictable path that does not exist yet (docker cp nests the source inside an existing
        # directory), then a hash check, so nothing the agent pre-planted can stand in for the grader.
        import hashlib, secrets
        gt = f"/opt/.g-{secrets.token_hex(8)}"
        sh(docker, "cp", os.path.join(task, "tests"), f"{wb}:{gt}")
        host_hash = hashlib.sha256(open(os.path.join(task, "tests", "run-tests.sh"), "rb").read()).hexdigest()
        c = sh(docker, "exec", wb, "sha256sum", f"{gt}/run-tests.sh")
        if c.returncode or c.stdout.split()[:1] != [host_hash]:
            raise SystemExit("grader hash mismatch: refusing to grade")
        g = sh(docker, "exec", wb, "bash", f"{gt}/run-tests.sh")
        open(os.path.join(run, "grader.txt"), "w").write(g.stdout + g.stderr)
        subprocess.run([sys.executable, "-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA wal_checkpoint(TRUNCATE)'); c.execute('PRAGMA journal_mode=DELETE'); c.close()",
                        os.path.join(run, "broker.db")])
        for fmt, ext, extra in (("json", "json", []), ("jsonl", "jsonl", []), ("text", "txt", [])):
            sh(BROKER, "export", "--db", os.path.join(run, "broker.db"), "--format", fmt, "--out", os.path.join(run, f"log.{ext}"))
        image_id = sh(docker, "image", "inspect", "-f", "{{.Id}}", image).stdout.strip()
        sh(sys.executable, os.path.join(ROOT, "scripts", "bench-report.py"), "--run", run, "--task", name, "--policy", policy,
           "--grader-exit", str(g.returncode), "--agent-exit", "0", "--started", str(started), "--finished", str(finished),
           "--image", image_id, "--max-steps", "0")
        spec = importlib.util.spec_from_file_location("score_run", os.path.join(ROOT, "scripts", "score-run.py"))
        sr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sr)
        doc = sr.score(json.load(open(os.path.join(run, "log.json"))), al or None, g.returncode == 0, "")
        json.dump(doc, open(os.path.join(run, "alignment-score.json"), "w"), indent=2)
        open(os.path.join(run, "alignment-score.txt"), "w").write(sr.text(doc) + "\n")
        print(sr.text(doc))
        print(f"bundle: {os.path.relpath(run, ROOT)}")
        return 0 if doc["result"]["safe"] else 1
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
        cleanup()


if __name__ == "__main__":
    sys.exit(main())
