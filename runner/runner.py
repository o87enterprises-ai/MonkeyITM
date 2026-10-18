#!/usr/bin/env python3
"""The MonkeyITM runner: takes runs from the control plane and executes them here.

    MITM_API=https://monkeyitm-vm.o87enterprises.workers.dev MITM_RUNNER_TOKEN=... python3 runner/runner.py

A runner polls the API for the next run (outbound HTTPS only: no open port is needed), fetches the
run's model key, executes the task with scripts/eval-job.py (broker, sandboxed agent, workbench,
grader, alignment score), sends a heartbeat every couple of seconds, uploads the log, score,
transcript and report, and reports the result. Standard library only; Linux.

What it guarantees (docs/API_V1.md, "Runner protocol"):
  - One run at a time per machine (the broker's socket path is fixed), so concurrency means more
    machines or sandboxes.
  - The task id and every limit come from the API but are validated here; the task must be a
    folder under the tasks directory. Nothing from the API is ever used as a path or a command.
  - The model key goes only into the environment of the job it belongs to. The runner's own token
    and API address are NOT passed to the job, and the key is redacted from everything uploaded.
  - An owner kill (the heartbeat reply says kill) pulls the broker's kill switch (SIGUSR1) at
    once; a job that has not stopped after a short grace is terminated, then killed.
  - If the control plane cannot be reached for MITM_LOST_S seconds, the runner stops its own run:
    no agent outlives its connection to the control plane.

Live sessions (docs/SESSIONS_DESIGN.md): a lease of kind "session" starts scripts/run-session.sh (a
workbench container and a broker on its own socket), tells the control plane it is ready, then holds a
long-poll open: each intent the customer's agent sends arrives here, is passed to the broker's socket,
and the broker's answer goes back. The kill switch (owner kill, lost control plane, Ctrl-C) is pulled on
the broker before the session is torn down; the broker's log is exported, scored and uploaded as for a job.

Settings (environment): MITM_API, MITM_RUNNER_TOKEN (required); MITM_POLL_S (5), MITM_HEARTBEAT_S
(2), MITM_LOST_S (30), MITM_KILL_GRACE_S (15), MITM_WORK (/tmp/mitm-runner), MITM_TASKS
(tasks/practice), MITM_ONCE=1 (exit after one run), MITM_KEEP=1 (keep run folders),
MITM_EVAL_JOB, MITM_REPO, MITM_SESSION_SCRIPT, MITM_BROKER_BIN, MITM_SESSION_WAIT_S (20),
MITM_SESSION_START_S (300), MITM_INTENT_TIMEOUT_S (130) (tests and tuning).
"""

import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
MODEL_NAME_RE = re.compile(r"^[\w./:-]{1,120}$")
BUNDLE_TASK_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
# What a customer's task bundle may contain (the API checks the same rules; this is the second check).
BUNDLE_BASES = ("python:3.12-slim", "node:20-slim", "ubuntu:24.04")
BUNDLE_PATH_RE = re.compile(r"^(workspace|tests)/[A-Za-z0-9._/-]+$")
BUNDLE_MAX_FILE = 256 * 1024
BUNDLE_MAX_FILES = 200
# Set by Ctrl-C or SIGTERM: idle waits end at once, and a run in progress is stopped.
STOP = threading.Event()
ARTIFACT_CAP = 850 * 1024
# Child environment: only what a build and a run need. Nothing of the runner's own settings.
PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME", "DOCKER_HOST", "USER", "LOGNAME")


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} runner: {msg}", flush=True)


def load_config(env=os.environ):
    cfg = {
        "api": (env.get("MITM_API") or "").rstrip("/"),
        "token": (env.get("MITM_RUNNER_TOKEN") or "").strip(),   # a stray space or carriage return from pasting
        "poll": float(env.get("MITM_POLL_S", "5")),
        "heartbeat": float(env.get("MITM_HEARTBEAT_S", "2")),
        "lost": float(env.get("MITM_LOST_S", "30")),
        "grace": float(env.get("MITM_KILL_GRACE_S", "15")),
        "work": env.get("MITM_WORK", "/tmp/mitm-runner"),
        "repo": env.get("MITM_REPO", ROOT),
        "tasks": env.get("MITM_TASKS", "tasks/practice"),
        "eval_job": env.get("MITM_EVAL_JOB", os.path.join(ROOT, "scripts", "eval-job.py")),
        "session_script": env.get("MITM_SESSION_SCRIPT", os.path.join(ROOT, "scripts", "run-session.sh")),
        "broker_bin": env.get("MITM_BROKER_BIN", os.path.join(env.get("MITM_REPO", ROOT), "target", "debug", "broker")),
        "session_wait": float(env.get("MITM_SESSION_WAIT_S", "20")),
        "session_start": float(env.get("MITM_SESSION_START_S", "300")),
        "intent_timeout": float(env.get("MITM_INTENT_TIMEOUT_S", "130")),
        "once": env.get("MITM_ONCE") == "1",
        "keep": env.get("MITM_KEEP") == "1",
    }
    if not cfg["api"] or not cfg["token"]:
        raise SystemExit("set MITM_API and MITM_RUNNER_TOKEN")
    if not re.match(r"^mitr_[0-9a-f]{32}$", cfg["token"]):
        # Say what is wrong without printing any of it: a paste that lost or gained characters.
        raise SystemExit(f"MITM_RUNNER_TOKEN is not shaped like a runner token (it has {len(cfg['token'])} characters, "
                         f"expected 37, starting mitr_): paste it again")
    if not (cfg["api"].startswith("https://") or re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?$", cfg["api"])):
        raise SystemExit("MITM_API must be https (http only for localhost)")
    return cfg


# ------------------------------------------------------------------ talking to the API

def call(cfg, method, path, body=None, timeout=20):
    """Returns (status, parsed JSON or None). Raises OSError when the API cannot be reached."""
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(cfg["api"] + path, data=data, method=method, headers={
        "Authorization": "Bearer " + cfg["token"], "Content-Type": "application/json",
        # Cloudflare (in front of the API) blocks Python's default user-agent with error 1010.
        "User-Agent": "monkeyitm-runner/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except ValueError:
            # Not our JSON: probably something in front of the API. Keep a snippet to show.
            return e.code, {"raw": raw[:120].decode(errors="replace")}


# ------------------------------------------------------------------ validating a lease

def check_spec(spec, cfg):
    """The API is trusted to be ours, not to be bug-free: re-check everything used here."""
    def bad(m):
        raise ValueError(m)
    if not isinstance(spec, dict):
        bad("the lease is not an object")
    task = spec.get("task")
    bundle = spec.get("suite") == "bundle"
    if bundle:
        if not isinstance(task, str) or not BUNDLE_TASK_RE.match(task):
            bad("bad task id")
        if not isinstance(spec.get("bundle_id"), str) or not re.match(r"^tb_[0-9a-f]{12}$", spec["bundle_id"]):
            bad("bad bundle id")
    else:
        if not isinstance(task, str) or not TASK_RE.match(task):
            bad("bad task id")
        tasks_dir = os.path.join(cfg["repo"], cfg["tasks"])
        if not os.path.isdir(os.path.join(tasks_dir, task)):
            bad("unknown task")
    if spec.get("mode") not in ("single", "group"):
        bad("bad mode")
    if not isinstance(spec.get("run_id"), str) or not re.match(r"^run_[0-9a-f]{16}$", spec["run_id"]):
        bad("bad run id")
    lim, pol, model = spec.get("limits") or {}, spec.get("policy") or {}, spec.get("model") or {}

    def num(v, lo, hi, what):
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            bad(f"bad {what}")
        return v
    out = {
        "task": task, "mode": spec["mode"], "run_id": spec["run_id"], "bundle": bundle,
        "max_steps": num(lim.get("max_steps"), 1, 50, "max_steps"),
        "timeout": num(lim.get("task_timeout_s"), 30, 1800, "task timeout"),
        "tripwire": num(pol.get("tripwire"), 1, 100, "tripwire"),
    }
    hosts = pol.get("allow_hosts", [])
    if not isinstance(hosts, list) or len(hosts) > 10 or not all(isinstance(h, str) and HOST_RE.match(h) for h in hosts):
        bad("bad allowed hosts")
    out["allow_hosts"] = hosts
    url = model.get("url")
    if not isinstance(url, str) or not url.startswith("https://") or any(c in url for c in " \n\r\t\0"):
        bad("bad model url")
    if not isinstance(model.get("name"), str) or not MODEL_NAME_RE.match(model["name"]):
        bad("bad model name")
    out["model_url"], out["model_name"] = url, model["name"]
    return out


# ------------------------------------------------------------------ a customer's task bundle

def _check_task(task, expect_id):
    """Check one bundle task, whatever the API said; returns (base, instruction, files, alignment)."""
    def bad(m):
        raise ValueError(m)
    if not isinstance(task, dict) or set(task) - {"id", "base", "instruction", "files", "alignment"}:
        bad("the task has unexpected fields")
    if task.get("id") != expect_id or not BUNDLE_TASK_RE.match(str(task.get("id"))):
        bad("bad task id")
    base = task.get("base", "python:3.12-slim")
    if base not in BUNDLE_BASES:
        bad("base image not allowed")
    ins = task.get("instruction")
    if not isinstance(ins, str) or not ins.strip() or len(ins) > 20000 or "\0" in ins:
        bad("bad instruction")
    files = task.get("files")
    if not isinstance(files, dict) or len(files) > BUNDLE_MAX_FILES or "tests/run-tests.sh" not in files:
        bad("bad files (tests/run-tests.sh is required)")
    align = task.get("alignment", {})
    if not isinstance(align, dict):
        bad("bad alignment")
    for path, content in files.items():
        segs = path.split("/") if isinstance(path, str) else []
        if (not isinstance(path, str) or len(path) > 200 or not BUNDLE_PATH_RE.match(path)
                or any(s in ("", ".", "..") for s in segs)):
            bad("bad file path")
        if not isinstance(content, str) or "\0" in content or len(content.encode()) > BUNDLE_MAX_FILE:
            bad("bad file content")
    return base, ins, files, align


def materialize(task, root, expect_id):
    """Write one bundle task out as a task folder under root, and return its path.

    Everything is checked again here, whatever the API said. The Dockerfile is ours: a base image
    from a short list, a working directory, nothing else. Uploaded files are plain text written
    under workspace/ or tests/ and never anywhere else.
    """
    base, ins, files, align = _check_task(task, expect_id)
    d = os.path.join(root, task["id"])
    os.makedirs(os.path.join(d, "workspace"), exist_ok=True)
    os.makedirs(os.path.join(d, "tests"), exist_ok=True)
    real = os.path.realpath(d)
    for path, content in files.items():
        segs = path.split("/")
        full = os.path.realpath(os.path.join(d, *segs))
        if not full.startswith(real + os.sep):
            raise ValueError("file path leaves the task folder")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.islink(full):
            raise ValueError("file path is a link")
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    os.chmod(os.path.join(d, "tests", "run-tests.sh"), 0o755)
    with open(os.path.join(d, "Dockerfile"), "w") as f:
        f.write(f"FROM {base}\nWORKDIR /workspace\n")
    with open(os.path.join(d, "instruction.md"), "w", encoding="utf-8") as f:
        f.write(ins.rstrip("\n") + "\n")
    with open(os.path.join(d, "alignment.json"), "w") as f:
        json.dump({**align, "id": task["id"]}, f)
    return d


# ------------------------------------------------------------------ stopping a run

def group_members(pgid):
    """(pid, cmdline) of every process in the process group, from /proc (Linux)."""
    out = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for p in pids:
        try:
            stat = open(f"/proc/{p}/stat").read()
            if int(stat.rsplit(")", 1)[1].split()[2]) != pgid:
                continue
            cmd = open(f"/proc/{p}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
            out.append((int(p), cmd))
        except (OSError, ValueError, IndexError):
            continue
    return out


def pull_kill_switch(proc):
    """SIGUSR1 to every broker in the process group: it refuses everything from now on, kills its
    container and helpers, and logs the stop. Returns how many it reached."""
    pulled = 0
    for pid, cmd in group_members(proc.pid):
        if "target/debug/broker" in cmd or "target/release/broker" in cmd:
            try:
                os.kill(pid, signal.SIGUSR1)
                pulled += 1
            except OSError:
                pass
    if pulled:
        log(f"kill switch pulled on {pulled} broker(s)")
    return pulled


def stop_run(proc, cfg, why):
    """Kill switch first (the broker stops everything and logs it), then terminate, then kill."""
    log(f"stopping the run: {why}")
    pull_kill_switch(proc)
    deadline = time.time() + cfg["grace"]
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.1)
    if proc.poll() is None:
        log("the job did not stop in time: terminating")
        for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            try:
                os.killpg(proc.pid, sig)
            except OSError:
                break
            end = time.time() + wait
            while proc.poll() is None and time.time() < end:
                time.sleep(0.1)
            if proc.poll() is not None:
                break
    # Stragglers in the group (a helper agent, a docker client) must not outlive the run.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


# ------------------------------------------------------------------ artifacts

def redact(text, key):
    """Remove the key, and the common re-encodings of it (base64, URL-encoded, hex), from text."""
    if not key or len(key) < 8:
        return text
    import base64
    import urllib.parse
    raw = key.encode()
    b64 = base64.b64encode(raw).decode()
    ub64 = base64.urlsafe_b64encode(raw).decode()
    forms = {key, b64, b64.rstrip("="), ub64, ub64.rstrip("="), urllib.parse.quote(key, safe=""),
             urllib.parse.quote_plus(key), raw.hex(), raw.hex().upper(), json.dumps(key)[1:-1]}
    for f in sorted(forms, key=len, reverse=True):
        if len(f) >= 8:
            text = text.replace(f, "[redacted]")
    return text


def fit(text, kind):
    if len(text) <= ARTIFACT_CAP:
        return text
    if kind == "log":
        try:
            doc = json.loads(text)
            for e in doc.get("events", []):
                e.pop("result", None)
            text2 = json.dumps(doc)
            if len(text2) <= ARTIFACT_CAP:
                return text2
            ev = doc.get("events", [])
            while ev and len(json.dumps({**doc, "events": ev, "truncated": True})) > ARTIFACT_CAP:
                ev = ev[: max(1, len(ev) // 2)] if len(ev) > 1 else []
            return json.dumps({**doc, "events": ev, "truncated": True})
        except ValueError:
            pass
    head = text[: ARTIFACT_CAP // 2 - 200]
    tail = text[-(ARTIFACT_CAP // 2 - 200):]
    return head + "\n[... trimmed to fit ...]\n" + tail


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


# ------------------------------------------------------------------ one run

def start_heartbeat(cfg, rid):
    """Heartbeat the run every few seconds in a thread. The returned state says whether the control
    plane asked for a kill, or has been out of reach for longer than MITM_LOST_S."""
    state = {"kill": False, "lost": False, "last_ok": time.time(), "done": threading.Event()}

    def beat():
        while not state["done"].wait(cfg["heartbeat"]):
            try:
                s, j = call(cfg, "POST", f"/runner/v1/runs/{rid}/heartbeat", timeout=10)
                if s == 200:
                    state["last_ok"] = time.time()
                    if j and j.get("kill"):
                        state["kill"] = True
                elif s in (401, 404):
                    state["kill"] = True   # the run is no longer ours
            except OSError:
                pass
            if time.time() - state["last_ok"] > cfg["lost"]:
                state["lost"] = True

    threading.Thread(target=beat, daemon=True).start()
    return state


def complete(cfg, run_id, status, result=None, note=None):
    try:
        call(cfg, "POST", f"/runner/v1/runs/{run_id}/complete", {"status": status, "result": result or {}, "note": note})
    except OSError as e:
        log(f"could not report the result of {run_id}: {e}")


def run_one(cfg, lease):
    rid = lease.get("run_id", "?")
    try:
        spec = check_spec(lease, cfg)
    except ValueError as e:
        log(f"refusing a bad lease ({e})")
        if isinstance(rid, str) and re.match(r"^run_[0-9a-f]{16}$", rid):
            complete(cfg, rid, "error", note=f"the runner refused the lease: {e}")
        return
    status, kj = call(cfg, "POST", f"/runner/v1/runs/{rid}/model-key")
    if status != 200 or not isinstance(kj, dict) or not kj.get("key"):
        complete(cfg, rid, "error", note="the runner could not get the model key (the run may have been stopped)")
        return
    key = kj["key"]

    work = os.path.join(cfg["work"], rid)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    tasks_dir = os.path.join(cfg["repo"], cfg["tasks"])
    if spec["bundle"]:
        s, bj = call(cfg, "POST", f"/runner/v1/runs/{rid}/bundle")
        if s != 200 or not isinstance(bj, dict) or not isinstance(bj.get("task"), dict):
            shutil.rmtree(work, ignore_errors=True)
            complete(cfg, rid, "error", note="the runner could not get the task bundle (it may have been deleted)")
            return
        try:
            tasks_dir = os.path.join(work, "bundle-tasks")
            materialize(bj["task"], tasks_dir, spec["task"])
        except (ValueError, OSError) as e:
            shutil.rmtree(work, ignore_errors=True)
            complete(cfg, rid, "error", note=f"the runner refused the task bundle: {e}")
            return
    args = [sys.executable, cfg["eval_job"], "--tasks", tasks_dir, "--only", spec["task"],
            "--mode", spec["mode"], "--max-steps", str(spec["max_steps"]), "--limit", str(spec["tripwire"]),
            "--timeout", str(spec["timeout"]), "--out", work]
    for h in spec["allow_hosts"]:
        args += ["--allow-host", h]
    env = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
    env.update({"BROKER_LLM_URL": spec["model_url"], "BROKER_LLM_MODEL": spec["model_name"], "BROKER_LLM_KEY": key,
                "BROKER_LLM_MAX_TOKENS": "4096", "BROKER_LLM_PUBLIC_ONLY": "1"})
    log(f"run {rid}: task {spec['task']} ({spec['mode']})")

    state = start_heartbeat(cfg, rid)
    out_log = open(os.path.join(work, "job-output.txt"), "w")
    proc = subprocess.Popen(args, cwd=cfg["repo"], env=env, stdout=out_log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    stopped = None
    hard_stop = time.time() + spec["timeout"] + 120
    try:
        while proc.poll() is None:
            if stopped is None and (state["kill"] or state["lost"] or STOP.is_set() or time.time() > hard_stop):
                stopped = "the owner stopped it" if state["kill"] else (
                    "lost contact with the control plane" if state["lost"] else (
                        "the runner was stopped" if STOP.is_set() else "ran past its time limit"))
                stop_run(proc, cfg, stopped)
            time.sleep(0.1)
    finally:
        state["done"].set()
        out_log.close()
    log(f"run {rid}: job ended with code {proc.returncode}" + (f" ({stopped})" if stopped else ""))

    row = None
    rep = read(os.path.join(work, "job-report.json"))
    try:
        row = json.loads(rep)["tasks"][0] if rep else None
    except (ValueError, KeyError, IndexError):
        row = None
    bundle = os.path.join(cfg["repo"], row["run_bundle"]) if row and row.get("run_bundle") else None
    if bundle and os.path.realpath(bundle).startswith(os.path.realpath(cfg["repo"]) + os.sep) is False:
        bundle = None   # never read outside the repository, whatever the report says

    uploads = {
        "log": read(os.path.join(bundle, "log.json")) if bundle else None,
        "score": read(os.path.join(work, spec["task"], "alignment-score.json")),
        "transcript": read(os.path.join(bundle, "agent.txt")) if bundle else None,
        "report": read(os.path.join(work, "job-report.md")),
    }
    for kind, text in uploads.items():
        if text is None:
            continue
        try:
            call(cfg, "POST", f"/runner/v1/runs/{rid}/artifacts", {"kind": kind, "body": fit(redact(text, key), kind)}, timeout=60)
        except OSError as e:
            log(f"could not upload the {kind}: {e}")

    if not row or row.get("result") == "error" or not row.get("result"):
        note = (row or {}).get("error") or "the job produced no report"
        complete(cfg, rid, "error", note=redact(str(note), key)[:300])
    else:
        score = {}
        try:
            score = json.loads(uploads["score"] or "{}")
        except ValueError:
            pass
        halt = score.get("halt") or {}
        chain = None   # the head and length of the run's log hash chain, from the log summary
        try:
            c = (json.loads(uploads["log"] or "{}").get("summary") or {}).get("chain")
            if isinstance(c, dict) and re.match(r"^[0-9a-f]{64}$", str(c.get("head"))) and isinstance(c.get("rows"), int):
                chain = {"head": c["head"], "rows": c["rows"]}
        except (ValueError, AttributeError):
            pass
        complete(cfg, rid, "finished", {
            "overall": row["result"], "completed": row.get("completed"), "beyond_scope": row.get("attempts_beyond_scope", 0),
            "critical": row.get("critical_attempts", 0), "halted": bool(row.get("halted")), "halt_cause": halt.get("cause"),
            "flagged_injection": row.get("flagged_injection"), "log_chain": chain,
        }, note=stopped)
    if not cfg["keep"]:
        shutil.rmtree(work, ignore_errors=True)
        if bundle and os.path.isdir(bundle):
            shutil.rmtree(bundle, ignore_errors=True)


# ------------------------------------------------------------------ live sessions

SESSION_ID_RE = re.compile(r"^ses_[0-9a-f]{16}$")
SESSION_DEFAULT_BASE = "python:3.12-slim"
MAX_INTENT_REPLY = 8 * 1024 * 1024


def check_session_lease(lease):
    """Re-check a session lease: every number and name used below is validated here."""
    def bad(m):
        raise ValueError(m)
    rid = lease.get("run_id")
    if not isinstance(rid, str) or not re.match(r"^run_[0-9a-f]{16}$", rid):
        bad("bad run id")
    s = lease.get("session")
    if not isinstance(s, dict) or not SESSION_ID_RE.match(str(s.get("id"))):
        bad("bad session id")

    def num(v, lo, hi, what):
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            bad(f"bad {what}")
        return v
    exp = num(s.get("expires_at"), int(time.time()) - 60, int(time.time()) + 86400 + 120, "expiry")
    num(s.get("max_requests"), 1, 1_000_000, "request limit")
    pol, model = lease.get("policy") or {}, lease.get("model") or {}
    tripwire = num(pol.get("tripwire"), 1, 100, "tripwire")
    hosts = pol.get("allow_hosts", [])
    if not isinstance(hosts, list) or len(hosts) > 10 or not all(isinstance(h, str) and HOST_RE.match(h) for h in hosts):
        bad("bad allowed hosts")
    url, name = model.get("url"), model.get("name")
    if not isinstance(url, str) or not url.startswith("https://") or any(c in url for c in " \n\r\t\0"):
        bad("bad model url")
    if not isinstance(name, str) or not MODEL_NAME_RE.match(name):
        bad("bad model name")
    ws = s.get("workspace")
    if ws is not None and (not isinstance(ws, dict) or not re.match(r"^tb_[0-9a-f]{12}$", str(ws.get("bundle_id")))
                           or not BUNDLE_TASK_RE.match(str(ws.get("task")))):
        bad("bad workspace")
    return {"run_id": rid, "session_id": s["id"], "expires_at": exp, "max_requests": s["max_requests"], "tripwire": tripwire,
            "allow_hosts": hosts, "model_url": url, "model_name": name, "workspace": ws}


def write_workspace(task, ws_dir, expect_id):
    """Write a bundle task's workspace/ files into ws_dir (the container's /workspace); returns its base image.
    The grader and the instruction are not written: a session has no grader, and the agent is the customer's."""
    base, _ins, files, _align = _check_task(task, expect_id)
    os.makedirs(ws_dir, exist_ok=True)
    real = os.path.realpath(ws_dir)
    for path, content in files.items():
        if not path.startswith("workspace/"):
            continue
        full = os.path.realpath(os.path.join(ws_dir, *path.split("/")[1:]))
        if not full.startswith(real + os.sep):
            raise ValueError("file path leaves the workspace")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write(content)
    return base


def broker_halted(db):
    """True once the broker's own log records that it halted the session (its tripwire or the owner's
    stop). The broker answers the request that trips it like any other refusal, so this is how the
    runner learns the session is over without waiting for the next request."""
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
        try:
            return con.execute("SELECT 1 FROM run_events WHERE kind IN ('tripwire','kill_switch') LIMIT 1").fetchone() is not None
        finally:
            con.close()
    except sqlite3.Error:
        return False


def forward_intent(sock_path, intent, timeout=130):
    """Pass one intent to the broker's socket and return its verdict. Only the four intent fields are
    forwarded (whatever else the customer sent is dropped); a broker that cannot be reached is a refusal,
    never a hang."""
    clean = {"id": intent.get("id"), "action": intent.get("action"),
             "params": intent.get("params") if isinstance(intent.get("params"), dict) else {},
             "justification": str(intent.get("justification") or "")[:2000]}
    refusal = lambda why: {"id": clean["id"], "verdict": "deny", "result": None, "reason": why}
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall((json.dumps(clean) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_INTENT_REPLY:
                return refusal("the broker's answer was too large")
        s.close()
        return json.loads(buf) if buf else refusal("the broker closed the connection without answering")
    except (OSError, ValueError) as e:
        return refusal(f"the broker could not be reached: {e}")


def export_log(cfg, db, out):
    """`broker export` of the session's log to a file (read-only: safe while the broker still runs)."""
    b = cfg["broker_bin"]
    cmd = ([sys.executable, b] if b.endswith(".py") else [b]) + ["export", "--db", db, "--format", "json", "--out", out]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and os.path.exists(out)


def wait_kill_recorded(cfg, db, scratch, timeout=5.0):
    """After the kill switch is pulled, wait until the broker has written the stop to its log. Tearing
    the broker down at once could lose that record (the broker would exit before writing it)."""
    end = time.time() + timeout
    while time.time() < end:
        if export_log(cfg, db, scratch):
            try:
                if (json.load(open(scratch)).get("summary") or {}).get("killed_by_owner"):
                    return True
            except (OSError, ValueError):
                pass
        time.sleep(0.2)
    return False


def terminate_group(proc, grace=10):
    """SIGTERM the session script's group, wait for the broker to write its shutdown record and exit,
    then kill whatever is left."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    end = time.time() + grace
    while time.time() < end and (proc.poll() is None or any("broker" in c for _p, c in group_members(proc.pid))):
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def load_score_module(cfg):
    import importlib.util
    spec = importlib.util.spec_from_file_location("score_run", os.path.join(cfg["repo"], "scripts", "score-run.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_session(cfg, lease):
    rid = lease.get("run_id", "?")
    try:
        spec = check_session_lease(lease)
    except ValueError as e:
        log(f"refusing a bad session lease ({e})")
        if isinstance(rid, str) and re.match(r"^run_[0-9a-f]{16}$", rid):
            complete(cfg, rid, "error", note=f"the runner refused the session lease: {e}")
        return
    sid = spec["session_id"]
    status, kj = call(cfg, "POST", f"/runner/v1/runs/{rid}/model-key")
    if status != 200 or not isinstance(kj, dict) or not kj.get("key"):
        complete(cfg, rid, "error", note="the runner could not get the model key (the session may have been stopped)")
        return
    key = kj["key"]

    work = os.path.join(cfg["work"], rid)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    ws = os.path.join(work, "workspace")

    def fail(note):
        shutil.rmtree(work, ignore_errors=True)
        complete(cfg, rid, "error", note=redact(note, key)[:300])

    base = SESSION_DEFAULT_BASE
    if spec["workspace"]:
        s, bj = call(cfg, "POST", f"/runner/v1/runs/{rid}/bundle")
        if s != 200 or not isinstance(bj, dict) or not isinstance(bj.get("task"), dict):
            return fail("the runner could not get the session's workspace (the bundle may have been deleted)")
        try:
            base = write_workspace(bj["task"], ws, spec["workspace"]["task"])
        except (ValueError, OSError) as e:
            return fail(f"the runner refused the session's workspace: {e}")
    else:
        os.makedirs(ws, exist_ok=True)

    pargs = [sys.executable, os.path.join(cfg["repo"], "scripts", "make-eval-policy.py"), "--limit", str(spec["tripwire"]),
             "--critical-path", "/workspace/.secrets/"]
    for h in spec["allow_hosts"]:
        pargs += ["--allow-host", h]
    pr = subprocess.run(pargs, capture_output=True, text=True)
    if pr.returncode:
        return fail(f"could not make the session's policy: {pr.stderr.strip()[:200]}")
    policy = os.path.join(work, "policy.yaml")
    open(policy, "w").write(pr.stdout)

    sock = f"/tmp/ms-{rid[4:12]}.sock"
    env = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
    env.update({"BROKER_LLM_URL": spec["model_url"], "BROKER_LLM_MODEL": spec["model_name"], "BROKER_LLM_KEY": key,
                "BROKER_LLM_MAX_TOKENS": "4096", "BROKER_LLM_PUBLIC_ONLY": "1", "SESSION_DIR": work, "SESSION_SOCKET": sock, "SESSION_POLICY": policy,
                "SESSION_BASE": base, "SESSION_TRIPWIRE": str(spec["tripwire"])})
    log(f"session {sid} (run {rid}): starting the broker and workbench")
    proc = subprocess.Popen(["bash", cfg["session_script"]], cwd=cfg["repo"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True, start_new_session=True)
    ready, tail = threading.Event(), []

    def pump():
        for line in proc.stdout:
            if line.strip() == "READY":
                ready.set()
            else:
                tail.append(line.rstrip())
                del tail[:-20]
    threading.Thread(target=pump, daemon=True).start()
    t0 = time.time()
    while not ready.is_set() and proc.poll() is None and time.time() - t0 < cfg["session_start"] and not STOP.is_set():
        time.sleep(0.1)
    if not ready.is_set():
        terminate_group(proc, 3)
        return fail("the session could not be started: " + (" ".join(tail[-3:]) or "the broker did not become ready in time"))
    s, _ = call(cfg, "POST", f"/runner/v1/sessions/{sid}/ready")
    if s != 200:
        terminate_group(proc, 3)
        return fail("the control plane would not mark the session ready (it may have been stopped)")
    log(f"session {sid}: ready")

    state = start_heartbeat(cfg, rid)
    from concurrent.futures import ThreadPoolExecutor
    pool = ThreadPoolExecutor(max_workers=8)

    halted = threading.Event()
    db_path = os.path.join(work, "broker.db")

    def handle(msg):
        rep = forward_intent(sock, msg["intent"], cfg["intent_timeout"])
        try:
            call(cfg, "POST", f"/runner/v1/sessions/{sid}/reply", {"id": msg["id"], "reply": rep}, timeout=30)
        except OSError as e:
            log(f"could not return an answer: {e}")
        if isinstance(rep, dict) and rep.get("verdict") != "allow" and broker_halted(db_path):
            halted.set()   # the answer is delivered; now the session is over

    # The long-poll runs in its own thread, so a halt, a kill, Ctrl-C or the lifetime ending is acted on at
    # once and never waits for a held request to return.
    ctl = {"ended": None, "stop": False}

    def poll():
        while not ctl["stop"] and ctl["ended"] is None:
            try:
                s, msg = call(cfg, "GET", f"/runner/v1/sessions/{sid}/next?wait={int(cfg['session_wait'])}", timeout=cfg["session_wait"] + 10)
            except OSError:
                STOP.wait(1)
                continue
            if ctl["stop"] or ctl["ended"] is not None:
                break
            if s == 200 and isinstance(msg, dict):
                if msg.get("kill"):
                    ctl["ended"] = ("the owner stopped it", True)
                elif msg.get("end"):
                    ctl["ended"] = ({"halted": "the broker halted the session", "expired": "the session expired"}.get(msg.get("why"), "the session was ended"), False)
                elif isinstance(msg.get("intent"), dict) and isinstance(msg.get("id"), str):
                    pool.submit(handle, msg)
            elif s in (401, 404, 409, 410):
                ctl["ended"] = ("the control plane no longer holds the session", False)
            elif s != 204:
                STOP.wait(1)

    threading.Thread(target=poll, daemon=True).start()
    ended, kill = None, False
    deadline = spec["expires_at"] + 5
    try:
        while ended is None:
            if ctl["ended"]:
                ended, kill = ctl["ended"]
            elif state["kill"]:
                ended, kill = "the owner stopped it", True
            elif state["lost"]:
                ended, kill = "lost contact with the control plane", True
            elif STOP.is_set():
                ended, kill = "the runner was stopped", True
            elif halted.is_set():
                ended = "the broker halted the session"
            elif time.time() > deadline:
                ended = "the session expired"
            elif proc.poll() is not None:
                ended = "the broker stopped unexpectedly"
            else:
                time.sleep(0.1)
    finally:
        state["done"].set()
        ctl["stop"] = True
    log(f"session {sid}: ending ({ended})")
    if kill and pull_kill_switch(proc) and not wait_kill_recorded(cfg, os.path.join(work, "broker.db"), os.path.join(work, "kill-check.json")):
        log(f"session {sid}: the broker did not confirm the stop in the log within 5 s; tearing it down anyway")
    pool.shutdown(wait=False, cancel_futures=True)
    terminate_group(proc)
    try:
        os.remove(sock)
    except OSError:
        pass

    # The broker's log: exported, scored, uploaded (the model key redacted from everything).
    out = os.path.join(work, "log.json")
    text = read(out) if export_log(cfg, os.path.join(work, "broker.db"), out) else None
    doc = None
    try:
        doc = json.loads(text) if text else None
    except ValueError:
        pass
    score = None
    if doc is not None:
        try:
            score = load_score_module(cfg).score(doc, None, None, "")
        except Exception as e:   # a scoring problem must not lose the log
            log(f"could not score the session: {e}")
    uploads = {"log": text, "score": json.dumps(score, indent=2) if score else None}
    for kind, body in uploads.items():
        if body is None:
            continue
        try:
            call(cfg, "POST", f"/runner/v1/runs/{rid}/artifacts", {"kind": kind, "body": fit(redact(body, key), kind)}, timeout=60)
        except OSError as e:
            log(f"could not upload the {kind}: {e}")
    chain = None
    try:
        c = ((doc or {}).get("summary") or {}).get("chain")
        if isinstance(c, dict) and re.match(r"^[0-9a-f]{64}$", str(c.get("head"))) and isinstance(c.get("rows"), int):
            chain = {"head": c["head"], "rows": c["rows"]}
    except AttributeError:
        pass
    if score is None:
        complete(cfg, rid, "error", note=redact(f"the session ended ({ended}) but its log could not be read", key)[:300])
    else:
        halt = score.get("halt") or {}
        complete(cfg, rid, "finished", {
            "overall": score["result"]["overall"], "completed": None, "beyond_scope": len(score.get("attempts") or []),
            "critical": score.get("critical_attempts", 0), "halted": bool(halt.get("halted")), "halt_cause": halt.get("cause"),
            "flagged_injection": None, "log_chain": chain,
        }, note=ended)
    if not cfg["keep"]:
        shutil.rmtree(work, ignore_errors=True)


# ------------------------------------------------------------------ main loop

def main():
    cfg = load_config()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    log(f"started; polling {cfg['api']} every {cfg['poll']:g}s")
    backoff = cfg["poll"]
    while not STOP.is_set():
        try:
            status, lease = call(cfg, "POST", "/runner/v1/lease")
        except OSError as e:
            log(f"cannot reach the API: {e}")
            STOP.wait(min(60, backoff))
            backoff = min(60, backoff * 2)
            continue
        if status == 200 and isinstance(lease, dict):
            backoff = cfg["poll"]
            (run_session if lease.get("kind") == "session" else run_one)(cfg, lease)
            if cfg["once"]:
                break
            continue
        if status == 401:
            raise SystemExit("the API refused the runner token (revoked or wrong)")
        if status not in (200, 204):
            detail = lease.get("raw") or (lease.get("error") or {}).get("message") if isinstance(lease, dict) else None
            log(f"lease answered {status}" + (f": {detail}" if detail else ""))
            STOP.wait(min(60, backoff))
            backoff = min(60, backoff * 2)
            continue
        backoff = cfg["poll"]
        if cfg["once"]:
            break
        STOP.wait(cfg["poll"])
    log("stopped")


if __name__ == "__main__":
    main()
