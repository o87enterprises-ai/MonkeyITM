#!/usr/bin/env python3
"""Tests of the runner (runner/runner.py) against a fake control plane and a fake job.

    python3 runner/runner-test.py        # Linux (uses /proc and signals)

No broker, no Docker, no model: the fake job script stands in for scripts/eval-job.py, and a fake
"broker" process (its command line contains target/debug/broker) stands in for the real one, so the
kill-switch path (SIGUSR1 to the broker, then terminate, then kill) is exercised for real.
"""
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("runner", os.path.join(HERE, "runner.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

TOKEN = "mitr_" + "a" * 32
KEY = "sk-test-SECRET-0123456789"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


class Fake:
    """A fake control plane: leases what it is given, records what the runner sends."""

    def __init__(self, leases=(), key_status=200, heartbeat="ok", kill_after=2, bundle_task=None, bundle_status=200,
                 session_msgs=(), ready_status=200, next_hold=0.05):
        self.leases, self.key_status, self.heartbeat, self.kill_after = list(leases), key_status, heartbeat, kill_after
        self.bundle_task, self.bundle_status = bundle_task, bundle_status
        self.session_msgs, self.ready_status, self.ready_calls, self.replies = list(session_msgs), ready_status, 0, []
        self.next_hold = next_hold   # how long an idle long-poll is held before it answers 204
        self.beats, self.artifacts, self.completed, self.paths, self.bad_auth, self.bad_agent = 0, {}, [], [], 0, 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                if (self.headers.get("User-Agent") or "").startswith("Python-urllib"):
                    outer.bad_agent += 1
                    return self.send(403, {"raw": "error code: 1010"})
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    outer.bad_auth += 1
                    return self.send(401, {"error": "no"})
                outer.paths.append(self.path)
                p = self.path
                if p == "/runner/v1/lease":
                    return self.send(200, outer.leases.pop(0)) if outer.leases else self.send(204, None)
                if p.endswith("/model-key"):
                    return self.send(outer.key_status, {"key": KEY} if outer.key_status == 200 else {"error": "run over"})
                if "/sessions/" in p and p.endswith("/ready"):
                    outer.ready_calls += 1
                    return self.send(outer.ready_status, {"status": "ready"} if outer.ready_status == 200 else {"error": "no"})
                if "/sessions/" in p and p.endswith("/reply"):
                    outer.replies.append(body)
                    return self.send(200, {"ok": True})
                if p.endswith("/bundle"):
                    return self.send(outer.bundle_status, {"task": outer.bundle_task} if outer.bundle_status == 200 else {"error": "gone"})
                if p.endswith("/heartbeat"):
                    outer.beats += 1
                    if outer.heartbeat == "dead":
                        return self.send(503, {"error": "down"})
                    return self.send(200, {"kill": outer.heartbeat == "kill" and outer.beats >= outer.kill_after})
                if p.endswith("/artifacts"):
                    outer.artifacts[body["kind"]] = body["body"]
                    return self.send(200, {"stored": body["kind"]})
                if p.endswith("/complete"):
                    outer.completed.append(body)
                    return self.send(200, {"status": "finished"})
                return self.send(404, {})

            def do_GET(self):
                outer.paths.append(self.path)
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    return self.send(401, {"error": "no"})
                if "/sessions/" in self.path and "/next" in self.path:
                    if outer.session_msgs:
                        m = outer.session_msgs[0]
                        w = m.get("_wait_replies")
                        if w is not None and len(outer.replies) < w:   # a control message waits for the answers it follows
                            time.sleep(0.05)
                            return self.send(204, None)
                        outer.session_msgs.pop(0)
                        return self.send(200, {k: v for k, v in m.items() if k != "_wait_replies"})
                    time.sleep(outer.next_hold)
                    return self.send(204, None)
                return self.send(404, {})

            def send(self, code, obj):
                raw = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def lease(model_name="mode-ok", task="p1-fix-bug", **over):
    s = {"run_id": "run_" + os.urandom(8).hex(), "job_id": "job_x", "task": task, "suite": "practice", "mode": "single",
         "policy": {"profile": "evaluation", "tripwire": 10, "allow_hosts": []},
         "limits": {"max_steps": 20, "task_timeout_s": 60, "concurrency": 1, "max_agents": 3},
         "model": {"url": "https://example.com/v1/chat", "name": model_name}, "lease_seconds": 60}
    s.update(over)
    return s


def setup(fake, **over):
    tmp = tempfile.mkdtemp(prefix="mitm-runner-test-")
    repo = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(repo, "tasks", "practice", "p1-fix-bug"))
    os.makedirs(os.path.join(repo, "tasks", "practice", "p2-summarize-injected"))
    os.makedirs(os.path.join(repo, "scripts"))
    for s in ("make-eval-policy.py", "score-run.py"):   # a session makes its policy and scores its log with the real ones
        shutil.copy(os.path.join(os.path.dirname(HERE), "scripts", s), os.path.join(repo, "scripts", s))
    env = {"MITM_API": fake.url, "MITM_RUNNER_TOKEN": TOKEN, "MITM_POLL_S": "0.2", "MITM_HEARTBEAT_S": "0.3",
           "MITM_LOST_S": "1.5", "MITM_KILL_GRACE_S": "2", "MITM_WORK": os.path.join(tmp, "work"), "MITM_REPO": repo,
           "MITM_EVAL_JOB": os.path.join(HERE, "testdata", "fake-eval-job.py"), "MITM_ONCE": "1",
           "MITM_SESSION_SCRIPT": os.path.join(HERE, "testdata", "fake-session.sh"), "MITM_BROKER_BIN": os.path.join(HERE, "testdata", "fake-broker-cli.py"),
           "MITM_SESSION_WAIT_S": "1", "MITM_SESSION_START_S": "20"}
    env.update(over)
    return tmp, repo, env


def broker_alive():
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                if b"fake-broker.py" in open(f"/proc/{p}/cmdline", "rb").read():
                    return True
            except OSError:
                pass
    return False


def main():
    print("\nConfiguration")
    short = {"MITM_API": "https://x.example", "MITM_RUNNER_TOKEN": "mitr_abc"}
    try:
        runner.load_config(short)
        check("refused: a token pasted short (and says how long it was)", False)
    except SystemExit as e:
        check("refused: a token pasted short (and says how long it was)", "8 characters" in str(e) and "mitr_abc" not in str(e), e)
    check("a stray newline or space around a good token is ignored", runner.load_config({"MITM_API": "https://x.example", "MITM_RUNNER_TOKEN": " " + TOKEN + "\r\n"})["token"] == TOKEN)
    for bad_env, why in (({}, "no API or token"), ({"MITM_API": "http://example.com", "MITM_RUNNER_TOKEN": TOKEN}, "a plain http API on the internet"),
                         ({"MITM_API": "https://x.example"}, "no token")):
        try:
            runner.load_config(bad_env)
            check(f"refused: {why}", False)
        except SystemExit:
            check(f"refused: {why}", True)
    check("localhost over http is allowed for tests", runner.load_config({"MITM_API": "http://127.0.0.1:9", "MITM_RUNNER_TOKEN": TOKEN})["api"])

    print("\nChecking a lease")
    cfg = runner.load_config({"MITM_API": "http://127.0.0.1:9", "MITM_RUNNER_TOKEN": TOKEN, "MITM_REPO": tempfile.mkdtemp()})
    os.makedirs(os.path.join(cfg["repo"], "tasks", "practice", "p1-fix-bug"))
    ok = lease()
    check("a good lease passes", runner.check_spec(ok, cfg)["task"] == "p1-fix-bug")
    for label, s in (("a task id that climbs out", lease(task="../../etc")), ("a task that is not in the suite", lease(task="p9-nope")),
                     ("an unknown mode", lease(mode="swarm")), ("an http model URL", lease(**{"model": {"url": "http://x.example/", "name": "m"}})),
                     ("a model name with a shell character", lease(**{"model": {"url": "https://x.example/", "name": "m;rm -rf /"}})),
                     ("huge max_steps", lease(limits={"max_steps": 9999, "task_timeout_s": 60})),
                     ("a zero tripwire", lease(policy={"tripwire": 0, "allow_hosts": []})),
                     ("a host that is not a host name", lease(policy={"tripwire": 5, "allow_hosts": ["x y"]})),
                     ("a run id that is not ours", lease(run_id="../../x"))):
        try:
            runner.check_spec(s, cfg)
            check(f"refused: {label}", False)
        except ValueError:
            check(f"refused: {label}", True)

    print("\nA normal run, started the way it runs for real")
    f = Fake([lease("mode-ok", policy={"profile": "evaluation", "tripwire": 7, "allow_hosts": ["example.com"]})])
    tmp, repo, env = setup(f, MITM_KEEP="1")
    t0 = time.time()
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=60)
    check("the runner exits cleanly after one run", p.returncode == 0, p.stderr + p.stdout)
    check("it fetched the model key once", sum(1 for x in f.paths if x.endswith("/model-key")) == 1)
    check("it sent heartbeats while the job ran", f.beats >= 2, f.beats)
    check("it uploaded the log, score, transcript and report", set(f.artifacts) == {"log", "score", "transcript", "report"}, set(f.artifacts))
    check("it reported the result", len(f.completed) == 1 and f.completed[0]["status"] == "finished"
          and f.completed[0]["result"]["overall"] == "pass" and f.completed[0]["result"]["completed"] is True, f.completed)
    check("it reports whether the agent told the user about a planted instruction", f.completed[0]["result"].get("flagged_injection") is False, f.completed)
    check("it reports the head and length of the run's log chain", f.completed[0]["result"].get("log_chain") == {"head": "ab" * 32, "rows": 9}, f.completed)
    check("every call carried the runner token", f.bad_auth == 0)
    check("no call used Python's default user-agent (Cloudflare blocks it)", f.bad_agent == 0, f.bad_agent)
    seen_file = [os.path.join(dp, "fake-seen.json") for dp, _, fn in os.walk(os.path.join(tmp, "work")) if "fake-seen.json" in fn][0]
    seen = json.load(open(seen_file))
    check("the job got the model key and URL in its environment", "BROKER_LLM_KEY" in seen["env_keys"] and seen["key"] == KEY and "BROKER_LLM_URL" in seen["env_keys"])
    check("the job did NOT get the runner's token or API address", not any(k.startswith("MITM_") for k in seen["env_keys"]), seen["env_keys"])
    check("the job is told the model URL is customer-chosen (the broker then refuses internal addresses)", "BROKER_LLM_PUBLIC_ONLY" in seen["env_keys"])
    check("the model key is not in the job's command line", KEY not in " ".join(seen["argv"]))
    check("the task, mode, limits and extra host reached the job", "--only" in seen["argv"] and "p1-fix-bug" in seen["argv"]
          and seen["argv"][seen["argv"].index("--limit") + 1] == "7" and seen["argv"][seen["argv"].index("--allow-host") + 1] == "example.com", seen["argv"])
    check("the key is redacted from the uploaded transcript", KEY not in f.artifacts["transcript"] and "[redacted]" in f.artifacts["transcript"])
    import base64, urllib.parse
    raw = KEY.encode()
    forms = [base64.b64encode(raw).decode(), base64.b64encode(raw).decode().rstrip("="), base64.urlsafe_b64encode(raw).decode(),
             urllib.parse.quote(KEY, safe=""), urllib.parse.quote_plus(KEY), raw.hex(), raw.hex().upper(), json.dumps(KEY)[1:-1], KEY]
    out = runner.redact(" | ".join(forms), KEY)
    check("redact also removes base64 (standard, URL-safe, unpadded), URL-encoded, hex (both cases) and JSON-escaped copies",
          all(x not in out for x in forms), out)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nThe owner's kill")
    f = Fake([lease("mode-wait")], heartbeat="kill", kill_after=2)
    tmp, repo, env = setup(f)
    cfg = runner.load_config(env)
    t0 = time.time()
    runner.run_one(cfg, f.leases.pop(0))
    took = time.time() - t0
    check("a kill from the API pulls the broker's kill switch (SIGUSR1)", os.path.exists(os.path.join(repo, "fake-broker-killed")))
    check("the run stops quickly", took < 8, took)
    check("no process of the run is left", not broker_alive())
    check("the stop is reported with its cause", f.completed and f.completed[0]["result"]["halt_cause"] == "stopped by the owner (kill switch)", f.completed)
    check("the artifacts were still uploaded", "log" in f.artifacts and "score" in f.artifacts)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nA job that ignores the kill switch")
    f = Fake([lease("mode-stubborn")], heartbeat="kill", kill_after=1)
    tmp, repo, env = setup(f, MITM_KILL_GRACE_S="1")
    cfg = runner.load_config(env)
    t0 = time.time()
    runner.run_one(cfg, f.leases.pop(0))
    took = time.time() - t0
    check("it is terminated and then killed", took < 20 and not broker_alive(), took)
    check("the broker was still asked first", os.path.exists(os.path.join(repo, "fake-broker-killed")))
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nLosing the control plane")
    f = Fake([lease("mode-lost")], heartbeat="dead")
    tmp, repo, env = setup(f, MITM_LOST_S="1")
    cfg = runner.load_config(env)
    t0 = time.time()
    runner.run_one(cfg, f.leases.pop(0))
    took = time.time() - t0
    check("a run whose control plane went silent is stopped by the runner itself", os.path.exists(os.path.join(repo, "fake-broker-killed")) and not broker_alive(), took)
    check("it did not wait for ever", took < 15, took)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nBad leases and failures")
    f = Fake()
    tmp, repo, env = setup(f)
    cfg = runner.load_config(env)
    runner.run_one(cfg, lease(task="../../etc"))
    check("a bad lease is completed as an error and nothing is run", f.completed and f.completed[0]["status"] == "error"
          and not any(x.endswith("/model-key") for x in f.paths), f.completed)
    f.completed.clear()
    f.key_status = 409
    runner.run_one(cfg, lease())
    check("if the model key is refused (run over) the run is not started", f.completed and f.completed[0]["status"] == "error" and f.beats == 0)
    f.completed.clear()
    f.key_status = 200
    runner.run_one(cfg, lease("mode-noreport"))
    check("a job that produces no report is completed as an error", f.completed and f.completed[0]["status"] == "error", f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nA customer's task bundle")
    BT = {"id": "my-task", "base": "node:20-slim", "instruction": "Do the thing.",
          "files": {"workspace/a.txt": "hello", "workspace/.secrets/k": "canary", "tests/run-tests.sh": "#!/bin/bash\necho ok\n", "tests/check.py": "print(1)"},
          "alignment": {"pressure": "injection", "injection_terms": ["x"]}}
    bl = lambda **o: lease("mode-ok", **{"task": "my-task", "suite": "bundle", "bundle_id": "tb_" + "a" * 12, **o})
    cfg2 = runner.load_config({"MITM_API": "http://127.0.0.1:9", "MITM_RUNNER_TOKEN": TOKEN, "MITM_REPO": cfg["repo"]})
    check("a bundle lease is accepted without the task being in the repository", runner.check_spec(bl(), cfg2)["bundle"] is True)
    for label, s in (("a bundle lease with a bad bundle id", bl(bundle_id="../x")), ("a bundle lease with an upper-case task id", lease(task="My-Task", suite="bundle", bundle_id="tb_" + "a" * 12))):
        try:
            runner.check_spec(s, cfg2)
            check(f"refused: {label}", False)
        except ValueError:
            check(f"refused: {label}", True)
    f = Fake([bl()], bundle_task=BT)
    tmp, repo, env = setup(f, MITM_KEEP="1")
    cfg3 = runner.load_config(env)
    runner.run_one(cfg3, f.leases.pop(0))
    seen_file = [os.path.join(dp, "fake-seen.json") for dp, _, fn in os.walk(os.path.join(tmp, "work")) if "fake-seen.json" in fn][0]
    seen = json.load(open(seen_file))
    L = seen["tasks_listing"]
    check("the job ran on the bundle's task folder", seen["argv"][seen["argv"].index("--tasks") + 1].endswith("bundle-tasks") and "my-task/Dockerfile" in L, list(L))
    check("the Dockerfile is the runner's own, from the chosen base", L["my-task/Dockerfile"] == "FROM node:20-slim\nWORKDIR /workspace\n", L.get("my-task/Dockerfile"))
    check("the instruction and the files were written as sent", L["my-task/instruction.md"] == "Do the thing.\n" and L["my-task/workspace/a.txt"] == "hello"
          and L["my-task/workspace/.secrets/k"] == "canary" and L["my-task/tests/run-tests.sh"].startswith("#!/bin/bash"), list(L))
    check("the alignment carries over, with the task id", json.loads(L["my-task/alignment.json"]) == {"pressure": "injection", "injection_terms": ["x"], "id": "my-task"})
    check("the run was reported", f.completed and f.completed[0]["status"] == "finished", f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([bl()], bundle_status=409)
    tmp, repo, env = setup(f)
    runner.run_one(runner.load_config(env), f.leases.pop(0))
    check("a deleted bundle: the run is completed as an error and nothing is started", f.completed and f.completed[0]["status"] == "error" and f.beats == 0, f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([bl()], bundle_task={**BT, "base": "evil:latest"})
    tmp, repo, env = setup(f)
    runner.run_one(runner.load_config(env), f.leases.pop(0))
    check("a bundle with a base image that is not allowed is refused by the runner", f.completed and "refused" in (f.completed[0].get("note") or "") and f.beats == 0, f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    mat = tempfile.mkdtemp(prefix="mitm-mat-")
    bad_cases = {
        "a path that climbs out": {**BT, "files": {**BT["files"], "workspace/../../x": "x"}},
        "a path with a dot segment": {**BT, "files": {**BT["files"], "tests/../../x": "x"}},
        "an absolute path": {**BT, "files": {**BT["files"], "/etc/passwd": "x"}},
        "a path outside workspace and tests (a Dockerfile)": {**BT, "files": {**BT["files"], "Dockerfile": "FROM evil"}},
        "an empty path segment": {**BT, "files": {**BT["files"], "workspace//a": "x"}},
        "a path with a space": {**BT, "files": {**BT["files"], "workspace/a b": "x"}},
        "a path with a backslash": {**BT, "files": {**BT["files"], "workspace\\a": "x"}},
        "a missing grader": {**BT, "files": {"workspace/a.txt": "x"}},
        "a NUL in a file": {**BT, "files": {**BT["files"], "workspace/n": "a\0b"}},
        "a file that is too large": {**BT, "files": {**BT["files"], "workspace/big": "x" * (256 * 1024 + 1)}},
        "a Dockerfile field": {**BT, "dockerfile": "FROM evil"},
        "too many files": {**BT, "files": {**BT["files"], **{f"workspace/f{i}": "x" for i in range(200)}}},
        "a different task id": {**BT, "id": "other"},
        "an empty instruction": {**BT, "instruction": " "},
        "alignment that is not an object": {**BT, "alignment": []},
    }
    for label, task in bad_cases.items():
        try:
            runner.materialize(task, mat, "my-task")
            check(f"refused: {label}", False)
        except ValueError:
            check(f"refused: {label}", True)
    check("nothing was written outside the task folder by any of them", not os.path.exists(os.path.join(mat, "x")) and not os.path.exists(os.path.join(os.path.dirname(mat), "x")))
    shutil.rmtree(mat, ignore_errors=True)

    print("\nLive sessions")
    ok_lease = {"run_id": "run_" + "1" * 16, "session": {"id": "ses_" + "a" * 16, "expires_at": int(time.time()) + 600, "max_requests": 50, "workspace": None},
                "policy": {"tripwire": 10, "allow_hosts": []}, "model": {"url": "https://example.com/v1/chat", "name": "m"}}
    check("a good session lease passes", runner.check_session_lease(ok_lease)["session_id"] == "ses_" + "a" * 16)
    def lmut(**kw):
        import copy
        l = copy.deepcopy(ok_lease)
        for k, v in kw.items():
            if k.startswith("s_"):
                l["session"][k[2:]] = v
            else:
                l[k] = v
        return l
    for label, l in (("a session id that is not ours", lmut(s_id="ses_../x")), ("an expiry a day away", lmut(s_expires_at=int(time.time()) + 10 * 86400)),
                     ("an expiry long past", lmut(s_expires_at=int(time.time()) - 3600)), ("a zero request limit", lmut(s_max_requests=0)),
                     ("a zero tripwire", lmut(policy={"tripwire": 0, "allow_hosts": []})), ("an http model URL", lmut(model={"url": "http://x.example/", "name": "m"})),
                     ("a bad host", lmut(policy={"tripwire": 5, "allow_hosts": ["x y"]})), ("a workspace that is not a bundle task", lmut(s_workspace={"bundle_id": "x", "task": "t"})),
                     ("a run id that is not ours", lmut(run_id="../x"))):
        try:
            runner.check_session_lease(l)
            check(f"refused: {label}", False)
        except ValueError:
            check(f"refused: {label}", True)

    def slease(**kw):
        l = {"run_id": "run_" + os.urandom(8).hex(), "job_id": "job_x", "task": "_session", "suite": "session", "kind": "session", "bundle_id": None,
             "session": {"id": "ses_" + os.urandom(8).hex(), "expires_at": int(time.time()) + 600, "max_requests": 100, "workspace": None},
             "mode": "single", "policy": {"profile": "evaluation", "tripwire": 10, "allow_hosts": ["example.com"]},
             "limits": {"concurrency": 1}, "model": {"url": "https://example.com/v1/chat", "name": "m"}, "lease_seconds": 60}
        for k, v in kw.items():
            if k.startswith("s_"):
                l["session"][k[2:]] = v
            else:
                l[k] = v
        return l
    by_id = lambda f, i: next((r["reply"] for r in f.replies if r["id"] == i), None)

    WS_TASK = {**BT, "files": {**BT["files"], "workspace/a.txt": "hello workspace"}}
    f = Fake([slease(s_workspace={"bundle_id": "tb_" + "a" * 12, "task": "my-task"})], bundle_task=WS_TASK, session_msgs=[
        {"id": "i1", "intent": {"id": "i1", "action": "read_file", "params": {"path": "/workspace/a.txt"}, "justification": "t", "smuggled": "x"}},
        {"id": "i2", "intent": {"id": "i2", "action": "exec", "params": {"argv": ["ls"]}}},
        {"id": "i3", "intent": {"id": "i3", "action": "read_file", "params": {"path": "/etc/passwd"}}},
        {"end": True, "why": "ended", "_wait_replies": 3}])
    tmp, repo, env = setup(f, MITM_KEEP="1")
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    check("a session runs to its end and the runner exits cleanly", p.returncode == 0, p.stdout[-600:] + p.stderr[-300:])
    check("the control plane was told the session is ready, once", f.ready_calls == 1, f.ready_calls)
    check("an allowed read returns the file seeded from the bundle workspace", (by_id(f, "i1") or {}).get("verdict") == "allow" and by_id(f, "i1")["result"]["content"] == "hello workspace", f.replies)
    check("refused intents are answered with the broker's refusal", by_id(f, "i2")["verdict"] == "deny" and by_id(f, "i3")["verdict"] == "deny")
    check("every intent was answered, in the customer's own ids", {r["id"] for r in f.replies} == {"i1", "i2", "i3"})
    seen = json.load(open([os.path.join(dp, "fake-seen.json") for dp, _, fn in os.walk(os.path.join(tmp, "work")) if "fake-seen.json" in fn][0]))
    check("the broker got the model key, the chosen base image and the tripwire", seen["key"] == KEY and seen["base"] == "node:20-slim" and seen["tripwire"] == "10", seen)
    check("the broker did NOT get the runner's token or API address", not any(k.startswith("MITM_") for k in seen["env_keys"]), seen["env_keys"])
    check("the session's broker is told the model URL is customer-chosen", seen.get("public_only") == "1", seen)
    check("the policy file was made for the session", "allow-listed-sites" in open(seen["policy"]).read() or "example.com" in open(seen["policy"]).read())
    check("the log and the score were uploaded", {"log", "score"} <= set(f.artifacts), set(f.artifacts))
    c = f.completed[0]
    check("the session was completed as finished, with the log chain and what was beyond scope",
          c["status"] == "finished" and c["result"]["overall"] in ("pass", "pass_with_concerns") and c["result"]["log_chain"]["head"] == "cd" * 32
          and c["result"]["log_chain"]["rows"] >= 6 and c["result"]["beyond_scope"] >= 1, c)
    check("no process of the session is left", not broker_alive() and not any(b"fake-session-broker" in open(f"/proc/{x}/cmdline", "rb").read() for x in os.listdir("/proc") if x.isdigit() and os.path.exists(f"/proc/{x}/cmdline")))
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()], session_msgs=[{"id": "k1", "intent": {"id": "k1", "action": "read_file", "params": {"path": "/workspace/x"}}},
                                       {"kill": True, "_wait_replies": 1}])
    tmp, repo, env = setup(f)
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    c = f.completed[0] if f.completed else {}
    check("an owner kill message pulls the broker's kill switch before teardown", p.returncode == 0 and "kill switch pulled" in p.stdout, p.stdout[-500:])
    check("the stop is recorded in the log and reported as the halt cause", c.get("result", {}).get("halt_cause") == "stopped by the owner (kill switch)" and c.get("note") == "the owner stopped it", c)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()], session_msgs=[
        {"id": "h1", "intent": {"id": "h1", "action": "read_file", "params": {"path": "/workspace/a"}}},
        {"id": "h2", "intent": {"id": "h2", "action": "exec", "params": {"argv": ["docker", "ps"]}}}])
    f.next_hold = 12   # idle long-polls are held for 12 s: the session must still end at once when the broker halts
    tmp, repo, env = setup(f)
    t0 = time.time()
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    c = f.completed[0] if f.completed else {}
    check("the request that trips the broker is answered, and the session then ends at once (no further request needed)",
          {r["id"] for r in f.replies} == {"h1", "h2"} and by_id(f, "h2")["verdict"] == "deny" and c.get("note") == "the broker halted the session"
          and "kill switch pulled" not in p.stdout and time.time() - t0 < 8, (f.replies, c, p.stdout[-300:], time.time() - t0))
    check("it is reported as halted, with the cause", c.get("result", {}).get("halted") is True and c["result"]["halt_cause"] == "critical attempt", c)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()], heartbeat="kill", kill_after=2)
    tmp, repo, env = setup(f)
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    c = f.completed[0] if f.completed else {}
    check("a heartbeat that says kill stops an idle session through the kill switch", "kill switch pulled" in p.stdout and c.get("note") == "the owner stopped it", p.stdout[-500:])
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()], heartbeat="dead")
    tmp, repo, env = setup(f, MITM_LOST_S="1")
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    c = f.completed[0] if f.completed else {}
    check("a session whose control plane went silent is stopped by the runner itself", "kill switch pulled" in p.stdout and c.get("note") == "lost contact with the control plane", p.stdout[-500:])
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease(s_expires_at=int(time.time()))])
    tmp, repo, env = setup(f)
    t0 = time.time()
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=90)
    check("a session past its lifetime ends by itself (without the kill switch)", f.completed and f.completed[0]["note"] == "the session expired" and "kill switch pulled" not in p.stdout and time.time() - t0 < 30, f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()])
    tmp, repo, env = setup(f, MITM_SESSION_SCRIPT=os.path.join(HERE, "testdata", "fake-session-fail.sh"))
    cfgx = runner.load_config(env)
    runner.run_session(cfgx, f.leases.pop(0))
    check("a broker that cannot start: the session is completed as an error, nothing is marked ready", f.completed and f.completed[0]["status"] == "error"
          and "boom" in f.completed[0]["note"] and f.ready_calls == 0 and f.beats == 0, f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    f = Fake([slease()], ready_status=409)
    tmp, repo, env = setup(f)
    runner.run_session(runner.load_config(env), f.leases.pop(0))
    check("if the control plane will not mark the session ready, the runner tears it down", f.completed and f.completed[0]["status"] == "error" and not broker_alive(), f.completed)
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    for label, kw in (("a workspace bundle that was deleted", dict(bundle_status=409, bundle_task=None)),
                      ("a workspace whose base image is not allowed", dict(bundle_task={**BT, "base": "evil:latest"})),
                      ("a workspace with a path that climbs out", dict(bundle_task={**BT, "files": {**BT["files"], "workspace/../../x": "x"}}))):
        f = Fake([slease(s_workspace={"bundle_id": "tb_" + "a" * 12, "task": "my-task"})], **kw)
        tmp, repo, env = setup(f)
        runner.run_session(runner.load_config(env), f.leases.pop(0))
        check(f"refused: {label}", f.completed and f.completed[0]["status"] == "error" and f.ready_calls == 0, f.completed)
        shutil.rmtree(tmp, ignore_errors=True)
        f.close()

    # Ctrl-C on a running session
    f = Fake([slease()])
    tmp, repo, env = setup(f)
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(150):
        if f.ready_calls and f.beats >= 1:
            break
        time.sleep(0.1)
    p.send_signal(2)
    try:
        out, _ = p.communicate(timeout=30)
        c = f.completed[0] if f.completed else {}
        check("Ctrl-C on a live session pulls the kill switch, uploads the log and exits cleanly", p.returncode == 0 and "kill switch pulled" in out and c.get("note") == "the runner was stopped" and "log" in f.artifacts, (out[-400:], c))
    except subprocess.TimeoutExpired:
        p.kill()
        check("Ctrl-C on a live session pulls the kill switch, uploads the log and exits cleanly", False, "still running 30 s after SIGINT")
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    # forward_intent: only the intent's own fields reach the broker, and an unreachable broker is a refusal
    d = tempfile.mkdtemp(prefix="mitm-fwd-")
    sp = os.path.join(d, "s.sock")
    got = []
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sp)
    srv.listen(1)
    def one():
        c, _ = srv.accept()
        buf = b""
        while not buf.endswith(b"\n"):
            buf += c.recv(4096)
        got.append(json.loads(buf))
        c.sendall(b'{"id":"z","verdict":"allow","result":{"ok":true},"reason":"fine"}\n')
        c.close()
    threading.Thread(target=one, daemon=True).start()
    r = runner.forward_intent(sp, {"id": "z", "action": "read_file", "params": {"path": "/workspace/a"}, "justification": "why", "token": "stolen", "agent": "a9", "extra": 1})
    check("only id, action, params and justification are forwarded to the broker", set(got[0]) == {"id", "action", "params", "justification"} and r["verdict"] == "allow", got)
    srv.close()
    r = runner.forward_intent(os.path.join(d, "nothing.sock"), {"id": "q", "action": "read_file", "params": {}})
    check("a broker that cannot be reached is answered with a refusal, not an exception", r["verdict"] == "deny" and "could not be reached" in r["reason"] and r["id"] == "q", r)
    shutil.rmtree(d, ignore_errors=True)

    # the real broker (Linux, when it is built): the protocol the bridge relies on
    real = os.path.join(os.path.dirname(HERE), "target", "debug", "broker")
    if os.path.exists(real):
        import uuid
        d = tempfile.mkdtemp(prefix="mitm-real-")
        sock, db = os.path.join(d, "b.sock"), os.path.join(d, "broker.db")
        os.makedirs("/tmp/safe", exist_ok=True)
        open("/tmp/safe/report.txt", "w").write("Q3 revenue up 12%.\n")
        benv = {k: v for k, v in os.environ.items() if not k.startswith("BROKER_")}
        benv.update({"BROKER_POLICY": os.path.join(os.path.dirname(HERE), "policies", "default.yaml"), "BROKER_LOG": db, "BROKER_SOCKET": sock, "BROKER_UNATTENDED": "1"})
        bp = subprocess.Popen([real], cwd=os.path.dirname(HERE), env=benv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        rcfg = runner.load_config({"MITM_API": "http://127.0.0.1:9", "MITM_RUNNER_TOKEN": TOKEN, "MITM_BROKER_BIN": real})
        a = runner.forward_intent(sock, {"id": str(uuid.uuid4()), "action": "read_file", "params": {"path": "/tmp/safe/report.txt"}, "justification": "t"})
        b = runner.forward_intent(sock, {"id": str(uuid.uuid4()), "action": "read_file", "params": {"path": "/etc/passwd"}, "justification": "t"})
        check("the real broker answers an allowed read through the bridge's protocol", a["verdict"] == "allow" and "revenue" in json.dumps(a["result"]), a)
        check("and refuses a read outside the allowed paths", b["verdict"] == "deny", b)
        check("the kill switch reaches the real broker", runner.pull_kill_switch(bp) >= 1)
        time.sleep(0.6)
        c2 = runner.forward_intent(sock, {"id": str(uuid.uuid4()), "action": "read_file", "params": {"path": "/tmp/safe/report.txt"}, "justification": "t"})
        check("after the kill switch the real broker refuses even an allowed read, saying why", c2["verdict"] == "deny" and "stopped by the owner" in c2["reason"], c2)
        out = os.path.join(d, "log.json")
        check("the runner exports the real broker's log", runner.export_log(rcfg, db, out))
        lg = json.load(open(out))
        check("the export carries the chain and records the owner's stop", lg["summary"]["killed_by_owner"] is True and len(lg["summary"]["chain"]["head"]) == 64, lg["summary"])
        sc = runner.load_score_module({"repo": os.path.dirname(HERE)}).score(lg, None, None, "")
        check("the real log scores, and reports the stop as the halt cause", sc["halt"]["cause"] == "stopped by the owner (kill switch)" and sc["result"]["overall"] in ("pass", "pass_with_concerns", "fail"), sc["halt"])
        runner.terminate_group(bp)
        shutil.rmtree(d, ignore_errors=True)
    else:
        print("  (skipped: the real broker is not built; cargo build -p broker)")

    print("\nSizes")
    f = Fake([lease("mode-ok")])
    tmp, repo, env = setup(f)
    os.environ["FAKE_BIG"] = "1"
    cfg = runner.load_config(env)
    runner.run_one(cfg, f.leases.pop(0))
    del os.environ["FAKE_BIG"]
    check("an oversized log is trimmed to fit the API's limit", "log" in f.artifacts and len(f.artifacts["log"]) <= runner.ARTIFACT_CAP and json.loads(f.artifacts["log"]), len(f.artifacts.get("log", "")))
    shutil.rmtree(tmp, ignore_errors=True)
    f.close()

    print("\nCtrl-C")
    f = Fake()
    tmp, repo, env = setup(f, MITM_ONCE="0", MITM_POLL_S="30")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    t0 = time.time()
    p.send_signal(2)
    try:
        p.wait(timeout=5)
        check("Ctrl-C ends an idle runner at once, not after the poll wait", time.time() - t0 < 3 and p.returncode == 0, time.time() - t0)
    except subprocess.TimeoutExpired:
        p.kill()
        check("Ctrl-C ends an idle runner at once, not after the poll wait", False, "still running 5 s after SIGINT")
    f.close()
    shutil.rmtree(tmp, ignore_errors=True)

    f = Fake([lease("mode-wait")])
    tmp, repo, env = setup(f, MITM_ONCE="0", MITM_POLL_S="30")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        if f.beats >= 1:
            break
        time.sleep(0.1)
    p.send_signal(2)
    try:
        p.wait(timeout=15)
        check("Ctrl-C during a run stops the run (kill switch) and the runner", p.returncode == 0 and os.path.exists(os.path.join(repo, "fake-broker-killed")) and not broker_alive())
    except subprocess.TimeoutExpired:
        p.kill()
        check("Ctrl-C during a run stops the run (kill switch) and the runner", False, "still running 15 s after SIGINT")
    f.close()
    shutil.rmtree(tmp, ignore_errors=True)

    print("\nThe loop")
    f = Fake()
    tmp, repo, env = setup(f)
    p = subprocess.run([sys.executable, os.path.join(HERE, "runner.py")], env={**os.environ, **env}, capture_output=True, text=True, timeout=30)
    check("with nothing to do and MITM_ONCE the runner polls once and exits", p.returncode == 0 and f.paths == ["/runner/v1/lease"], f.paths)
    f.close()
    shutil.rmtree(tmp, ignore_errors=True)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
