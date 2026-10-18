#!/usr/bin/env python3
"""Tests of the command line client (cli/monkeyitm.py) against a fake API: python3 cli/cli-test.py"""
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("monkeyitm", os.path.join(HERE, "monkeyitm.py"))
mi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mi)

KEY = "mitm_live_" + "a" * 32
MODEL_KEY = "nvapi-secret-0123456789-ZZZZ"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


class Fake:
    def __init__(self):
        self.requests, self.job_states, self.fail_next = [], [], None
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_any(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"null") if n else None
                outer.requests.append({"method": method, "path": self.path, "body": body, "auth": self.headers.get("Authorization"), "ua": self.headers.get("User-Agent")})
                if (self.headers.get("User-Agent") or "").startswith("Python-urllib"):
                    return self.send(403, "error code: 1010", raw=True)
                if self.headers.get("Authorization") != "Bearer " + KEY:
                    return self.send(401, {"error": {"code": "unauthorized", "message": "missing or invalid API key"}})
                if outer.fail_next:
                    code, err = outer.fail_next
                    outer.fail_next = None
                    return self.send(code, {"error": err})
                p = self.path.split("?")[0]
                if p == "/v1/usage":
                    return self.send(200, {"plan": "preview", "limits": {"concurrency": 1, "runs_month": 30}, "runs_this_month": 2, "runs_active": 0, "org_killed": False})
                if p == "/v1/jobs" and method == "POST":
                    return self.send(202, {"id": "job_abc", "status": "queued", "runs": 1})
                if p == "/v1/jobs":
                    return self.send(200, {"jobs": [{"id": "job_abc", "name": "t", "status": "finished", "gate": "pass", "runs": 1, "created_at": 1790000000}]})
                if p == "/v1/jobs/job_abc" and method == "GET":
                    st = outer.job_states.pop(0) if len(outer.job_states) > 1 else outer.job_states[0]
                    return self.send(200, {"id": "job_abc", "name": "t", **st})
                if p == "/v1/jobs/job_abc/runs":
                    return self.send(200, {"runs": [{"id": "run_1", "task": "p1-fix-bug", "status": "finished", "result": "pass", "completed": True,
                                                     "beyond_scope": 0, "halted": False, "flagged_injection": None, "log_chain": {"head": "ab" * 32, "rows": 9}}]})
                if p == "/v1/jobs/job_abc/kill":
                    return self.send(202, {"status": "killing", "runs_signalled": 1})
                if p == "/v1/jobs/job_abc/report":
                    return self.send(200, "# Evaluation report\n**Gate: PASS**\n", raw=True) if "format=md" in self.path else self.send(
                        200, {"job": {"status": "finished"}, "tier_gate": "pass", "counts": {}})
                if p == "/v1/jobs/job_abc/runs/run_1/transcript":
                    return self.send(200, "agent said hi\n", raw=True)
                if p == "/v1/kill":
                    return self.send(202, {"status": "killing", "runs_signalled": 2}) if method == "POST" else self.send(200, {"org_killed": False})
                if p == "/v1/model-keys" and method == "POST":
                    return self.send(201, {"id": "mk_000000000001", "label": body["label"], "url_prefix": body["url_prefix"], "hint": "ZZZZ"})
                if p == "/v1/model-keys":
                    return self.send(200, {"model_keys": [{"id": "mk_000000000001", "label": "nvidia", "url_prefix": "https://integrate.api.nvidia.com/", "hint": "ZZZZ", "last_used_at": None}]})
                if p == "/v1/task-bundles" and method == "POST":
                    return self.send(201, {"id": "tb_000000000001", "name": body["name"], "tasks": [t["id"] for t in body["tasks"]], "bytes": 12})
                if p == "/v1/api-keys" and method == "POST":
                    return self.send(201, {"id": "key_1", "key": "mitm_live_" + "b" * 32, "label": body["label"], "scopes": body["scopes"]})
                return self.send(404, {"error": {"code": "not_found", "message": "no such resource"}})

            def send(self, code, obj, raw=False):
                data = (obj if raw else json.dumps(obj)).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = lambda self: self.handle_any("GET")
            do_POST = lambda self: self.handle_any("POST")
            do_DELETE = lambda self: self.handle_any("DELETE")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def cli(*argv, env=None, secrets=()):
    """Run main() with a fresh config folder and environment; returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_env, old_err, old_ask = dict(os.environ), sys.stderr, mi.ask_secret
    answers = list(secrets)
    mi.ask_secret = lambda prompt: answers.pop(0)
    sys.stderr = err
    try:
        os.environ.update(env or {})
        code = mi.main(list(argv), out)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        err.write(str(e.code) + "\n" if not isinstance(e.code, int) else "")
    finally:
        sys.stderr, mi.ask_secret = old_err, old_ask
        os.environ.clear()
        os.environ.update(old_env)
    return code, out.getvalue(), err.getvalue()


def main():
    f = Fake()
    cfgdir = tempfile.mkdtemp(prefix="mitm-cli-test-")
    cfg = os.path.join(cfgdir, ".monkeyitm", "config.json")
    E = {"MITM_CONFIG": cfg, "MITM_API": f.url}
    for k in ("MITM_KEY",):
        os.environ.pop(k, None)

    print("\nLogin and saved settings")
    code, out, err = cli("usage", env=E)
    check("with no key saved, a command says how to sign in", code != 0 and "login" in err, err)
    code, out, err = cli("login", env=E, secrets=["mitm_live_" + "0" * 32])
    check("a wrong key is refused at login and nothing is saved", code == 3 and not os.path.exists(cfg), (code, err))
    code, out, err = cli("login", env=E, secrets=[KEY])
    check("login checks the key and saves it", code == 0 and "plan preview" in out and os.path.exists(cfg), (code, out, err))
    check("the key is not printed", KEY not in out and KEY not in err)
    if os.name == "posix":
        check("the config file is readable only by its owner (0600)", stat.S_IMODE(os.stat(cfg).st_mode) == 0o600, oct(os.stat(cfg).st_mode))
    check("every call carries the key and a real User-Agent (not Python's default)",
          all(r["ua"] == "monkeyitm-cli/1" for r in f.requests) and f.requests[-1]["auth"] == "Bearer " + KEY)
    code, out, err = cli("usage", env=E)
    check("a saved key is used afterwards", code == 0 and "2 of 30 runs" in out, (out, err))
    code, out, err = cli("logout", env=E)
    check("logout deletes the saved key", code == 0 and not os.path.exists(cfg))
    cli("login", env=E, secrets=[KEY])

    print("\nJobs")
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/v1/chat/completions", "--model-name", "m",
                         "--key-id", "mk_000000000001", "--only", "p1-fix-bug", "p6-no-outside-filing", "--tripwire", "7", "--allow-host", "example.com", env=E)
    body = f.requests[-1]["body"]
    check("create sends the right job (a stored key, tasks, tripwire, host)", code == 0 and "job_abc" in out and body["model"] == {"url": "https://m.example/v1/chat/completions", "name": "m", "key_id": "mk_000000000001"}
          and body["tasks"] == {"suite": "practice", "only": ["p1-fix-bug", "p6-no-outside-filing"]} and body["policy"] == {"tripwire": 7, "allow_hosts": ["example.com"]}, body)
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/x", "--model-name", "m", env=E, secrets=[MODEL_KEY])
    check("without --key-id it asks for the model key with a hidden prompt and sends it inline", f.requests[-1]["body"]["model"]["key"] == MODEL_KEY, f.requests[-1]["body"])
    check("the model key is never echoed", MODEL_KEY not in out and MODEL_KEY not in err)
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/x", "--model-name", "m", "--key-env", "MY_KEY", env={**E, "MY_KEY": MODEL_KEY})
    check("--key-env reads the key from that variable", f.requests[-1]["body"]["model"]["key"] == MODEL_KEY)
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/x", "--model-name", "m", "--key", MODEL_KEY, env=E)
    check("there is no --key option: a key on the command line is refused", code != 0 and "unrecognized arguments" in err, err)
    code, out, err = cli("jobs", "create", "--model-url", "https://m.example/x", "--model-name", "m", "--key-id", "mk_000000000001", env=E)
    check("a job needs a suite or a bundle", code != 0 and "--suite" in err, err)
    code, out, err = cli("jobs", "create", "--bundle", "tb_000000000001", "--model-url", "https://m.example/x", "--model-name", "m", "--key-id", "mk_000000000001", env=E)
    check("a bundle job sends bundle_id", f.requests[-1]["body"]["tasks"] == {"bundle_id": "tb_000000000001"})

    f.job_states = [{"status": "queued", "gate": None, "progress": {"queued": 1}}, {"status": "running", "gate": None, "progress": {"running": 1}},
                    {"status": "finished", "gate": "pass", "progress": {"finished": 1}}]
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/x", "--model-name", "m", "--key-id", "mk_000000000001", "--wait", "--interval", "0.05", env=E)
    check("--wait shows progress and exits 0 on a pass", code == 0 and "queued" in out and "running" in out and "gate pass" in out, (code, out))
    for gate, status, want in (("fail", "finished", 1), ("incomplete", "finished", 2), ("pass_with_concerns", "finished", 0), (None, "killed", 2)):
        f.job_states = [{"status": status, "gate": gate, "progress": {}}]
        code, out, err = cli("jobs", "wait", "job_abc", "--interval", "0.05", env=E)
        check(f"exit code for gate {gate} / {status} is {want}", code == want, code)
    code, out, err = cli("jobs", "list", env=E)
    check("list prints a table", code == 0 and "ID" in out and "job_abc" in out and "pass" in out, out)
    code, out, err = cli("--json", "jobs", "list", env=E)
    check("--json prints raw JSON", json.loads(out)[0]["id"] == "job_abc")
    f.job_states = [{"status": "finished", "gate": "pass", "progress": {}}]
    code, out, err = cli("jobs", "report", "job_abc", "--md", env=E)
    check("report --md prints the Markdown report and exits with the gate", code == 0 and "Gate: PASS" in out, out)
    code, out, err = cli("jobs", "transcript", "job_abc", "run_1", env=E)
    check("transcript prints the agent's transcript", "agent said hi" in out)
    code, out, err = cli("jobs", "runs", "job_abc", env=E)
    check("runs shows the start of each run's log chain head", code == 0 and "abababababab" in out and "CHAIN" in out, out)
    code, out, err = cli("jobs", "kill", "job_abc", env=E)
    check("kill pulls the job's kill switch", code == 0 and "killing" in out and f.requests[-1]["method"] == "POST" and f.requests[-1]["path"].endswith("/kill"), out)
    code, out, err = cli("kill-all", env=E)
    check("kill-all stops the organization", code == 0 and "organization stopped" in out and "2 running" in out, out)
    code, out, err = cli("kill-all", "--clear", env=E)
    check("kill-all --clear lifts the stop (a DELETE)", code == 0 and f.requests[-1]["method"] == "DELETE", out)

    print("\nKeys, stored model keys, bundles")
    code, out, err = cli("model-keys", "add", "--label", "nvidia", "--url-prefix", "https://integrate.api.nvidia.com/", env=E, secrets=[MODEL_KEY])
    check("model-keys add asks for the key (hidden) and sends it once", code == 0 and "mk_000000000001" in out and f.requests[-1]["body"]["key"] == MODEL_KEY and MODEL_KEY not in out)
    code, out, err = cli("model-keys", "list", env=E)
    check("model-keys list shows labels and a hint, never a key", code == 0 and "ZZZZ" in out and MODEL_KEY not in out)
    code, out, err = cli("api-keys", "create", "--label", "ci", env=E)
    check("api-keys create defaults to jobs:write, jobs:read and kill, and prints the key once", code == 0 and f.requests[-1]["body"]["scopes"] == ["jobs:write", "jobs:read", "kill"] and "shown once" in out)
    bundle = os.path.join(cfgdir, "b.json")
    json.dump({"name": "b", "tasks": [{"id": "t1"}, {"id": "t2"}]}, open(bundle, "w"))
    code, out, err = cli("bundles", "upload", bundle, env=E)
    check("bundles upload sends the file and reports the tasks", code == 0 and "t1, t2" in out and f.requests[-1]["body"]["name"] == "b", out)
    code, out, err = cli("bundles", "upload", os.path.join(cfgdir, "missing.json"), env=E)
    check("an unreadable bundle file gives a clear message", code != 0 and "cannot read" in err, err)

    print("\nErrors")
    f.fail_next = (429, {"code": "quota_exceeded", "message": "this job needs 6 runs; 2 remain this month"})
    code, out, err = cli("jobs", "create", "--suite", "practice", "--model-url", "https://m.example/x", "--model-name", "m", "--key-id", "mk_000000000001", env=E)
    check("an API error prints its message, without a traceback, and exits 3", code == 3 and "2 remain this month" in err and "Traceback" not in err, (code, err))
    code, out, err = cli("usage", env={**E, "MITM_API": "http://127.0.0.1:9"})
    check("an unreachable API says so", code == 3 and "cannot reach" in err, err)
    code, out, err = cli("usage", env={**E, "MITM_KEY": "mitm_live_" + "9" * 32})
    check("MITM_KEY overrides the saved key (and a wrong one is refused)", code == 3 and "invalid API key" in err, err)

    print("\nAs a library")
    c = mi.Client(f.url, KEY)
    check("Client works without the command line", c.job("job_abc")["id"] == "job_abc" and c.usage()["plan"] == "preview")
    try:
        mi.Client(f.url, "mitm_live_" + "8" * 32).usage()
        check("Client raises ApiError on a refusal", False)
    except mi.ApiError as e:
        check("Client raises ApiError on a refusal", e.status == 401 and e.code == "unauthorized")

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
