#!/usr/bin/env python3
"""MonkeyITM: command line and Python client for the public API (docs/API_V1.md).

One file, standard library only (Python 3.9+). Copy it anywhere.

    python3 monkeyitm.py login                       # asks for your API key (hidden), checks it, saves it
    python3 monkeyitm.py jobs create --suite practice --model-url https://integrate.api.nvidia.com/v1/chat/completions \\
        --model-name z-ai/glm-5.3 --key-id mk_... --wait
    python3 monkeyitm.py jobs list
    python3 monkeyitm.py jobs report job_... --md
    python3 monkeyitm.py jobs kill job_...           # the owner's kill switch for one job
    python3 monkeyitm.py kill-all                    # stop every job in your organization
    python3 monkeyitm.py model-keys add --label nvidia --url-prefix https://integrate.api.nvidia.com/
    python3 monkeyitm.py bundles upload bundle.json

Secrets are never taken from the command line (it would sit in your shell history and in the
process list): `login` and `model-keys add` ask with a hidden prompt, or read the variable named by
--key-env. The saved key lives in ~/.monkeyitm/config.json (mode 0600); MITM_KEY and MITM_API
override it. As a library:

    from monkeyitm import Client
    c = Client("https://...", "mitm_live_...")
    job = c.create_job({...}); print(c.job(job["id"])["status"])

Exit codes of `jobs wait`, `jobs create --wait` and `jobs report`: 0 pass or pass with concerns,
1 fail, 2 incomplete or killed, 3 an error talking to the API.
"""

import argparse
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API = "https://monkeyitm-vm.o87enterprises.workers.dev"
# Cloudflare (in front of the API) refuses Python's default user-agent with error 1010.
USER_AGENT = "monkeyitm-cli/1"


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(f"{message} ({status} {code})")
        self.status, self.code, self.message = status, code, message


class Client:
    def __init__(self, api, key, timeout=30):
        self.api, self.key, self.timeout = api.rstrip("/"), key, timeout

    def call(self, method, path, body=None, params=None, raw=False):
        url = self.api + path + ("?" + urllib.parse.urlencode(params) if params else "")
        data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + self.key, "User-Agent": USER_AGENT, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                text = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                err = json.loads(text)["error"]
                raise ApiError(e.code, err.get("code", "error"), err.get("message", text[:200]))
            except (ValueError, KeyError, TypeError):
                raise ApiError(e.code, "error", text[:200] or e.reason)
        except urllib.error.URLError as e:
            raise ApiError(0, "unreachable", f"cannot reach {self.api}: {e.reason}")
        if raw:
            return text
        return json.loads(text) if text else None

    # jobs
    def create_job(self, spec):
        return self.call("POST", "/v1/jobs", spec)

    def jobs(self, limit=25):
        return self.call("GET", "/v1/jobs", params={"limit": limit})["jobs"]

    def job(self, job_id):
        return self.call("GET", f"/v1/jobs/{job_id}")

    def runs(self, job_id):
        return self.call("GET", f"/v1/jobs/{job_id}/runs")["runs"]

    def report(self, job_id, markdown=False):
        return self.call("GET", f"/v1/jobs/{job_id}/report", params={"format": "md"} if markdown else None, raw=markdown)

    def artifact(self, job_id, run_id, kind):
        return self.call("GET", f"/v1/jobs/{job_id}/runs/{run_id}/{kind}", raw=True)

    def incident(self, job_id):
        return self.call("GET", f"/v1/jobs/{job_id}/incident")

    def kill_job(self, job_id):
        return self.call("POST", f"/v1/jobs/{job_id}/kill")

    def delete_job(self, job_id):
        return self.call("DELETE", f"/v1/jobs/{job_id}")

    # organization
    def kill_org(self):
        return self.call("POST", "/v1/kill")

    def clear_org_kill(self):
        return self.call("DELETE", "/v1/kill")

    def usage(self):
        return self.call("GET", "/v1/usage")

    def audit(self):
        return self.call("GET", "/v1/audit")["audit"]

    # keys, stored model keys, bundles
    def api_keys(self):
        return self.call("GET", "/v1/api-keys")["keys"]

    def create_api_key(self, label, scopes):
        return self.call("POST", "/v1/api-keys", {"label": label, "scopes": scopes})

    def revoke_api_key(self, key_id):
        return self.call("DELETE", f"/v1/api-keys/{key_id}")

    def model_keys(self):
        return self.call("GET", "/v1/model-keys")["model_keys"]

    def add_model_key(self, label, url_prefix, key):
        return self.call("POST", "/v1/model-keys", {"label": label, "url_prefix": url_prefix, "key": key})

    def delete_model_key(self, key_id):
        return self.call("DELETE", f"/v1/model-keys/{key_id}")

    def bundles(self):
        return self.call("GET", "/v1/task-bundles")["task_bundles"]

    def bundle(self, bundle_id):
        return self.call("GET", f"/v1/task-bundles/{bundle_id}")

    def upload_bundle(self, doc):
        return self.call("POST", "/v1/task-bundles", doc)

    def delete_bundle(self, bundle_id):
        return self.call("DELETE", f"/v1/task-bundles/{bundle_id}")


# ------------------------------------------------------------------ config and secrets

def config_path():
    return os.environ.get("MITM_CONFIG") or os.path.join(os.path.expanduser("~"), ".monkeyitm", "config.json")


def load_config():
    try:
        return json.load(open(config_path()))
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    p = config_path()
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def ask_secret(prompt):
    """A hidden prompt. (Tests replace this.)"""
    return getpass.getpass(prompt).strip()


def secret_from(args, what):
    """From the variable named by --key-env, or a hidden prompt: never from an argument."""
    if getattr(args, "key_env", None):
        v = os.environ.get(args.key_env, "").strip()
        if not v:
            raise SystemExit(f"the environment variable {args.key_env} is empty or not set")
        return v
    return ask_secret(f"{what}: ")


def client_from(args):
    cfg = load_config()
    key = os.environ.get("MITM_KEY") or cfg.get("key")
    api = os.environ.get("MITM_API") or getattr(args, "api", None) or cfg.get("api") or DEFAULT_API
    if not key:
        raise SystemExit("no API key: run `monkeyitm login` (or set MITM_KEY)")
    return Client(api, key)


# ------------------------------------------------------------------ output

def table(rows, cols, out):
    if not rows:
        out.write("(none)\n")
        return
    w = [max(len(c), *(len(str(r.get(c) if r.get(c) is not None else "")) for r in rows)) for c in cols]
    out.write("  ".join(c.upper().ljust(n) for c, n in zip(cols, w)).rstrip() + "\n")
    for r in rows:
        out.write("  ".join(str(r.get(c) if r.get(c) is not None else "").ljust(n) for c, n in zip(cols, w)).rstrip() + "\n")


def when(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + "Z" if ts else ""


def show(obj, args, out, render):
    if getattr(args, "json", False):
        out.write(json.dumps(obj, indent=2) + "\n")
    else:
        render(obj)


GATE_EXIT = {"pass": 0, "pass_with_concerns": 0, "fail": 1, "incomplete": 2}


def gate_exit(job):
    if job.get("status") == "killed":
        return 2
    return GATE_EXIT.get(job.get("gate"), 2)


def wait_for(client, job_id, interval, out, quiet=False):
    last = None
    while True:
        j = client.job(job_id)
        line = f"{j['status']} {json.dumps(j.get('progress') or {}, sort_keys=True)}"
        if line != last and not quiet:
            out.write(f"{time.strftime('%H:%M:%S')} {line}\n")
            out.flush()
            last = line
        if j["status"] in ("finished", "killed"):
            return j
        time.sleep(interval)


# ------------------------------------------------------------------ commands

def build_job(args):
    if bool(args.suite) == bool(args.bundle):
        raise SystemExit("choose one of --suite practice or --bundle tb_...")
    tasks = {"suite": args.suite} if args.suite else {"bundle_id": args.bundle}
    if args.only:
        tasks["only"] = args.only
    model = {"url": args.model_url, "name": args.model_name}
    if args.key_id:
        model["key_id"] = args.key_id
    else:
        model["key"] = secret_from(args, "Model API key")
    spec = {"name": args.name, "tasks": tasks, "model": model, "mode": args.mode}
    if args.repeat != 1:
        spec["repeat"] = args.repeat
    pol = {}
    if args.tripwire is not None:
        pol["tripwire"] = args.tripwire
    if args.allow_host:
        pol["allow_hosts"] = args.allow_host
    if pol:
        spec["policy"] = pol
    lim = {k: v for k, v in (("max_steps", args.max_steps), ("task_timeout_s", args.task_timeout)) if v is not None}
    if lim:
        spec["limits"] = lim
    return spec


def run(args, out):
    cmd = args.cmd
    if cmd == "login":
        api = args.api or os.environ.get("MITM_API") or load_config().get("api") or DEFAULT_API
        key = secret_from(args, "API key")
        u = Client(api, key).usage()
        save_config({"api": api, "key": key})
        out.write(f"signed in to {api} (plan {u['plan']}); saved to {config_path()}\n")
        return 0
    if cmd == "logout":
        try:
            os.remove(config_path())
        except OSError:
            pass
        out.write("signed out (the saved key is deleted; revoke it with `api-keys revoke` if it may have leaked)\n")
        return 0

    c = client_from(args)
    sub = getattr(args, "sub", None)

    if cmd == "usage":
        show(c.usage(), args, out, lambda u: out.write(
            f"plan {u['plan']}: {u['runs_this_month']} of {u['limits']['runs_month']} runs this month, {u['runs_active']} active "
            f"(concurrency {u['limits']['concurrency']}){'; ORGANIZATION STOPPED' if u['org_killed'] else ''}\n"))
        return 0
    if cmd == "audit":
        show(c.audit(), args, out, lambda rows: table([{**r, "at": when(r["at"])} for r in rows[:50]], ["at", "actor", "action", "detail"], out))
        return 0
    if cmd == "kill-all":
        if args.clear:
            c.clear_org_kill()
            out.write("the organization stop is cleared; jobs can be submitted again\n")
        else:
            r = c.kill_org()
            out.write(f"organization stopped: {r['runs_signalled']} running run(s) told to stop; queued runs cancelled\n")
        return 0

    if cmd == "jobs":
        if sub == "create":
            j = c.create_job(build_job(args))
            out.write(f"{j['id']}  {j['status']}  {j['runs']} run(s)\n")
            if args.wait:
                j = wait_for(c, j["id"], args.interval, out)
                out.write(f"{j['status']}: gate {j.get('gate')}\n")
                return gate_exit(j)
            return 0
        if sub == "list":
            show(c.jobs(args.limit), args, out, lambda rows: table(
                [{**r, "created": when(r["created_at"])} for r in rows], ["id", "name", "status", "gate", "runs", "created"], out))
            return 0
        if sub == "show":
            show(c.job(args.job), args, out, lambda j: out.write(
                f"{j['id']}  {j['name']}\nstatus {j['status']}  gate {j.get('gate')}  runs {j['runs']}  progress {j.get('progress')}\n"
                + (f"stopped by the owner; last run stopped {j['seconds_to_stop']} s after the call\n" if j.get("kill_requested_at") and j.get("seconds_to_stop") is not None else "")))
            return 0
        if sub == "wait":
            j = wait_for(c, args.job, args.interval, out)
            out.write(f"{j['status']}: gate {j.get('gate')}\n")
            return gate_exit(j)
        if sub == "runs":
            show(c.runs(args.job), args, out, lambda rows: table(
                [{**r, "chain": ((r.get("log_chain") or {}).get("head") or "")[:12]} for r in rows],
                ["id", "task", "status", "result", "completed", "beyond_scope", "halted", "flagged_injection", "chain"], out))
            return 0
        if sub == "report":
            if args.md:
                out.write(c.report(args.job, markdown=True))
                j = c.job(args.job)
            else:
                rep = c.report(args.job)
                out.write(json.dumps(rep, indent=2) + "\n")
                j = {"status": rep["job"]["status"], "gate": rep.get("tier_gate")}
            return gate_exit(j)
        if sub in ("log", "score", "transcript"):
            out.write(c.artifact(args.job, args.run, sub))
            return 0
        if sub == "incident":
            out.write(json.dumps(c.incident(args.job), indent=2) + "\n")
            return 0
        if sub == "kill":
            r = c.kill_job(args.job)
            out.write(f"{r['status']}: {r['runs_signalled']} run(s) told to stop\n")
            return 0
        if sub == "delete":
            c.delete_job(args.job)
            out.write(f"deleted {args.job}\n")
            return 0

    if cmd == "api-keys":
        if sub == "list":
            show(c.api_keys(), args, out, lambda rows: table(
                [{**r, "scopes": " ".join(r["scopes"]), "revoked": "yes" if r.get("revoked_at") else ""} for r in rows], ["id", "prefix", "label", "scopes", "revoked"], out))
            return 0
        if sub == "create":
            r = c.create_api_key(args.label, args.scope)
            out.write(f"{r['id']}  scopes {' '.join(r['scopes'])}\nkey (shown once, save it now): {r['key']}\n")
            return 0
        if sub == "revoke":
            c.revoke_api_key(args.id)
            out.write(f"revoked {args.id}\n")
            return 0

    if cmd == "model-keys":
        if sub == "list":
            show(c.model_keys(), args, out, lambda rows: table(
                [{**r, "last used": when(r.get("last_used_at"))} for r in rows], ["id", "label", "url_prefix", "hint", "last used"], out))
            return 0
        if sub == "add":
            r = c.add_model_key(args.label, args.url_prefix, secret_from(args, "Model API key"))
            out.write(f"stored as {r['id']} (pinned to {r['url_prefix']}); use it with --key-id {r['id']}\n")
            return 0
        if sub == "delete":
            c.delete_model_key(args.id)
            out.write(f"deleted {args.id}\n")
            return 0

    if cmd == "bundles":
        if sub == "list":
            show(c.bundles(), args, out, lambda rows: table(
                [{**r, "tasks": ",".join(r["tasks"])} for r in rows], ["id", "name", "bytes", "tasks"], out))
            return 0
        if sub == "show":
            show(c.bundle(args.id), args, out, lambda b: (out.write(f"{b['id']}  {b['name']}  {b['bytes']} bytes\n"), table(b["tasks"], ["id", "base", "files", "instruction_bytes"], out)))
            return 0
        if sub == "upload":
            try:
                doc = json.load(open(args.file, encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise SystemExit(f"cannot read {args.file}: {e} (make one with scripts/pack-bundle.py)")
            r = c.upload_bundle(doc)
            out.write(f"{r['id']}  {len(r['tasks'])} task(s), {r['bytes']} bytes: {', '.join(r['tasks'])}\n")
            return 0
        if sub == "delete":
            c.delete_bundle(args.id)
            out.write(f"deleted {args.id}\n")
            return 0

    raise SystemExit(f"unknown command: {cmd} {sub or ''}".strip())


def parser():
    ap = argparse.ArgumentParser(prog="monkeyitm", description="MonkeyITM API client", allow_abbrev=False)
    ap.add_argument("--api", help=f"API address (default {DEFAULT_API})")
    ap.add_argument("--json", action="store_true", help="print raw JSON where a command lists things")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("login"); p.add_argument("--key-env", help="read the key from this environment variable instead of asking")
    sp.add_parser("logout")
    sp.add_parser("usage")
    sp.add_parser("audit")
    p = sp.add_parser("kill-all", help="stop every job in your organization"); p.add_argument("--clear", action="store_true", help="lift a previous stop")

    jobs = sp.add_parser("jobs").add_subparsers(dest="sub", required=True)
    p = jobs.add_parser("create", allow_abbrev=False)   # no --key shorthand for --key-id: a key must never be typed as an argument
    p.add_argument("--name", default="job")
    p.add_argument("--suite", choices=["practice"])
    p.add_argument("--bundle")
    p.add_argument("--only", nargs="*")
    p.add_argument("--model-url", required=True)
    p.add_argument("--model-name", required=True)
    p.add_argument("--key-id", help="a stored model key (mk_...); otherwise you are asked for the key")
    p.add_argument("--key-env", help="take an inline model key from this environment variable")
    p.add_argument("--mode", choices=["single", "group"], default="single")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--tripwire", type=int)
    p.add_argument("--allow-host", action="append")
    p.add_argument("--max-steps", type=int)
    p.add_argument("--task-timeout", type=int)
    p.add_argument("--wait", action="store_true", help="wait for the job to end and exit with its gate")
    p.add_argument("--interval", type=float, default=5)
    jobs.add_parser("list").add_argument("--limit", type=int, default=25)
    for name in ("show", "runs", "incident", "kill", "delete"):
        jobs.add_parser(name).add_argument("job")
    p = jobs.add_parser("wait"); p.add_argument("job"); p.add_argument("--interval", type=float, default=5)
    p = jobs.add_parser("report"); p.add_argument("job"); p.add_argument("--md", action="store_true")
    for name in ("log", "score", "transcript"):
        p = jobs.add_parser(name); p.add_argument("job"); p.add_argument("run")

    keys = sp.add_parser("api-keys").add_subparsers(dest="sub", required=True)
    keys.add_parser("list")
    p = keys.add_parser("create"); p.add_argument("--label", default="key")
    p.add_argument("--scope", action="append", default=None, choices=["jobs:write", "jobs:read", "sessions:write", "kill", "keys:admin"])
    keys.add_parser("revoke").add_argument("id")

    mk = sp.add_parser("model-keys").add_subparsers(dest="sub", required=True)
    mk.add_parser("list")
    p = mk.add_parser("add"); p.add_argument("--label", required=True); p.add_argument("--url-prefix", required=True)
    p.add_argument("--key-env", help="read the key from this environment variable instead of asking")
    mk.add_parser("delete").add_argument("id")

    bd = sp.add_parser("bundles").add_subparsers(dest="sub", required=True)
    bd.add_parser("list")
    bd.add_parser("show").add_argument("id")
    bd.add_parser("upload").add_argument("file")
    bd.add_parser("delete").add_argument("id")
    return ap


def main(argv=None, out=None):
    out = out or sys.stdout
    args = parser().parse_args(argv)
    if getattr(args, "scope", "x") is None:
        args.scope = ["jobs:write", "jobs:read", "kill"]
    try:
        return run(args, out)
    except ApiError as e:
        print(f"error: {e.message}" + (f" ({e.code})" if e.status else ""), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted (a job you started keeps running; stop it with `jobs kill`)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
