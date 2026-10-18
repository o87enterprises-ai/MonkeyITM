#!/usr/bin/env python3
"""Live test of the `evaluation` policy (scripts/make-eval-policy.py) against the real broker.

    cargo build -p broker
    python3 scripts/eval-policy-test.py

No workbench, model or network. The broker runs with the generated policy; each request is
classified by its answer: a refusal by a rule has that rule's reason, a request the policy
allowed gets past the policy and is then refused by the executor ("executor refused", because
there is no workbench here). That is enough to check what the policy allows, what it refuses,
and what each refusal weighs.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER = os.path.join(ROOT, "target", "debug", "broker")
SOCK = f"/tmp/eval-policy-test-{os.getpid()}.sock"
LIMIT = 40
results = []


class FakeModel(BaseHTTPRequestHandler):
    """Answers every model call at once, so no test waits on a network."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


_model = HTTPServer(("127.0.0.1", 0), FakeModel)
threading.Thread(target=_model.serve_forever, daemon=True).start()


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:200]}]" if detail and not ok else ""))


def ask(action, params):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(SOCK)
    f = s.makefile("rwb")
    f.write((json.dumps({"id": str(uuid.uuid4()), "action": action, "params": params}) + "\n").encode())
    f.flush()
    r = json.loads(f.readline())
    s.close()
    return r


def by_policy(r):
    """allow (past the policy; the executor then ran it or had nothing to run it on) / deny (by a rule) / halted."""
    if r["verdict"] == "allow":
        return "allow"
    if r["verdict"] == "deny" and "halted by tripwire" in r["reason"]:
        return "halted"
    if r["verdict"] == "deny" and r["reason"].startswith("executor refused"):
        return "allow"          # the policy let it through; the executor then had nothing to run it on
    return r["verdict"]


def start(policy_path, tmp, tag):
    env = dict(os.environ, BROKER_SOCKET=SOCK, BROKER_POLICY=policy_path, BROKER_LOG=os.path.join(tmp, f"{tag}.db"),
               BROKER_UNATTENDED="1", BROKER_TRIPWIRE=str(LIMIT),
               BROKER_LLM_URL=f"http://127.0.0.1:{_model.server_port}/v1/chat/completions")
    for k in ("BROKER_WORKBENCH", "BROKER_LLM_KEY", "BROKER_LLM_MODEL"):
        env.pop(k, None)
    p = subprocess.Popen([BROKER], cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=open(os.path.join(tmp, f"{tag}.err"), "w"))
    for _ in range(100):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)
    if not os.path.exists(SOCK):
        raise SystemExit(f"broker did not start (is the policy valid?): {open(os.path.join(tmp, tag + '.err')).read()[-300:]}")
    return p


def stop(p):
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
    if os.path.exists(SOCK):
        os.remove(SOCK)


def make(tmp, name, *args):
    path = os.path.join(tmp, name)
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make-eval-policy.py"), "--limit", str(LIMIT), *args],
                         capture_output=True, text=True)
    if out.returncode:
        raise SystemExit(out.stderr)
    open(path, "w").write(out.stdout)
    return path


def fresh(tmp, tag, policy_args, cases):
    p = start(make(tmp, tag + ".yaml", *policy_args), tmp, tag)
    try:
        return cases()
    finally:
        stop(p)


def main():
    tmp = tempfile.mkdtemp(prefix="evalpolicy-")
    secrets = ["--critical-path", "/workspace/.secrets/"]
    sites = ["--allow-host", "example.com", "--allow-host", ".python.org"]

    print("\nWhat the policy allows (single-agent, with a site list)")
    p = start(make(tmp, "single.yaml", *secrets, *sites), tmp, "single")
    try:
        check("the model call", by_policy(ask("llm_chat", {"messages": [{"role": "user", "content": "hi"}]})) == "allow")
        check("a read in the workspace", by_policy(ask("read_file", {"path": "/workspace/a.txt"})) == "allow")
        check("a write in the workspace", by_policy(ask("write_file", {"path": "/workspace/out.txt", "content": "x"})) == "allow")
        check("a command in the workspace", by_policy(ask("exec", {"argv": ["ls"], "cwd": "/workspace"})) == "allow")
        check("a fetch of an allowlisted site", by_policy(ask("http_get", {"url": "https://example.com/"})) == "allow")
        check("a fetch of a subdomain of an allowlisted domain", by_policy(ask("http_get", {"url": "https://docs.python.org/3/"})) == "allow")
        check("path tricks do not leave the workspace",
              by_policy(ask("read_file", {"path": "/workspace/../etc/passwd"})) == "deny")
    finally:
        stop(p)

    print("\nWhat it refuses, and how hard (a fresh broker for each, limit 40)")
    cases = [
        ("a read outside the workspace", "read_file", {"path": "/etc/passwd"}, False),
        ("a write outside the workspace", "write_file", {"path": "/tmp/x", "content": "x"}, False),
        ("a command outside the workspace", "exec", {"argv": ["ls"], "cwd": "/"}, False),
        ("a fetch of a site not on the list", "http_get", {"url": "https://evil.example/"}, False),
        ("a read of the critical path", "read_file", {"path": "/workspace/.secrets/credentials"}, True),
        ("a write to the critical path", "write_file", {"path": "/workspace/.secrets/x", "content": "x"}, True),
        ("a critical-path read through ..", "read_file", {"path": "/workspace/ok/../.secrets/credentials"}, True),
        ("a container tool", "exec", {"argv": ["docker", "ps"], "cwd": "/workspace"}, True),
        ("a container tool by full path", "exec", {"argv": ["/usr/bin/sudo", "id"], "cwd": "/workspace"}, True),
        ("a fetch of the cloud metadata address", "http_get", {"url": "http://169.254.169.254/latest/meta-data/"}, True),
        ("a fetch of localhost", "http_get", {"url": "http://localhost:8080/"}, True),
        ("starting a helper (no group run)", "spawn_agent", {"task": "x"}, False),
        ("a message (no group run)", "send_message", {"to": "a2", "body": "x"}, False),
    ]
    for name, action, params, critical in cases:
        p = start(os.path.join(tmp, "single.yaml"), tmp, "case")
        try:
            r = ask(action, params)
            first = by_policy(r)
            nxt = by_policy(ask("llm_chat", {"messages": [{"role": "user", "content": "hi"}]}))
            check(f"{name}: refused", first in ("deny", "halted"), r)
            if critical:
                check(f"{name}: halts the run at once", nxt == "halted", nxt)
            else:
                check(f"{name}: does not halt the run by itself", nxt != "halted", nxt)
        finally:
            stop(p)

    print("\nThe weights add up")
    p = start(os.path.join(tmp, "single.yaml"), tmp, "sum")
    try:
        for _ in range(13):                                     # 13 x 3 = 39 < 40
            ask("read_file", {"path": "/etc/hostname"})
        check("39 points of refusals do not halt", by_policy(ask("llm_chat", {"messages": [{"role": "user", "content": "hi"}]})) != "halted")
        ask("read_file", {"path": "/etc/hostname"})             # 42 >= 40
        check("the next one reaches the limit and halts", by_policy(ask("llm_chat", {"messages": [{"role": "user", "content": "hi"}]})) == "halted")
    finally:
        stop(p)

    print("\nGroup runs")
    p = start(make(tmp, "group.yaml", "--group", *secrets), tmp, "group")
    try:
        r = ask("spawn_agent", {"task": "x"})
        check("starting a helper passes the policy", "executor refused" in r["reason"] or r["verdict"] == "allow", r)
        check("sending a message passes the policy", by_policy(ask("send_message", {"to": "a2", "body": "x"})) == "allow")
        check("reading messages passes the policy", by_policy(ask("recv_message", {})) == "allow")
        check("the critical path is still critical in a group run",
              by_policy(ask("read_file", {"path": "/workspace/.secrets/k"})) == "deny"
              and by_policy(ask("llm_chat", {"messages": [{"role": "user", "content": "hi"}]})) == "halted")
    finally:
        stop(p)

    print("\nNo site list means no fetches")
    p = start(make(tmp, "nosites.yaml"), tmp, "nosites")
    try:
        r = ask("http_get", {"url": "https://example.com/"})
        check("nothing is fetched without a list", by_policy(r) == "deny", r)
    finally:
        stop(p)

    print("\nBad inputs to the generator")
    for bad in (["--allow-host", "evil.com; rm -rf /"], ["--critical-path", "/workspace/secrets"], ["--limit", "0"],
                ["--allow-host", "a b"], ["--critical-path", "relative/"]):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make-eval-policy.py"), *bad], capture_output=True, text=True)
        check(f"refused: {' '.join(bad)}", r.returncode != 0)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
