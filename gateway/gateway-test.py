#!/usr/bin/env python3
"""Tests of the shape-B gateway (gateway/gateway.py) in front of the real broker.

    cargo build -p broker
    python3 gateway/gateway-test.py

A team's agent is simulated by this script: only HTTP with a bearer token. No Docker, model
or network beyond localhost. Checks: who may talk, what gets through to the broker (exactly
one request per call), the limits (rate, size, count, time, bad requests), that the broker's
own decisions, refusals and tripwire pass through unchanged, and that nothing internal leaks.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
from monkeyitm_client import Broker, BrokerError  # noqa: E402

BROKER = os.path.join(ROOT, "target", "debug", "broker")
TOKEN = "t" * 40
results = []
procs = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:200]}]" if detail and not ok else ""))


def http(port, method, path, body=None, token=TOKEN, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    h = {"Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, ConnectionError):
        return 0, {}          # the server closed the connection on us (an oversized body)


def intent(action, params):
    return {"id": str(uuid.uuid4()), "action": action, "params": params}


def start_broker(tmp, tag, tripwire=0):
    sock = os.path.join(tmp, f"{tag}.sock")
    policy = os.path.join(tmp, "policy.yaml")
    open(policy, "w").write('''rules:
  - name: allow-safe
    action: read_file
    match: { path_prefix: "/tmp/safe/" }
    verdict: allow
  - name: default-deny
    action: any
    verdict: deny
    reason: "no earlier rule allowed this request"
''')
    env = dict(os.environ, BROKER_SOCKET=sock, BROKER_POLICY=policy, BROKER_LOG=os.path.join(tmp, f"{tag}.db"),
               BROKER_UNATTENDED="1", BROKER_TRIPWIRE=str(tripwire))
    env.pop("BROKER_WORKBENCH", None)
    p = subprocess.Popen([BROKER], cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=open(os.path.join(tmp, f"{tag}.err"), "w"))
    procs.append(p)
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    return p, sock, os.path.join(tmp, f"{tag}.db")


def start_gateway(tmp, tag, sock, port, **extra):
    env = dict(os.environ, GATEWAY_TOKEN=TOKEN, GATEWAY_BROKER_SOCK=sock, GATEWAY_PORT=str(port),
               GATEWAY_STATE_DIR=os.path.join(tmp, f"{tag}-state"), GATEWAY_RATE="1000")
    env.update({k: str(v) for k, v in extra.items()})
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "gateway", "gateway.py")], env=env,
                         stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, f"{tag}-gw.err"), "w"))
    procs.append(p)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return p
        except Exception:
            time.sleep(0.1)
    raise SystemExit(f"gateway did not start: {open(os.path.join(tmp, tag + '-gw.err')).read()}")


def intents_logged(db):
    out = subprocess.run([BROKER, "export", "--db", db, "--format", "json", "--out", "/dev/stdout"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    return json.loads(out[out.index("{"):])["summary"]["intents"]


def main():
    os.makedirs("/tmp/safe", exist_ok=True)
    open("/tmp/safe/report.txt", "w").write("Q3 revenue up 12%.\n")
    tmp = tempfile.mkdtemp(prefix="gwtest-")
    try:
        run(tmp)
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


def run(tmp):
    print("\nWho may talk")
    bp, sock, db = start_broker(tmp, "a")
    start_gateway(tmp, "a", sock, 8301, GATEWAY_MAX_BAD=8)
    s, _ = http(8301, "GET", "/healthz", token=None)
    check("healthz needs no token", s == 200)
    for name, tok in (("no token", None), ("a wrong token", "x" * 40), ("a token one character off", TOKEN[:-1] + "u"), ("an empty token", "")):
        s, b = http(8301, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}), token=tok)
        check(f"refused: {name}", s == 401, (s, b))
    check("none of those reached the broker", intents_logged(db) == 0)
    s, b = http(8301, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("the right token gets the broker's verdict, allowed, with the file", s == 200 and b["verdict"] == "allow" and "revenue" in b["result"]["content"], (s, b))
    s, b = http(8301, "POST", "/v1/intent", intent("read_file", {"path": "/etc/passwd"}))
    check("a refusal passes through as the broker's own deny and reason", s == 200 and b["verdict"] == "deny" and "no earlier rule" in b["reason"], (s, b))
    s, b = http(8301, "GET", "/v1/status")
    check("status counts the requests and the refusal", s == 200 and b["requests"] == 2 and b["bad_requests"] == 4, b)

    print("\nExactly one request per call")
    s, b = http(8301, "POST", "/v1/intent", raw=json.dumps(intent("read_file", {"path": "/tmp/safe/report.txt"})).encode() + b"\n" + json.dumps(intent("read_file", {"path": "/etc/shadow"})).encode())
    check("two requests in one body are refused", s == 400, (s, b))
    n0 = intents_logged(db)
    s, b = http(8301, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt\n{\"id\":\"x\",\"action\":\"read_file\",\"params\":{\"path\":\"/etc/shadow\"}}"}))
    check("a newline inside a value cannot smuggle a second request",
          s == 200 and b["verdict"] == "deny" and intents_logged(db) == n0 + 1, (s, b))

    print("\nBad requests, size, and closing for abuse")
    s, _ = http(8301, "POST", "/v1/intent", raw=b"not json")
    check("not JSON is refused", s == 400)
    s, _ = http(8301, "POST", "/v1/intent", raw=b"[1,2]")
    check("a JSON list is refused", s == 400)
    s, _ = http(8301, "POST", "/v1/intent", raw=b"x" * (5 * 1024 * 1024))
    check("a body over 4 MiB is refused", s in (413, 0), s)
    s, b = http(8301, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("after too many bad requests the session is closed, even for the right token", s == 403 and "closed" in b.get("error", ""), (s, b))

    print("\nLimits")
    bp, sock, db = start_broker(tmp, "b")
    start_gateway(tmp, "b", sock, 8302, GATEWAY_RATE=2, GATEWAY_MAX_REQUESTS=1000)
    codes = [http(8302, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))[0] for _ in range(12)]
    check("going faster than the rate gets 429s, and the first few get through", 429 in codes and codes[0] == 200, codes)
    bp, sock, db = start_broker(tmp, "c")
    start_gateway(tmp, "c", sock, 8303, GATEWAY_MAX_REQUESTS=3)
    codes = [http(8303, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))[0] for _ in range(5)]
    check("the session stops at its request limit", codes == [200, 200, 200, 403, 403], codes)
    bp, sock, db = start_broker(tmp, "d")
    start_gateway(tmp, "d", sock, 8304, GATEWAY_TTL_SECONDS=2)
    check("a request inside the time limit works", http(8304, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))[0] == 200)
    time.sleep(3)
    s, b = http(8304, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("after the time limit the token no longer works", s == 403 and "expired" in b.get("error", ""), (s, b))
    time.sleep(3)
    check("the closing note is written", os.path.exists(os.path.join(tmp, "d-state", "closed.json")))

    print("\nFinishing, the broker's tripwire, and what does not leak")
    bp, sock, db = start_broker(tmp, "e")
    start_gateway(tmp, "e", sock, 8305)
    s, b = http(8305, "POST", "/v1/finish", {})
    check("finish closes the session", s == 200 and b["closed"])
    s, b = http(8305, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("nothing is accepted after finish", s == 403, (s, b))
    bp, sock, db = start_broker(tmp, "f", tripwire=3)
    start_gateway(tmp, "f", sock, 8306)
    for _ in range(3):
        http(8306, "POST", "/v1/intent", intent("read_file", {"path": "/etc/passwd"}))
    s, b = http(8306, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("the broker's tripwire halts the team's run, and the gateway relays it unchanged",
          s == 200 and b["verdict"] == "deny" and "halted by tripwire" in b["reason"], (s, b))
    s, b = http(8306, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("after the halt reply the session is closed: the team is told the run is over", s == 403 and "closed" in b.get("error", ""), (s, b))
    bp, sock, db = start_broker(tmp, "h")
    start_gateway(tmp, "h", sock, 8308)
    bp.kill()
    time.sleep(0.5)
    s, b = http(8308, "POST", "/v1/intent", intent("read_file", {"path": "/tmp/safe/report.txt"}))
    check("if the broker is gone the answer is a plain 502 with no paths in it",
          s == 502 and "/tmp" not in json.dumps(b) and tmp not in json.dumps(b), (s, b))
    s, b = http(8308, "GET", "/v1/nothing")
    check("unknown paths are 404", s == 404)

    print("\nThe client library")
    bp, sock, db = start_broker(tmp, "g")
    start_gateway(tmp, "g", sock, 8307)
    c = Broker("http://127.0.0.1:8307", TOKEN)
    r = c.read_file("/tmp/safe/report.txt")
    check("read_file returns the verdict and the content", r["verdict"] == "allow" and "revenue" in r["result"]["content"], r)
    check("a refusal is a normal answer, not an exception", c.read_file("/etc/passwd")["verdict"] == "deny")
    check("exec and write_file are sent as requests the broker refuses here", c.exec(["ls"])["verdict"] == "deny" and c.write_file("/workspace/x", "y")["verdict"] == "deny")
    check("status works", c.status()["requests"] == 4)
    try:
        Broker("http://127.0.0.1:8307", "x" * 40).status()
        check("a wrong token raises BrokerError", False)
    except BrokerError as e:
        check("a wrong token raises BrokerError", "401" in str(e), e)
    try:
        Broker("http://127.0.0.1:1", TOKEN, timeout=2).status()
        check("an unreachable gateway raises BrokerError", False)
    except BrokerError:
        check("an unreachable gateway raises BrokerError", True)
    check("finish closes it", c.finish()["closed"])


if __name__ == "__main__":
    sys.exit(main())
