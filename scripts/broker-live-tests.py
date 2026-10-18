#!/usr/bin/env python3
"""Live tests of the broker process itself: no model, no sandbox, no container.

    cargo build -p broker
    python3 scripts/broker-live-tests.py

A. Malformed input   garbage on the socket must never be allowed, never crash
                     the broker, and never stop it serving a valid request.
B. Path spellings    odd spellings of allowed and denied paths: nothing may
                     return the canary, and every allow must be inside /tmp/safe/.
C. Many agents       40 connections x 25 mixed requests at once: every reply
                     echoes its own request, every verdict is the expected one,
                     and the log holds exactly one intent row and one verdict
                     row per request.
D. Human approval    the attended path, with answers piped to the broker's
                     stdin: y allows, n denies, an empty answer denies.
E. Startup refusals  an unusable log path or a broken policy must stop the
                     broker from starting (it must not run without a log or rules).
F. Type-ahead        on a real terminal, a key pressed before the approval
                     question appears must not answer it.
H. Hash chain        the export carries the chain head; `broker verify` finds intact;
                     an edit made to the database file behind the broker's back is found.
G. Kill switch       SIGUSR1 or a kill file stops the run at once: every later
                     request is refused, the stop is logged once, the broker
                     stays up, and a stale kill file does not stop a new run.

Every case checks a rule; none tries to get around one. Fixtures are the
same fake canary the other tests use (/tmp/demo-home/.aws/credentials).
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCK = "/tmp/broker.sock"
BROKER = os.path.join(ROOT, "target", "debug", "broker")
CANARY_ID = "AKIAFAKEFAKEFAKEFAKE"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))


def fixtures():
    os.makedirs("/tmp/safe", exist_ok=True)
    os.makedirs("/tmp/demo-home/.aws", exist_ok=True)
    with open("/tmp/demo-home/.aws/credentials", "w") as f:
        f.write(f"[default]\naws_access_key_id = {CANARY_ID}\naws_secret_access_key = canary\n")
    with open("/tmp/safe/report.txt", "w") as f:
        f.write("Q3 revenue up 12%.\n")
    try:
        os.remove("/tmp/safe/innocent.txt")
    except FileNotFoundError:
        pass
    os.symlink("/tmp/demo-home/.aws/credentials", "/tmp/safe/innocent.txt")


class Broker:
    def __init__(self, unattended=True, stdin=None, log=None, policy=None, stderr=None, allow_piped=True):
        self.dir = tempfile.mkdtemp(prefix="blt-")
        self.db = log or os.path.join(self.dir, "broker.db")
        env = dict(os.environ, BROKER_LOG=self.db, BROKER_POLICY=policy or os.path.join(ROOT, "policies/default.yaml"))
        env.pop("BROKER_WORKBENCH", None)
        env.pop("BROKER_TRIPWIRE", None)
        if unattended:
            env["BROKER_UNATTENDED"] = "1"
        else:
            env.pop("BROKER_UNATTENDED", None)
            env.pop("BROKER_ALLOW_PIPED_APPROVAL", None)
            if stdin == subprocess.PIPE and allow_piped:
                env["BROKER_ALLOW_PIPED_APPROVAL"] = "1"     # a scripted approver, on purpose
        if os.path.exists(SOCK):
            os.remove(SOCK)
        self.p = subprocess.Popen([BROKER], cwd=ROOT, env=env, stdin=stdin or subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=stderr or subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(SOCK) or self.p.poll() is not None:
                break
            time.sleep(0.1)
        self.up = os.path.exists(SOCK)

    def alive(self):
        return self.p.poll() is None

    def export(self):
        out = subprocess.run([BROKER, "export", "--db", self.db, "--format", "json", "--out", "/dev/stdout"],
                             capture_output=True, text=True, cwd=ROOT).stdout
        return json.loads(out[out.index("{"):])

    def close(self):
        if self.alive():
            self.p.terminate()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        if os.path.exists(SOCK):
            os.remove(SOCK)


def ask(action, params, timeout=5):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    f = s.makefile("rwb")
    intent = {"id": str(uuid.uuid4()), "action": action, "params": params, "justification": "live-test"}
    f.write((json.dumps(intent) + "\n").encode())
    f.flush()
    line = f.readline()
    s.close()
    return json.loads(line) if line else None


def raw(data, timeout=5):
    """Send raw bytes; return the parsed reply, 'closed', or 'silent'."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    try:
        s.sendall(data)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                return "closed" if not buf else buf
            buf += chunk
        try:
            return json.loads(buf)
        except ValueError:
            return buf
    except socket.timeout:
        return "silent"
    except (BrokenPipeError, ConnectionResetError):
        return "closed"
    finally:
        s.close()


def allowed(reply):
    return isinstance(reply, dict) and reply.get("verdict") == "allow"


def part_a():
    print("\nA. Malformed input")
    b = Broker()
    try:
        cases = {
            "empty line": b"\n",
            "not JSON": b"this is not json\n",
            "JSON list": b"[]\n",
            "object without action": b'{"id":"1"}\n',
            "unknown action": json.dumps({"id": "1", "action": "format_disk", "params": {}}).encode() + b"\n",
            "missing params": json.dumps({"id": "1", "action": "read_file"}).encode() + b"\n",
            "path is a number": json.dumps({"id": "1", "action": "read_file", "params": {"path": 5}}).encode() + b"\n",
            "NUL inside a path": json.dumps({"id": "1", "action": "read_file", "params": {"path": "/tmp/safe/report.txt\u0000/../../x"}}).encode() + b"\n",
            "invalid UTF-8": b'{"id":"1","action":"read_file","params":{"path":"/tmp/safe/\xff\xfe"}}\n',
            "2 MB line": b'{"id":"1","action":"read_file","params":{"path":"' + b"a" * (2 * 1024 * 1024) + b'"}}\n',
            "deeply nested JSON": b"[" * 20000 + b"]" * 20000 + b"\n",
            "half a request then hang up": b'{"id":"1","action":"read_file"',
        }
        for name, data in cases.items():
            try:
                reply = raw(data, timeout=3)
            except Exception as e:
                reply = f"error {e}"
            ok = not allowed(reply) and b.alive()
            check(f"{name}: not allowed, broker still up", ok, f"reply {str(reply)[:80]}")
        r = ask("read_file", {"path": "/tmp/safe/report.txt"})
        check("a valid request is still served afterwards", allowed(r), str(r)[:100])
        r = ask("read_file", {"path": "/tmp/demo-home/.aws/credentials"})
        check("and a refused one is still refused", r and r["verdict"] == "deny", str(r)[:100])
    finally:
        b.close()


def part_b():
    print("\nB. Path spellings (no spelling may return the canary)")
    b = Broker()
    try:
        paths = [
            "/tmp/safe/report.txt", "/tmp/safe/./report.txt", "/tmp//safe/report.txt",
            "/tmp/safe/../safe/report.txt", "/TMP/safe/report.txt", "/tmp/safe/report.txt/",
            "/tmp/safe/%2e%2e/report.txt", "/tmp/safe/innocent.txt",
            "/tmp/safe/../demo-home/.aws/credentials", "/tmp/safe/./../demo-home/.aws/credentials",
            "/tmp/safe//../demo-home/.aws/credentials", "tmp/safe/report.txt", "/tmp/safe", "/tmp/safe/",
            "//tmp/safe/../demo-home/.aws/credentials", "/tmp/safe/report.txt\u0000../../demo-home/.aws/credentials",
            "/tmp/safe/‮/../../demo-home/.aws/credentials", "/tmp/demo-home/.aws/credentials",
            "/proc/self/root/tmp/demo-home/.aws/credentials", "/tmp/safe/../../proc/self/environ",
        ]
        leaked, outside = [], []
        for p in paths:
            r = ask("read_file", {"path": p})
            verdict = r["verdict"] if r else "none"
            print(f"      {verdict:<8} {p!r}")
            if r and CANARY_ID in json.dumps(r.get("result")):
                leaked.append(p)
            if allowed(r) and not os.path.realpath(p.split("\u0000")[0]).startswith("/tmp/safe"):
                outside.append(p)
        check("no spelling returned the canary", not leaked, str(leaked))
        check("every allow resolves inside /tmp/safe/", not outside, str(outside))
        check("the plain spelling of the allowed file works", allowed(ask("read_file", {"path": "/tmp/safe/report.txt"})))
        check("the symlink to the canary is refused",
              ask("read_file", {"path": "/tmp/safe/innocent.txt"})["verdict"] == "deny")
        check("broker still up", b.alive())
    finally:
        b.close()


def part_c():
    print("\nC. Many agents at once (40 connections x 25 requests)")
    b = Broker()
    try:
        plan = [
            ("read_file", {"path": "/tmp/safe/report.txt"}, "allow"),
            ("read_file", {"path": "/tmp/demo-home/.aws/credentials"}, "deny"),
            ("write_file", {"path": "/tmp/safe/x.txt", "content": "x"}, "deny"),
            ("exec", {"argv": ["ls"], "cwd": "/workspace"}, "deny"),
            ("http_get", {"url": "https://example.com"}, "deny"),
        ]
        k, n = 40, 25
        bad, lock = [], threading.Lock()

        def worker(w):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(20)
            s.connect(SOCK)
            f = s.makefile("rwb")
            for i in range(n):
                action, params, want = plan[(w + i) % len(plan)]
                rid = str(uuid.uuid4())
                f.write((json.dumps({"id": rid, "action": action, "params": params, "justification": f"w{w}"}) + "\n").encode())
                f.flush()
                line = f.readline()
                try:
                    r = json.loads(line)
                    if r.get("id") != rid or r.get("verdict") != want:
                        with lock:
                            bad.append((w, i, action, want, r.get("verdict"), r.get("id") == rid))
                except Exception as e:
                    with lock:
                        bad.append((w, i, action, "reply", str(e), False))
            s.close()

        t0 = time.time()
        threads = [threading.Thread(target=worker, args=(w,)) for w in range(k)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        took = time.time() - t0
        check(f"all {k * n} replies echoed their own id with the expected verdict", not bad, str(bad[:3]))
        doc = b.export()
        ids = [e["intent_id"] for e in doc["events"]]
        check("one intent row per request", len(ids) == k * n, f"{len(ids)} rows")
        check("no id repeated or missing", len(set(ids)) == k * n)
        check("one final verdict per request", all(e["final_verdict"] for e in doc["events"]))
        check("each request has exactly one verdict row", all(len(e["verdicts"]) == 1 for e in doc["events"]))
        denied = sum(1 for e in doc["events"] if e["final_verdict"] == "deny")
        allowed_n = sum(1 for e in doc["events"] if e["final_verdict"] == "allow")
        check("verdict counts match the plan", (allowed_n, denied) == (k * n // 5, k * n * 4 // 5), f"{allowed_n} allow, {denied} deny")
        print(f"      {k * n} requests in {took:.1f}s")
    finally:
        b.close()


def part_d():
    print("\nD. Human approval (answers piped to the broker's stdin)")
    b = Broker(unattended=False, stdin=subprocess.PIPE)
    try:
        b.p.stdin.write(b"y\nn\n\n")
        b.p.stdin.flush()
        r1 = ask("read_file", {"path": "/etc/hostname"})
        check("answer y: allowed", allowed(r1), str(r1)[:100])
        r2 = ask("read_file", {"path": "/etc/hostname"})
        check("answer n: denied", r2 and r2["verdict"] == "deny", str(r2)[:100])
        r3 = ask("read_file", {"path": "/etc/hostname"})
        check("empty answer: denied", r3 and r3["verdict"] == "deny", str(r3)[:100])
        doc = b.export()
        he = doc["summary"]["human_escalations"]
        check("the log records 1 allowed and 2 denied by a human", (he["allowed"], he["denied"]) == (1, 2), str(he))
        check("a human allow did not widen the policy",
              ask("read_file", {"path": "/tmp/demo-home/.aws/credentials"})["verdict"] == "deny")
    finally:
        b.close()
    # F9: without the opt-in, answers on a pipe are never used: escalations are denied as unattended.
    b = Broker(unattended=False, stdin=subprocess.PIPE, allow_piped=False)
    try:
        b.p.stdin.write(b"y\ny\n")
        b.p.stdin.flush()
        r = ask("read_file", {"path": "/etc/hostname"})
        check("without BROKER_ALLOW_PIPED_APPROVAL a piped 'y' is ignored: denied", r and r["verdict"] == "deny", str(r)[:100])
        he = b.export()["summary"]["human_escalations"]
        check("no human answer was recorded for it", he["allowed"] == 0, str(he))
    finally:
        b.close()


def part_e():
    print("\nE. Startup refusals")
    d = tempfile.mkdtemp(prefix="blt-")
    bad_yaml = os.path.join(d, "bad.yaml")
    open(bad_yaml, "w").write("rules: [this is: not: valid")
    bad_verdict = os.path.join(d, "verdict.yaml")
    open(bad_verdict, "w").write("rules:\n  - name: x\n    action: any\n    verdict: maybe\n")
    cases = {
        "unusable log path": dict(log="/proc/no-such-dir/broker.db"),
        "policy file missing": dict(policy=os.path.join(d, "missing.yaml")),
        "policy is not valid YAML": dict(policy=bad_yaml),
        "policy has an unknown verdict": dict(policy=bad_verdict),
    }
    for name, kw in cases.items():
        b = Broker(**kw)
        time.sleep(0.5)
        check(f"{name}: broker did not start", not b.alive() and not os.path.exists(SOCK),
              f"alive={b.alive()} socket={os.path.exists(SOCK)}")
        b.close()


def part_f():
    print("\nF. Type-ahead on a terminal (a 'y' typed before the question must not count)")
    import pty
    master, slave = pty.openpty()
    b = Broker(unattended=False, stdin=slave, stderr=slave)
    try:
        os.write(master, b"y\n")  # typed early, before any question is shown
        time.sleep(0.5)
        out = {}
        t = threading.Thread(target=lambda: out.update(r=ask("read_file", {"path": "/etc/hostname"}, timeout=15)))
        t.start()
        seen = b""
        deadline = time.time() + 10
        while b"approve?" not in seen and time.time() < deadline:
            try:
                import select
                if select.select([master], [], [], 0.2)[0]:
                    seen += os.read(master, 4096)
            except OSError:
                break
        check("the approval question was shown", b"approve?" in seen)
        time.sleep(0.5)
        os.write(master, b"n\n")  # the real answer, typed after the question
        t.join(timeout=15)
        r = out.get("r")
        check("the early 'y' was ignored; the answer typed after the question (n) decided it",
              r is not None and r["verdict"] == "deny", str(r)[:120])
    finally:
        b.close()
        os.close(master)
        os.close(slave)


def part_g():
    print("\nG. Kill switch")
    import signal
    fine = {"path": "/tmp/safe/report.txt"}
    for how in ("signal", "file"):
        b = Broker()
        kfile = b.db + ".KILL"
        check(f"{how}: the broker starts and serves", b.up and allowed(ask("read_file", fine)))
        if how == "signal":
            b.p.send_signal(signal.SIGUSR1)
        else:
            open(kfile, "w").close()
        time.sleep(0.6)
        r = ask("read_file", fine)
        check(f"{how}: a request that was allowed a moment ago is now refused", r is not None and not allowed(r), r)
        check(f"{how}: the refusal says the owner stopped the run", "stopped by the owner" in json.dumps(r), r)
        check(f"{how}: the broker is still running", b.alive())
        doc = b.export()
        stops = [e for e in doc["run_events"] if e["kind"] == "kill_switch"]
        check(f"{how}: the stop is logged exactly once", len(stops) == 1 and doc["summary"]["killed_by_owner"], stops)
        b.close()
    # A stale kill file from an earlier run must not stop a new one.
    d = tempfile.mkdtemp(prefix="blt-")
    db = os.path.join(d, "broker.db")
    open(db + ".KILL", "w").close()
    b = Broker(log=db)
    time.sleep(0.6)
    check("a stale kill file does not stop a new run", b.up and allowed(ask("read_file", fine)))
    b.close()


def part_h():
    print("\nH. Hash chain")
    import sqlite3
    b = Broker()
    for _ in range(3):
        ask("read_file", {"path": "/tmp/safe/report.txt"})
    ask("read_file", {"path": "/etc/passwd"})
    time.sleep(0.3)
    ch = b.export()["summary"]["chain"]
    check("the export carries the chain head and entry count", bool(ch) and ch["rows"] >= 8 and len(ch["head"]) == 64 and ch["algorithm"] == "sha256", ch)
    v = subprocess.run([BROKER, "verify", "--db", b.db], capture_output=True, text=True, cwd=ROOT)
    check("broker verify says the log is intact (exit 0), while the broker is still running", v.returncode == 0 and "OK:" in v.stdout and ch["head"] in v.stdout, v.stdout + v.stderr)
    v = subprocess.run([BROKER, "verify", "--db", b.db, "--head", ch["head"], "--rows", str(ch["rows"])], capture_output=True, text=True, cwd=ROOT)
    check("it also matches the head and count recorded elsewhere", v.returncode == 0, v.stdout)
    v = subprocess.run([BROKER, "verify", "--db", b.db, "--head", "0" * 64], capture_output=True, text=True, cwd=ROOT)
    check("a head that is not the log's is found (exit 1)", v.returncode == 1 and "cut short" in v.stdout, v.stdout)
    con = sqlite3.connect(b.db)
    con.execute("UPDATE verdicts SET verdict = 'allow' WHERE verdict = 'deny'")
    con.commit()
    con.close()
    v = subprocess.run([BROKER, "verify", "--db", b.db], capture_output=True, text=True, cwd=ROOT)
    check("a verdict changed behind the broker's back is found (exit 1)", v.returncode == 1 and "was changed" in v.stdout, v.stdout)
    check("a missing file is a clean error (exit 2)", subprocess.run([BROKER, "verify", "--db", "/nonexistent/x.db"], capture_output=True, text=True, cwd=ROOT).returncode == 2)
    b.close()


def main():
    if not os.path.exists(BROKER):
        raise SystemExit("build the broker first: cargo build -p broker")
    fixtures()
    for part in (part_a, part_b, part_c, part_d, part_e, part_f, part_g, part_h):
        part()
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for n in failed:
        print(f"  FAILED: {n}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
