#!/usr/bin/env python3
"""Tests of cli/guard.py (Linux, needs bubblewrap): the agent inside reaches the session only through the guard.

    python3 cli/guard-test.py

A fake session server runs on the host; an "agent" (a Python script) runs inside the guard and tries the routes a
real agent might: the bridge (must work, with the token added outside), the fake server directly, the internet,
the token in its own or any process's environment, the user's home directory, other paths through the bridge.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = "mts_" + "c" * 32
SID = "ses_0123456789abcdef"
results = []
seen = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "origin": self.headers.get("Origin")})
        out = json.dumps({"ok": True, "path": self.path, "auth_ok": self.headers.get("Authorization") == f"Bearer {TOKEN}",
                          "echo": body.decode(errors="replace")[:100]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


AGENT = r'''
import json, os, socket, urllib.request, glob
r = {}
def post(path, body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'):
    q = urllib.request.Request("http://127.0.0.1:8765" + path, data=body, headers={"Content-Type": "application/json", "Origin": "https://evil.example"})
    try:
        with urllib.request.urlopen(q, timeout=10) as res: return res.status, json.loads(res.read())
    except urllib.error.HTTPError as e: return e.code, None
    except Exception as e: return -1, str(e)
r["mcp"] = post("/mcp")
r["intent"] = post("/intent", b'{"action":"read_file","params":{"path":"/workspace/a"}}')
r["other"] = post("/v1/jobs")[0]
def can_connect(host, port):
    try: socket.create_connection((host, port), 3).close(); return True
    except OSError: return False
r["direct_fake"] = can_connect("127.0.0.1", int(os.environ.get("FAKE_PORT", "0") or 0) or FAKEPORT)
r["internet"] = can_connect("1.1.1.1", 443)
r["dns"] = can_connect("example.com", 443)
r["env_has_token"] = any("mts_" in v for v in os.environ.values())
leak = False
for p in glob.glob("/proc/[0-9]*/environ") + glob.glob("/proc/[0-9]*/cmdline"):
    try:
        if b"mts_" in open(p, "rb").read(): leak = True
    except OSError: pass
r["proc_has_token"] = leak
r["home_visible"] = os.path.exists(os.path.expanduser("~real")) or os.path.isdir("/home") and bool(os.listdir("/home"))
r["root_home"] = os.path.isdir("/root") and bool(os.listdir("/root")) if os.path.isdir("/root") else False
r["mcp_url_env"] = os.environ.get("MONKEYITM_MCP_URL")
def can_write(p):
    try: open(p, "w").write("x"); return True
    except OSError: return False
r["write_usr"] = can_write("/usr/pwned") or can_write("/etc/pwned") or can_write("/pwned")
r["write_guard"] = can_write("/guard/guard.py")
r["host_procs"] = len(glob.glob("/proc/[0-9]*"))
import subprocess as sp
r["mount"] = sp.run(["sh", "-c", "mount -t tmpfs x /mnt 2>/dev/null || mount -o remount,rw /usr 2>/dev/null"]).returncode == 0
r["unshare_net"] = sp.run(["sh", "-c", "unshare -n true 2>/dev/null"]).returncode == 0 and can_connect("1.1.1.1", 443)
r["raw_http_to_bridge_other_path"] = None
try:
    s = socket.create_connection(("127.0.0.1", 8765), 3)
    s.sendall(b"POST /mcp/../v1/jobs HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"); r["raw_http_to_bridge_other_path"] = s.recv(200).split(b" ")[1].decode()
except Exception as e: r["raw_http_to_bridge_other_path"] = str(e)
open("/work/out.json", "w").write(json.dumps(r))
'''


def main():
    if sys.platform != "linux" or subprocess.run(["which", "bwrap"], capture_output=True).returncode:
        print("skipped: needs Linux and bubblewrap")
        print("0 passed, 0 failed")
        return 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    work = tempfile.mkdtemp(prefix="guardtest-")
    agent = os.path.join(work, "agent.py")
    open(agent, "w").write(AGENT.replace("FAKEPORT", str(port)))
    url = f"http://127.0.0.1:{port}/v1/sessions/{SID}"
    env = {**os.environ, "MONKEYITM_SESSION_TOKEN": TOKEN}

    print("\nRefusals before anything runs")
    bad = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "--session-url", url, "--", "true"], env=env, capture_output=True, text=True)
    check("a plain-http session URL is refused (https only)", bad.returncode != 0 and "https" in bad.stderr, bad.stderr)
    bad = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "--allow-http", "--session-url", url, "--", "true"],
                         env={**os.environ, "MONKEYITM_SESSION_TOKEN": "mitm_live_nope"}, capture_output=True, text=True)
    check("something that is not a session token is refused", bad.returncode != 0 and "session token" in bad.stderr, bad.stderr)
    bad = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "--allow-http", "--session-url", f"http://127.0.0.1:{port}/v1/jobs", "--", "true"],
                         env=env, capture_output=True, text=True)
    check("a URL that is not a session is refused", bad.returncode != 0, bad.stderr)
    for wd in ("/", os.path.expanduser("~"), "/home"):
        bad = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "--allow-http", "--session-url", url, "--workdir", wd, "--", "true"],
                             env=env, capture_output=True, text=True)
        check(f"--workdir {wd} is refused (too much of the machine)", bad.returncode != 0 and "expose too much" in bad.stderr, bad.stderr)

    print("\nAn agent inside the guard")
    p = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "--allow-http", "--session-url", url, "--workdir", work,
                        "--", "python3", "/work/agent.py"], env=env, capture_output=True, text=True, timeout=120)
    try:
        r = json.load(open(os.path.join(work, "out.json")))
    except (OSError, ValueError):
        check("the agent ran", False, p.stdout[-400:] + p.stderr[-400:])
        print(f"\n{sum(ok for _, ok in results)} passed, {sum(not ok for _, ok in results)} failed")
        return 1
    check("the agent ran inside the sandbox and finished", p.returncode == 0, p.stderr[-300:])
    check("its MCP call reached the session through the guard", r["mcp"][0] == 200 and r["mcp"][1]["path"] == f"/v1/sessions/{SID}/mcp", r["mcp"])
    check("the guard added the session token outside the sandbox", r["mcp"][1]["auth_ok"] is True and r["intent"][1]["auth_ok"] is True, r)
    check("the intent endpoint works the same way", r["intent"][0] == 200 and r["intent"][1]["path"].endswith("/intent"), r["intent"])
    check("the agent's Origin header is not passed on", all(s["origin"] is None for s in seen), seen)
    check("any other path is closed (404)", r["other"] == 404, r["other"])
    check("the agent cannot reach the session server directly", r["direct_fake"] is False)
    check("the agent cannot reach the internet", r["internet"] is False and r["dns"] is False)
    check("the token is not in the agent's environment", r["env_has_token"] is False)
    check("the token is in no process environment or command line it can see", r["proc_has_token"] is False)
    check("the user's home directories are not visible", r["home_visible"] is False and r["root_home"] is False, r)
    check("the agent is told where the session is", r["mcp_url_env"] == "http://127.0.0.1:8765/mcp", r["mcp_url_env"])
    check("only the agent's requests reached the server (two, both with the token)", len(seen) == 2, seen)
    check("the system and guard's own code are read-only to the agent", r["write_usr"] is False and r["write_guard"] is False, r)
    check("the agent sees only its own few processes, not the host's", r["host_procs"] < 10, r["host_procs"])
    check("the agent cannot mount or remount filesystems", r["mount"] is False)
    check("a new namespace does not give the agent a network", r["unshare_net"] is False)
    check("a raw request with a dot-dot path through the bridge is refused (404)", r["raw_http_to_bridge_other_path"] == "404", r["raw_http_to_bridge_other_path"])

    srv.shutdown()
    passed, failed = sum(ok for _, ok in results), sum(not ok for _, ok in results)
    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
