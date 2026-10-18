#!/usr/bin/env python3
"""Checks the broker's retry on a rate-limited model call.

    cargo build -p broker && python3 scripts/flaky-llm-check.py

A stand-in provider answers 429 (Retry-After: 1) twice, then a normal reply. The
broker should return the reply, not a denial, and the provider should see 3 calls.
"""
import json, os, signal, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCK = f"/tmp/flaky-check-{os.getpid()}.sock"
calls = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        calls.append(time.time())
        if len(calls) <= 2:
            self.send_response(429); self.send_header("Retry-After", "1"); self.end_headers()
            return
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = tempfile.mkdtemp()
env = dict(os.environ, BROKER_SOCKET=SOCK, BROKER_LOG=f"{tmp}/b.db", BROKER_UNATTENDED="1",
           BROKER_POLICY=f"{ROOT}/policies/multi-agent-test.yaml",
           BROKER_LLM_URL=f"http://127.0.0.1:{srv.server_port}/v1/chat/completions")
b = subprocess.Popen([f"{ROOT}/target/debug/broker"], cwd=ROOT, env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(100):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX); s.connect(SOCK)
    s.sendall(json.dumps({"id": "1", "action": "llm_chat", "params": {"messages": [{"role": "user", "content": "hi"}]}}).encode() + b"\n")
    r = json.loads(s.makefile().readline())
finally:
    b.send_signal(signal.SIGINT); b.wait(timeout=10)
ok = r.get("verdict") == "allow" and len(calls) == 3
print(("PASS" if ok else "FAIL"), f"verdict={r.get('verdict')} provider_calls={len(calls)}")
sys.exit(0 if ok else 1)
