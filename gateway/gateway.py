#!/usr/bin/env python3
"""The gateway for shape B: a team's own agent talks to a broker we host (docs/EVALUATION_PLATFORM.md).

    python3 gateway/gateway.py            # settings from the environment, below

It is a thin authenticated front for ONE broker's Unix socket. The broker still decides,
executes and logs every request; the gateway only carries the team's JSON requests to it and the
broker's verdicts back, and refuses anything that is not a well-formed request from the one
bearer token it was started with. Standard library only.

  GATEWAY_TOKEN         the bearer token (required, 32+ characters); one team, one token
  GATEWAY_BROKER_SOCK   the broker's socket (default /tmp/broker.sock)
  GATEWAY_PORT          default 8300
  GATEWAY_HOST          default 127.0.0.1 (the sandbox's published port reaches it)
  GATEWAY_TTL_SECONDS   the token stops working after this long (default 2700)
  GATEWAY_RATE          requests per second allowed (default 5, burst 10)
  GATEWAY_MAX_REQUESTS  total requests per session (default 2000)
  GATEWAY_STATE_DIR     where counters and the closing note go (default /tmp/gateway)

Endpoints (all but /healthz need `Authorization: Bearer <token>`):
  POST /v1/intent   body: one intent {"id","action","params","justification"}; reply: the broker's verdict
  GET  /v1/status   how many requests, how many were refused, whether the run is closed
  POST /v1/finish   the team is done: closes the session (the broker is not stopped here)

Everything the gateway itself refuses (bad token, too fast, too big, not JSON, closed) is counted,
not sent to the broker, and ends the session after GATEWAY_MAX_BAD of them (default 30).
"""

import hmac
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 4 * 1024 * 1024        # matches the broker's line limit
MAX_REPLY = 8 * 1024 * 1024
READ_TIMEOUT = 130                 # a model call inside the broker may take two minutes


class Session:
    def __init__(self, ttl, rate, max_requests, max_bad):
        self.started = time.time()
        self.ttl, self.rate, self.max_requests, self.max_bad = ttl, rate, max_requests, max_bad
        self.lock = threading.Lock()
        self.tokens, self.last = float(rate * 2), time.time()     # token bucket, burst = 2 x rate
        self.requests = self.refused = self.bad = 0
        self.closed = None            # reason, once closed

    def close(self, why):
        with self.lock:
            if self.closed is None:
                self.closed = why

    def admit(self):
        """None if the request may go on, else the reason it may not."""
        with self.lock:
            now = time.time()
            if self.closed:
                return f"the session is closed ({self.closed})"
            if now - self.started > self.ttl:
                self.closed = "expired"
                return "the session has expired"
            self.tokens = min(self.rate * 2.0, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < 1:
                return "too many requests: slow down"
            if self.requests >= self.max_requests:
                self.closed = "request limit reached"
                return "the request limit for this session has been reached"
            self.tokens -= 1
            self.requests += 1
            return None

    def note_bad(self):
        with self.lock:
            self.bad += 1
            if self.bad >= self.max_bad and self.closed is None:
                self.closed = "too many bad requests"


def ask_broker(sock_path, line):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(READ_TIMEOUT)
    try:
        s.connect(sock_path)
        s.sendall(line + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REPLY:
                raise OSError("reply too large")
        return buf
    finally:
        s.close()


def make_handler(cfg, session):
    token = cfg["token"].encode()

    class H(BaseHTTPRequestHandler):
        server_version = "gateway"
        sys_version = ""

        def log_message(self, *a):
            pass

        def reply(self, status, obj):
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def authed(self):
            got = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip().encode()
            if not hmac.compare_digest(got, token):
                session.note_bad()
                self.reply(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if self.path == "/healthz":
                return self.reply(200, {"ok": True})
            if not self.authed():
                return
            if self.path == "/v1/status":
                with session.lock:
                    return self.reply(200, {"requests": session.requests, "bad_requests": session.bad,
                                            "closed": session.closed, "seconds_left": max(0, int(session.ttl - (time.time() - session.started)))})
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n < 0:
                return self.reply(400, {"error": "bad Content-Length"})
            if n > MAX_BODY:
                session.note_bad()
                return self.reply(413, {"error": "too large"})
            body = self.rfile.read(n) if n else b""
            if not self.authed():
                return
            if self.path == "/v1/finish":
                session.close("finished by the team")
                return self.reply(200, {"closed": True})
            if self.path != "/v1/intent":
                return self.reply(404, {"error": "not found"})
            why = session.admit()
            if why:
                session.note_bad()
                return self.reply(429 if "slow" in why else 403, {"error": why})
            try:
                intent = json.loads(body)
                if not isinstance(intent, dict):
                    raise ValueError
            except ValueError:
                session.note_bad()
                return self.reply(400, {"error": "expected one JSON object"})
            # One request, one line: re-encode so a body cannot smuggle a second line to the broker.
            line = json.dumps(intent, separators=(",", ":")).encode()
            try:
                raw = ask_broker(cfg["sock"], line)
                verdict = json.loads(raw)
            except (OSError, ValueError):
                return self.reply(502, {"error": "the broker did not answer"})   # no paths or details to the client
            if verdict.get("verdict") == "deny":
                with session.lock:
                    session.refused += 1
                if "halted by tripwire" in str(verdict.get("reason", "")):
                    session.close("the broker halted the run (tripwire)")    # this reply is the last one
            return self.reply(200, verdict)

    return H


def main():
    env = os.environ
    token = env.get("GATEWAY_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("GATEWAY_TOKEN is required (32+ characters)")
    cfg = {"token": token, "sock": env.get("GATEWAY_BROKER_SOCK", "/tmp/broker.sock")}
    session = Session(int(env.get("GATEWAY_TTL_SECONDS", "2700")), float(env.get("GATEWAY_RATE", "5")),
                      int(env.get("GATEWAY_MAX_REQUESTS", "2000")), int(env.get("GATEWAY_MAX_BAD", "30")))
    srv = ThreadingHTTPServer((env.get("GATEWAY_HOST", "127.0.0.1"), int(env.get("GATEWAY_PORT", "8300"))), make_handler(cfg, session))
    state = env.get("GATEWAY_STATE_DIR", "/tmp/gateway")
    os.makedirs(state, mode=0o700, exist_ok=True)

    def closer():
        while True:
            time.sleep(2)
            if session.closed:
                with open(os.path.join(state, "closed.json"), "w") as f:
                    json.dump({"closed": session.closed, "requests": session.requests, "refused": session.refused,
                               "bad": session.bad, "at": int(time.time())}, f)
    threading.Thread(target=closer, daemon=True).start()
    print(f"gateway on {srv.server_address[0]}:{srv.server_address[1]} for the broker at {cfg['sock']}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
