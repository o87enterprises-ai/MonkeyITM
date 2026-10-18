#!/usr/bin/env python3
"""monkeyitm guard: run your own agent so that its only way out is a MonkeyITM live session (Linux).

    export MONKEYITM_SESSION_TOKEN=mts_...        # or you are asked for it, hidden
    python3 cli/guard.py --session-url https://<site>/v1/sessions/ses_... [--workdir DIR] [--port 8765] -- <agent command...>

The agent runs in a bubblewrap sandbox with no network, no home directory, no environment from you (and so no
token or keys), and a read-only view of the system. Inside, http://127.0.0.1:<port>/mcp and /intent are its only
way to do anything: a bridge forwards them over a Unix socket to this process, outside the sandbox, which adds the
session token and relays to the session. Everything else (the internet, the API itself, other paths) is closed.
Point the agent's MCP client at the URL in $MONKEYITM_MCP_URL. --workdir is mounted read-write at /work; nothing
else of yours is visible.

Design: docs/SESSIONS_DESIGN.md section 6. Needs bwrap (apt install bubblewrap) and python3.
"""

import argparse
import getpass
import http.client
import os
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.parse

MAX_BODY = 4 * 1024 * 1024
ALLOWED = {"/intent", "/mcp"}
FORWARD_HEADERS = ("content-type", "accept", "mcp-protocol-version", "mcp-session-id", "last-event-id")


# ---------------------------------------------------------------- inside the sandbox: the loopback bridge

def bridge(port, sock_path):
    """127.0.0.1:port -> the guard's Unix socket, byte for byte. Runs inside the sandbox."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    while True:
        c, _ = srv.accept()
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            u.connect(sock_path)
        except OSError:
            c.close()
            continue
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


# ---------------------------------------------------------------- outside: the relay that holds the token

class Relay(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path, base, token):
        self.base = base        # urllib.parse result of the session URL
        self.token = token
        super().__init__(path, Handler)


class Handler(socketserver.StreamRequestHandler):
    def reply(self, status, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.wfile.write(f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n".encode() + b)

    def handle(self):
        line = self.rfile.readline(8192).decode("latin-1").strip()
        m = re.match(r"^(GET|POST|DELETE) (\S+) HTTP/1\.[01]$", line)
        headers = {}
        while True:
            h = self.rfile.readline(8192).decode("latin-1")
            if h in ("\r\n", "\n", ""):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if not m:
            return self.reply(400, '{"error":"bad request"}')
        method, path = m.group(1), urllib.parse.urlsplit(m.group(2)).path
        if path not in ALLOWED:
            return self.reply(404, '{"error":"only /mcp and /intent are open through the guard"}')
        try:
            n = int(headers.get("content-length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return self.reply(413, '{"error":"bad or oversized body"}')
        body = self.rfile.read(n) if n else None
        b = self.server.base
        conn = (http.client.HTTPSConnection if b.scheme == "https" else http.client.HTTPConnection)(b.netloc, timeout=150)
        out = {k: headers[k] for k in FORWARD_HEADERS if k in headers}
        out["Authorization"] = f"Bearer {self.server.token}"
        out["User-Agent"] = "monkeyitm-guard/1"
        try:
            conn.request(method, b.path.rstrip("/") + path, body=body, headers=out)
            r = conn.getresponse()
            data = r.read()
            ctype = r.getheader("Content-Type", "application/json")
            self.reply(r.status, data, ctype)
        except OSError as e:
            self.reply(502, '{"error":"the guard could not reach the session: %s"}' % type(e).__name__)
        finally:
            conn.close()


def sandbox_argv(guard_file, sock_dir, port, workdir, cmd):
    ro = []
    for p in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc/alternatives", "/etc/ssl", "/etc/ca-certificates",
              "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf"):
        if os.path.exists(p):
            ro += ["--ro-bind", p, p]
    mcp = f"http://127.0.0.1:{port}/mcp"
    argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", *ro,
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
            "--dir", "/guard", "--ro-bind", guard_file, "/guard/guard.py", "--bind", sock_dir, "/guard/sock",
            "--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/tmp",
            "--setenv", "MONKEYITM_MCP_URL", mcp, "--setenv", "MONKEYITM_INTENT_URL", f"http://127.0.0.1:{port}/intent"]
    if workdir:
        argv += ["--bind", workdir, "/work", "--chdir", "/work"]
    else:
        argv += ["--chdir", "/tmp"]
    # The sandbox's own root (a private tmpfs) read-only too; only /tmp, /run and /work stay writable.
    argv += ["--remount-ro", "/"]
    # The bridge starts first, then the agent replaces the shell; when the agent exits the sandbox ends.
    script = ('python3 /guard/guard.py --bridge %d /guard/sock/s & '
              'for i in $(seq 50); do python3 -c "import socket;socket.create_connection((\'127.0.0.1\',%d),1)" 2>/dev/null && break; sleep 0.1; done; '
              'exec "$@"') % (port, port)
    return argv + ["sh", "-c", script, "guard-agent", *cmd]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--session-url", help="https://<site>/v1/sessions/ses_...")
    ap.add_argument("--workdir", help="a directory mounted read-write at /work for the agent")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--allow-http", action="store_true", help=argparse.SUPPRESS)   # tests against a local fake only
    ap.add_argument("--bridge", nargs=2, metavar=("PORT", "SOCK"), help=argparse.SUPPRESS)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    if a.bridge:
        return bridge(int(a.bridge[0]), a.bridge[1])
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not a.session_url or not cmd:
        ap.error("usage: guard.py --session-url URL -- <agent command...>")
    if sys.platform != "linux" or not shutil.which("bwrap"):
        sys.exit("guard needs Linux with bubblewrap (apt install bubblewrap)")
    base = urllib.parse.urlsplit(a.session_url)
    if base.scheme != "https" and not a.allow_http:
        sys.exit("the session URL must be https://")
    if not re.search(r"/v1/sessions/ses_[0-9a-f]{16}$", base.path.rstrip("/")):
        sys.exit("the session URL must end in /v1/sessions/ses_<16 hex>")
    token = (os.environ.pop("MONKEYITM_SESSION_TOKEN", "") or getpass.getpass("Session token (mts_..., hidden): ")).strip()
    if not re.fullmatch(r"mts_[0-9a-f]{32}", token):
        sys.exit("that does not look like a session token (mts_ followed by 32 hex characters)")
    if a.workdir and not os.path.isdir(a.workdir):
        sys.exit(f"--workdir {a.workdir} is not a directory")
    if a.workdir:
        # The work folder is mounted read-write: never the whole system or a whole home directory.
        real = os.path.realpath(a.workdir)
        home = os.path.realpath(os.path.expanduser("~"))
        if real in ("/", "/home", "/root", "/etc", "/usr", "/var", "/proc", "/sys", "/dev", home) or home.startswith(real + os.sep):
            sys.exit(f"--workdir {a.workdir} ({real}) would expose too much: give the agent a project folder, not {real}")

    sock_dir = tempfile.mkdtemp(prefix="mitm-guard-")
    os.chmod(sock_dir, 0o700)
    relay = Relay(os.path.join(sock_dir, "s"), base, token)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    child = subprocess.Popen(sandbox_argv(os.path.abspath(__file__), sock_dir, a.port,
                                          os.path.abspath(a.workdir) if a.workdir else None, cmd),
                             env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    signal.signal(signal.SIGINT, lambda *_: child.terminate())
    signal.signal(signal.SIGTERM, lambda *_: child.terminate())
    code = child.wait()
    relay.shutdown()
    shutil.rmtree(sock_dir, ignore_errors=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
