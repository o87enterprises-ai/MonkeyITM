#!/usr/bin/env python3
"""Send one intent (JSON on stdin) to the broker, print the verdict (one line)."""
import socket
import sys

SOCK = "/tmp/broker.sock"

payload = sys.stdin.read().strip()
if not payload:
    print("no intent on stdin", file=sys.stderr)
    sys.exit(2)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
s.sendall((payload + "\n").encode())

buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
s.close()

print(buf.decode().rstrip())
