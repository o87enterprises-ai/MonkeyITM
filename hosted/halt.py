#!/usr/bin/env python3
"""Stop everything on the nucleus host, right now.

    sudo python3 hosted/halt.py            # on the host VM (reads /etc/nucleus/nucleus.env)

Sends a signed POST /v1/halt to the local service: every run is killed, and no run starts
again until the owner removes <NUCLEUS_ROOT>/HALT and restarts the service. First step of
the incident plan (docs/INCIDENT_PLAN.md). Settings come from the environment, or from
the env file named by NUCLEUS_ENV_FILE (default /etc/nucleus/nucleus.env).
"""

import os
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nucleus_host as nh  # noqa: E402


def load_env(path):
    env = dict(os.environ)
    try:
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass
    return env


def main():
    env = load_env(os.environ.get("NUCLEUS_ENV_FILE", "/etc/nucleus/nucleus.env"))
    secret = env.get("NUCLEUS_SECRET", "")
    if len(secret) < 32:
        print("NUCLEUS_SECRET not found (is the env file readable? try sudo)", file=sys.stderr)
        return 2
    base = env.get("NUCLEUS_HALT_URL", f"http://127.0.0.1:{env.get('NUCLEUS_PORT', '8099')}")
    ts, nonce, path = str(int(time.time())), uuid.uuid4().hex, "/v1/halt"
    sig = nh.sign(secret.encode(), ts, nonce, "POST", path, b"")
    req = urllib.request.Request(base + path, data=b"", method="POST", headers={
        "X-Nucleus-Time": ts, "X-Nucleus-Nonce": nonce, "X-Nucleus-Sig": sig, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print("halted:", r.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        print(f"the service refused the halt: {e.code} {e.read().decode()[:200]}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"could not reach the service: {e}", file=sys.stderr)
    print("If the service is unreachable, stop it instead: sudo systemctl stop nucleus", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
