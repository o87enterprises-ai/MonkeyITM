#!/usr/bin/env bash
# Prepare a Vercel Sandbox (Ubuntu) to run MonkeyITM-VM's tests and agent launch.
# TEST HOSTS ONLY: it opens Docker's socket to the sandbox user, which is fine on a
# throwaway virtual machine and wrong anywhere shared.
#
#   bash scripts/vercel-sandbox-setup.sh
#
# Safe to repeat. Run it again whenever the sandbox restarts: the /proc covers and the
# Docker service do not survive a restart.
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$(id -u)" -ne 0 ] || { echo "run as the normal sandbox user; the script uses sudo"; exit 1; }

fail=0
pass() { echo "  PASS  $1"; }
miss() { echo "  FAIL  $1"; fail=1; }

echo "1. packages"
need=()
for p in bubblewrap docker.io cargo python3 build-essential; do
  dpkg -s "$p" >/dev/null 2>&1 || need+=("$p")
done
if [ "${#need[@]}" -gt 0 ]; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null 2>&1
fi
echo "  installed: bubblewrap docker.io cargo python3 build-essential"

echo "2. /proc covers"
# Vercel blanks these two files; Linux then refuses a fresh /proc inside bubblewrap.
sudo umount /proc/kcore /proc/keys 2>/dev/null || true

echo "3. bubblewrap without ambient capabilities"
# The sandbox user holds every capability, which makes bubblewrap refuse to start.
sudo tee /usr/local/bin/bwrap >/dev/null <<'EOF'
#!/bin/sh
exec setpriv --ambient-caps=-all --inh-caps=-all /usr/bin/bwrap "$@"
EOF
sudo chmod 755 /usr/local/bin/bwrap
hash -r

echo "4. Docker"
pgrep -x dockerd >/dev/null || sudo sh -c 'dockerd >/tmp/dockerd.log 2>&1 &'
for _ in $(seq 1 30); do
  sudo docker info >/dev/null 2>&1 && break
  sleep 1
done
sudo chmod 666 /var/run/docker.sock
echo "  NOTE  Docker's socket is now open to every user on this machine (test host only)"

echo "5. checks"
if bwrap --ro-bind / / --unshare-all --dev /dev --proc /proc true 2>/dev/null; then
  pass "bubblewrap starts an isolated sandbox with its own /proc"
else
  miss "bubblewrap could not start (run: bwrap --ro-bind / / --unshare-all --dev /dev --proc /proc true)"
fi
if docker info >/dev/null 2>&1; then
  pass "Docker answers as the sandbox user"
else
  miss "Docker is not answering (see /tmp/dockerd.log)"
fi
if cargo --version >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
  pass "cargo and python3 are present ($(cargo --version | cut -d' ' -f1-2))"
else
  miss "cargo or python3 is missing"
fi

echo "6. build the broker"
if cargo build -q -p broker; then
  pass "broker built"
else
  miss "broker did not build"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "Ready. Next:  python3 scripts/broker-live-tests.py"
  echo "              python3 scripts/workbench-test.py"
  echo "              python3 scripts/multi-agent-test.py"
  echo "Sandbox sessions on the free plan last at most 45 minutes."
else
  echo "Not ready: fix the FAIL lines above and run this script again."
  exit 1
fi
