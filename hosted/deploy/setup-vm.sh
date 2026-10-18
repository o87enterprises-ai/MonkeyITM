#!/usr/bin/env bash
# Prepare a fresh Debian or Ubuntu VM to run the nucleus host (docs/HOSTED_REAL_TEST.md).
#
#   sudo bash setup-vm.sh                 # as root, on the VM, from a checkout of the repo
#   sudo bash setup-vm.sh --check         # only report what is and is not in place
#
# What it does, in order (safe to run again):
#   1. installs bubblewrap, git, build tools, Python and a firewall
#   2. creates an unprivileged user `nucleus` (no login, no sudo) and its folders
#   3. installs the repository read-only to /opt/monkeyitm (only logs/ is writable by nucleus)
#   4. builds the broker and installs it to /opt/monkeyitm-bin/broker
#   5. writes /etc/nucleus/nucleus.env (mode 0600, root only) with a fresh secret, if absent
#   6. installs the systemd service and the health-check timer
#   7. turns the firewall on: nothing inbound except SSH from NUCLEUS_SSH_FROM (default:
#      nowhere; set it, or you will lock yourself out of a remote VM)
# It does NOT start the service: fill in /etc/nucleus/nucleus.env first (the model key).
# This VM must hold nothing else of value and no credentials that matter.
set -euo pipefail

CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
APP=/opt/monkeyitm
BIN=/opt/monkeyitm-bin
DATA=/var/lib/nucleus
ENVF=/etc/nucleus/nucleus.env
SSH_FROM="${NUCLEUS_SSH_FROM:-}"

say() { printf '%s\n' "$*"; }
need_root() { [ "$(id -u)" = 0 ] || { say "run as root (sudo)"; exit 1; }; }

if [ "$CHECK" = 1 ]; then
  ok() { say "  ok    $1"; }; no() { say "  MISSING  $1"; }
  command -v bwrap >/dev/null && ok "bubblewrap" || no "bubblewrap"
  id nucleus >/dev/null 2>&1 && ok "user nucleus" || no "user nucleus"
  [ -d "$APP/scripts" ] && ok "$APP" || no "$APP"
  [ -x "$BIN/broker" ] && ok "$BIN/broker" || no "$BIN/broker"
  [ -f "$ENVF" ] && ok "$ENVF ($(stat -c %a "$ENVF"))" || no "$ENVF"
  [ -f /etc/systemd/system/nucleus.service ] && ok "nucleus.service" || no "nucleus.service"
  ufw status 2>/dev/null | head -1 || true
  # bubblewrap needs unprivileged user namespaces; some systems switch them off.
  if ! id nucleus >/dev/null 2>&1; then
    no "bubblewrap check for the nucleus user (the user does not exist yet)"
  elif sudo -u nucleus bwrap --unshare-all --ro-bind /usr /usr --symlink usr/bin /bin --proc /proc --dev /dev -- /usr/bin/true 2>/dev/null; then
    ok "bubblewrap works for the nucleus user"
  else
    no "bubblewrap does not work for the nucleus user (see the note in docs/HOSTED_REAL_TEST.md)"
  fi
  exit 0
fi

need_root
export DEBIAN_FRONTEND=noninteractive
say "1/7 packages"
apt-get update -qq
apt-get install -y -qq bubblewrap git curl ca-certificates build-essential pkg-config python3 ufw >/dev/null

say "2/7 user and folders"
id nucleus >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin nucleus
install -d -m 0700 -o nucleus -g nucleus "$DATA"
install -d -m 0750 -o root -g nucleus /etc/nucleus

say "3/7 code (read-only to the service)"
mkdir -p "$APP"
# Everything except build output, local state and the git history.
tar -C "$SRC" --exclude=./target --exclude=./.git --exclude=./logs --exclude=./site/.wrangler --exclude=./site/node_modules -cf - . | tar -C "$APP" -xf -
chown -R root:root "$APP"
chmod -R go-w "$APP"
install -d -m 0755 -o nucleus -g nucleus "$APP/logs"   # run-agent.sh writes here

say "4/7 broker binary"
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"
( cd "$SRC" && cargo build --release -p broker )
install -d -m 0755 "$BIN"
install -m 0755 "$SRC/target/release/broker" "$BIN/broker"

say "5/7 settings"
if [ ! -f "$ENVF" ]; then
  umask 077
  cat > "$ENVF" <<EOF
# Settings for the nucleus host. Mode 0600, root only. Keep the secret out of chat and email.
NUCLEUS_SECRET=$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 48)
NUCLEUS_LLM_URL=https://integrate.api.nvidia.com/v1/chat/completions
NUCLEUS_LLM_MODELS=nvidia/nemotron-3-super-120b-a12b
NUCLEUS_LLM_KEY=PUT-THE-OWNERS-MODEL-KEY-HERE
NUCLEUS_ROOT=$DATA
NUCLEUS_PORT=8099
NUCLEUS_BROKER=$BIN/broker
# Optional: where the health check posts a warning (a URL you choose); leave empty for none.
MONITOR_WEBHOOK=
EOF
  chown root:nucleus "$ENVF"; chmod 0640 "$ENVF"
  say "   created $ENVF: put the model key in it, and copy NUCLEUS_SECRET to the Worker"
else
  say "   $ENVF already exists: left alone"
fi

say "6/7 services"
install -m 0644 "$SRC/hosted/deploy/nucleus.service" /etc/systemd/system/nucleus.service
install -m 0644 "$SRC/hosted/deploy/nucleus-monitor.service" /etc/systemd/system/nucleus-monitor.service
install -m 0644 "$SRC/hosted/deploy/nucleus-monitor.timer" /etc/systemd/system/nucleus-monitor.timer
systemctl daemon-reload
systemctl enable nucleus.service nucleus-monitor.timer >/dev/null

say "7/7 firewall"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
if [ -n "$SSH_FROM" ]; then
  ufw allow from "$SSH_FROM" to any port 22 proto tcp >/dev/null
  say "   SSH allowed from $SSH_FROM only"
else
  say "   WARNING: NUCLEUS_SSH_FROM not set: SSH is NOT allowed. Set it (your address) and run again, or use the provider's console."
fi
ufw --force enable >/dev/null

say ""
say "Done. Next:"
say "  1. edit $ENVF (the model key; check the model list)"
say "  2. bash $SRC/hosted/deploy/setup-vm.sh --check"
say "  3. systemctl start nucleus ; curl -s http://127.0.0.1:8099/healthz"
say "  4. set up the tunnel (hosted/deploy/README.md), then the Worker settings"
