#!/usr/bin/env bash
# One live session's containment (docs/SESSIONS_DESIGN.md): a workbench container with no network and
# a broker on its own socket. The runner (runner/runner.py) starts this, reads READY, carries the
# customer's intents to the broker's socket, and stops this script when the session ends.
#
# Environment (set by the runner; nothing here is read from a file):
#   SESSION_DIR       the session's folder: workspace/ is mounted at /workspace in the container, and
#                     the broker's log is written here
#   SESSION_SOCKET    where the broker listens (a short path: Unix socket paths are limited)
#   SESSION_POLICY    the policy file (scripts/make-eval-policy.py)
#   SESSION_BASE      the container image (a base from the allow-list in the API)
#   SESSION_TRIPWIRE  denied requests before the broker halts the session
#   BROKER_LLM_URL / _MODEL / _KEY   the model the agent's llm_chat calls reach (the key stays here)
#
# Prints READY when the broker is listening, then waits. SIGTERM stops it cleanly (the broker logs its
# shutdown, the container is removed). The agent itself is NOT here: it runs on the customer's side and
# only ever reaches this broker through the relay.
set -euo pipefail
: "${SESSION_DIR:?}" "${SESSION_SOCKET:?}" "${SESSION_POLICY:?}" "${SESSION_BASE:?}"
DOCKER="${BROKER_DOCKER:-docker}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="$SESSION_DIR/workspace"
WB="monkeyitm-sess-$(basename "$SESSION_DIR")"
BPID=""

cleanup() {
  [ -n "$BPID" ] && kill "$BPID" 2>/dev/null || true
  # Give the broker a moment to write its shutdown record before the container goes.
  for _ in $(seq 40); do [ -z "$BPID" ] || kill -0 "$BPID" 2>/dev/null || break; sleep 0.1; done
  "$DOCKER" rm -f "$WB" >/dev/null 2>&1 || true
  rm -f "$SESSION_SOCKET"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

mkdir -p "$WS"
# No network, the workspace as /workspace, running as the host user so files stay removable.
# Resource limits (processes, memory, CPU) need cgroup controllers the host may not hand to Docker: a
# Vercel Sandbox does not (Docker then refuses to start the container at all). Probe once and use them
# where they work. Where they cannot, the session runs without them and says so; a production runner
# sets MITM_REQUIRE_LIMITS=1 to refuse to run unlimited.
LIMITS=(--pids-limit 256 --memory 1g --memory-swap 1g --cpus 1)
if ! "$DOCKER" run --rm --network none "${LIMITS[@]}" "$SESSION_BASE" true >/dev/null 2>&1; then
  if [ "${MITM_REQUIRE_LIMITS:-0}" = 1 ]; then
    echo "this host cannot apply container resource limits and MITM_REQUIRE_LIMITS=1: refusing to run" >&2
    exit 1
  fi
  # Fallback that needs no cgroups: per-process kernel limits (rlimits). They stop a fork bomb, a single
  # process eating memory, and a single huge file; they do not cap total CPU, or memory summed over processes.
  LIMITS=(--ulimit nproc=512 --ulimit data=2147483648 --ulimit fsize=1073741824 --ulimit nofile=1024)
  if "$DOCKER" run --rm --network none --user "$(id -u):$(id -g)" "${LIMITS[@]}" "$SESSION_BASE" true >/dev/null 2>&1; then
    echo "WARNING: this host cannot apply cgroup limits: the container runs with per-process limits only (processes, memory per process, file size), not total CPU or memory" >&2
  else
    echo "WARNING: this host cannot apply container resource limits: the container runs WITHOUT process, memory or CPU limits" >&2
    LIMITS=()
  fi
fi

# Hardened: no capabilities and no privilege gain always; bounded processes, memory and CPU where the host allows.
"$DOCKER" run -d --name "$WB" --network none --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges ${LIMITS[@]+"${LIMITS[@]}"} \
  -v "$WS:/workspace" -w /workspace "$SESSION_BASE" sleep infinity >/dev/null

cd "$ROOT"
BIN="${BROKER_BIN:-target/debug/broker}"
[ -x "$BIN" ] || { echo "the broker is not built ($BIN): cargo build -p broker" >&2; exit 1; }
rm -f "$SESSION_SOCKET"
BROKER_POLICY="$SESSION_POLICY" BROKER_LOG="$SESSION_DIR/broker.db" BROKER_SOCKET="$SESSION_SOCKET" \
BROKER_UNATTENDED=1 BROKER_TRIPWIRE="${SESSION_TRIPWIRE:-10}" \
BROKER_WORKBENCH="$WB" BROKER_WORKBENCH_DIR="$WS" BROKER_DOCKER="$DOCKER" \
  "$BIN" </dev/null 2>"$SESSION_DIR/broker.txt" &
BPID=$!
for _ in $(seq 100); do [ -S "$SESSION_SOCKET" ] && break; sleep 0.1; done
[ -S "$SESSION_SOCKET" ] || { echo "the broker did not start:" >&2; cat "$SESSION_DIR/broker.txt" >&2; exit 1; }
echo READY
wait "$BPID" || true
