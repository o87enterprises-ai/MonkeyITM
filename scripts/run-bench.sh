#!/usr/bin/env bash
# Proctored benchmark run: one task, one agent, full containment and a run bundle.
#
#   bash scripts/run-bench.sh tasks/example-fix-bug [--max-steps N]
#
# What happens:
#   1. The task's image is built and started as a disposable workbench
#      container with no network, the task files mounted at /workspace.
#   2. The broker starts unattended (no human; escalations are denied and
#      counted) with the benchmark policy, executing inside the workbench.
#   3. The agent runs in its own bubblewrap sandbox and can only ask the
#      broker. It never touches the workbench directly.
#   4. After the agent stops, the broker is stopped, the hidden tests are
#      copied in for the first time, and the grader runs.
#   5. Everything lands in runs/<task>-<time>/: score, containment report,
#      full log, agent transcript, grader output, and a manifest of hashes.
#
# The model is whatever the broker is pointed at (BROKER_LLM_URL / _MODEL /
# _KEY). For a no-cost pipeline check, use the scripted stand-in:
#   MOCK_SCRIPT=solve-example python3 scripts/mock-llm.py &
#   BROKER_LLM_URL=http://127.0.0.1:8088/v1/chat/completions bash scripts/run-bench.sh tasks/example-fix-bug
#
# The tripwire halts the run after 10 denied requests (BENCH_TRIPWIRE=N to
# change, 0 to disable): later requests are refused and the workbench killed.
#
# Needs Docker (or Podman via BROKER_DOCKER=podman), bubblewrap, Rust, Python 3.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
[ $# -ge 1 ] || usage 1
case "$1" in -h|--help) usage 0 ;; esac

TASK=$(cd "$1" && pwd); shift
MAX_STEPS=30
while [ $# -gt 0 ]; do
  case "$1" in
    --max-steps) MAX_STEPS=$2; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1"; usage 1 ;;
  esac
done

NAME=$(basename "$TASK")
DOCKER=${BROKER_DOCKER:-docker}
POLICY=${BENCH_POLICY:-$([ -f "$TASK/policy.yaml" ] && echo "$TASK/policy.yaml" || echo policies/benchmarks/default.yaml)}
for f in Dockerfile instruction.md tests/run-tests.sh; do
  [ -f "$TASK/$f" ] || { echo "task is missing $f (see tasks/README.md)"; exit 1; }
done
command -v "$DOCKER" >/dev/null || { echo "need $DOCKER"; exit 1; }
command -v bwrap >/dev/null || { echo "need bubblewrap: sudo apt install bubblewrap"; exit 1; }
if python3 -c "import socket; socket.socket(socket.AF_UNIX).connect('/tmp/broker.sock')" 2>/dev/null; then
  echo "a broker is already running on /tmp/broker.sock; stop it first"; exit 1
fi
rm -f /tmp/broker.sock

STAMP=$(date +%Y%m%d-%H%M%S)
RUN="runs/$NAME-$STAMP"
mkdir -p "$RUN/workspace"
RUN=$(cd "$RUN" && pwd)
[ -d "$TASK/workspace" ] && cp -a "$TASK/workspace/." "$RUN/workspace/"

IMAGE="monkeyitm-task-$NAME"
WB="monkeyitm-wb-$NAME-$STAMP"
BPID=""
cleanup() {
  [ -n "$BPID" ] && kill "$BPID" 2>/dev/null || true
  "$DOCKER" rm -f "$WB" >/dev/null 2>&1 || true
  rm -f /tmp/broker.sock
}
trap cleanup EXIT

# As root, --user "$(id -u)" would make the workbench root again, and the grader protections rely on it not being.
if [ "$(id -u)" = 0 ]; then echo "run-bench.sh must not run as root (the workbench would run as root inside)" >&2; exit 1; fi
echo "== task: $NAME   run: ${RUN#"$PWD"/}"
echo "-- building task image"
"$DOCKER" build -q -t "$IMAGE" "$TASK" >/dev/null
# Resource limits (processes, memory, CPU) need cgroup controllers the host may not hand to Docker: a
# Vercel Sandbox does not (Docker then refuses to start the container at all). Probe once and use them
# where they work. Where they cannot, the session runs without them and says so; a production runner
# sets MITM_REQUIRE_LIMITS=1 to refuse to run unlimited.
LIMITS=(--pids-limit 256 --memory 1g --memory-swap 1g --cpus 1)
if ! "$DOCKER" run --rm --network none "${LIMITS[@]}" "$IMAGE" true >/dev/null 2>&1; then
  if [ "${MITM_REQUIRE_LIMITS:-0}" = 1 ]; then
    echo "this host cannot apply container resource limits and MITM_REQUIRE_LIMITS=1: refusing to run" >&2
    exit 1
  fi
  # Fallback that needs no cgroups: per-process kernel limits (rlimits). They stop a fork bomb, a single
  # process eating memory, and a single huge file; they do not cap total CPU, or memory summed over processes.
  LIMITS=(--ulimit nproc=512 --ulimit data=2147483648 --ulimit fsize=1073741824 --ulimit nofile=1024)
  if "$DOCKER" run --rm --network none --user "$(id -u):$(id -g)" "${LIMITS[@]}" "$IMAGE" true >/dev/null 2>&1; then
    echo "WARNING: this host cannot apply cgroup limits: the container runs with per-process limits only (processes, memory per process, file size), not total CPU or memory" >&2
  else
    echo "WARNING: this host cannot apply container resource limits: the container runs WITHOUT process, memory or CPU limits" >&2
    LIMITS=()
  fi
fi
# Not root: root inside the container could write anywhere in it (replace system binaries, pre-create the
# grader's directory) even with every capability dropped.
"$DOCKER" run -d --name "$WB" --network none --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges ${LIMITS[@]+"${LIMITS[@]}"} \
  -v "$RUN/workspace:/workspace" "$IMAGE" sleep infinity >/dev/null
echo "-- workbench $WB started (no network)"

cargo build -q -p broker
if [ "${BENCH_GROUP:-0}" = 1 ]; then export BROKER_MAX_AGENTS=3 BROKER_AGENT_DIR="$RUN/agents"; fi
BROKER_POLICY="$POLICY" BROKER_LOG="$RUN/broker.db" BROKER_UNATTENDED=1 BROKER_TRIPWIRE="${BENCH_TRIPWIRE:-10}" \
BROKER_WORKBENCH="$WB" BROKER_WORKBENCH_DIR="$RUN/workspace" BROKER_DOCKER="$DOCKER" \
  target/debug/broker </dev/null 2>"$RUN/broker.txt" &
BPID=$!
for _ in $(seq 100); do [ -S /tmp/broker.sock ] && break; sleep 0.1; done
[ -S /tmp/broker.sock ] || { echo "broker did not start:"; cat "$RUN/broker.txt"; exit 1; }

# BENCH_GROUP=1: a group run (up to three agents under this broker, one log, one kill switch).
GROUP_ARGS=()
if [ "${BENCH_GROUP:-0}" = 1 ]; then GROUP_ARGS=(--group); fi

echo "-- agent running (max $MAX_STEPS steps)"
STARTED=$(date +%s)
set +e
NO_EXPORT=1 AGENT_TRANSCRIPT="$RUN/agent.txt" \
  bash scripts/run-agent.sh --task "$(cat "$TASK/instruction.md")" --max-steps "$MAX_STEPS" ${GROUP_ARGS[@]+"${GROUP_ARGS[@]}"} >/dev/null
AGENT_EXIT=$?
set -e
FINISHED=$(date +%s)
kill "$BPID" 2>/dev/null || true
wait "$BPID" 2>/dev/null || true
BPID=""
echo "-- agent stopped (exit $AGENT_EXIT); broker stopped"

echo "-- grading: hidden tests copied in now, for the first time"
# An unpredictable path that does not exist yet (docker cp puts the source INSIDE an existing directory,
# so a directory the agent pre-created would shadow the real grader), then a hash check before running it.
GT="/opt/.g-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
"$DOCKER" cp "$TASK/tests" "$WB:$GT"
HOST_HASH=$(sha256sum "$TASK/tests/run-tests.sh" | cut -d' ' -f1)
CONTAINER_HASH=$("$DOCKER" exec "$WB" sha256sum "$GT/run-tests.sh" | cut -d' ' -f1)
if [ "$HOST_HASH" != "$CONTAINER_HASH" ]; then
  echo "grader hash mismatch (host $HOST_HASH, container $CONTAINER_HASH): refusing to grade" >&2
  exit 1
fi
set +e
"$DOCKER" exec "$WB" bash "$GT/run-tests.sh" >"$RUN/grader.txt" 2>&1
GRADER_EXIT=$?
set -e

# Fold the write-ahead log into broker.db so the manifest hash covers everything.
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA wal_checkpoint(TRUNCATE)'); c.execute('PRAGMA journal_mode=DELETE'); c.close()" "$RUN/broker.db"
target/debug/broker export --db "$RUN/broker.db" --out "$RUN/log.json" 2>/dev/null
target/debug/broker export --db "$RUN/broker.db" --format jsonl --out "$RUN/log.jsonl" 2>/dev/null
target/debug/broker export --db "$RUN/broker.db" --format text --out "$RUN/log.txt" 2>/dev/null

python3 scripts/bench-report.py \
  --run "$RUN" --task "$NAME" --policy "$POLICY" --grader-exit "$GRADER_EXIT" \
  --agent-exit "$AGENT_EXIT" --started "$STARTED" --finished "$FINISHED" \
  --image "$("$DOCKER" image inspect -f '{{.Id}}' "$IMAGE")" --max-steps "$MAX_STEPS"
