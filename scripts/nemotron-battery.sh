#!/usr/bin/env bash
# Run the 20-task battery (scripts/battery.py) against a real model, with one
# broker for the whole batch so there is one combined log.
#
#   read -rs BROKER_LLM_KEY; export BROKER_LLM_KEY      # type the key; it is not echoed
#   export BROKER_LLM_URL=https://integrate.api.nvidia.com/v1/chat/completions
#   export BROKER_LLM_MODEL=nvidia/nemotron-3-super-120b-a12b
#   export BROKER_LLM_MAX_TOKENS=4096
#   bash scripts/nemotron-battery.sh            # all 20 tasks
#   bash scripts/nemotron-battery.sh 4 5 6      # only these task numbers
#
# Each task checks one rule (see `python3 scripts/battery.py list`); none asks
# the model to find a way around a rule. Scoring uses only the broker's log.
# The model API key stays in the broker's environment and is never sent to the
# agent. Output goes to logs/battery-<stamp>/.
set -uo pipefail
cd "$(dirname "$0")/.."

STEPS=${STEPS:-8}
RUN_TIMEOUT=${RUN_TIMEOUT:-900}
STAMP=$(date +%Y%m%d-%H%M%S)
OUT=logs/battery-$STAMP
SOCK=/tmp/broker.sock
BROKER=target/debug/broker
N=$(python3 -I scripts/battery.py list | wc -l)

command -v bwrap >/dev/null || { echo "need bubblewrap: sudo apt install bubblewrap"; exit 1; }
[ -n "${BROKER_LLM_URL:-}" ] && [ -n "${BROKER_LLM_MODEL:-}" ] \
  || { echo "set BROKER_LLM_URL and BROKER_LLM_MODEL (and BROKER_LLM_KEY for a hosted model)"; exit 1; }
if [ -S "$SOCK" ]; then
  echo "A broker is already running ($SOCK exists). Stop it, then run this again."
  exit 1
fi
cargo build -q -p broker || { echo "build failed"; exit 1; }
mkdir -p "$OUT"

TASKS=("$@")
[ ${#TASKS[@]} -eq 0 ] && mapfile -t TASKS < <(seq 1 "$N")
echo "model: $BROKER_LLM_MODEL   tasks: ${TASKS[*]}   steps per task: $STEPS"

BATCH_START=$(date +%s)
env BROKER_UNATTENDED=1 "$BROKER" > "$OUT/broker.log" 2>&1 &
BROKER_PID=$!
trap 'kill "$BROKER_PID" 2>/dev/null; wait "$BROKER_PID" 2>/dev/null; rm -f "$SOCK"' EXIT
for _ in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 0.5; done
[ -S "$SOCK" ] || { echo "broker did not start; see $OUT/broker.log"; exit 1; }

JOB=bat-$STAMP
printf 'https://example.com/\n' > "$OUT/urls.txt"
"$BROKER" stage --job "$JOB" --urls "$OUT/urls.txt" --yes || { echo "staging failed"; exit 1; }

: > "$OUT/scores.txt"
for t in "${TASKS[@]}"; do
  prompt=$(python3 -I scripts/battery.py task "$t" | sed "s/{job}/$JOB/g")
  echo
  echo "=== task $t of $N ==="
  sleep 2
  AGENT_TRANSCRIPT="$OUT/task-$t-agent.txt" \
    timeout -k 10 "$RUN_TIMEOUT" bash scripts/run-agent.sh --max-steps "$STEPS" --task "$prompt"
  latest=$(ls -t logs/run-*.json 2>/dev/null | head -1)
  if [ -z "$latest" ]; then echo "$t NO-LOG" | tee -a "$OUT/scores.txt"; continue; fi
  cp "$latest" "${latest%.json}.txt" "$OUT/"
  python3 -I scripts/battery.py check "$t" "$OUT/$(basename "$latest")" | tee -a "$OUT/scores.txt"
done

"$BROKER" export --since "$BATCH_START" --format json --out "$OUT/combined.json"
"$BROKER" export --since "$BATCH_START" --format text --out "$OUT/combined.txt"
python3 scripts/summarize-logs.py "$OUT" > "$OUT/SUMMARY.md"

echo
echo "=== scores ==="
grep -E "^ *[0-9]+ " "$OUT/scores.txt"
echo
for s in PASS FAIL "NOT ATTEMPTED" UNEXPECTED; do
  printf '%-14s %s\n' "$s" "$(grep -cE "^ *[0-9]+ .* $s\$" "$OUT/scores.txt")"
done
echo
tail -12 "$OUT/SUMMARY.md"
echo
echo "Combined log: $OUT/combined.txt   Everything: $OUT/"
