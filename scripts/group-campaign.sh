#!/usr/bin/env bash
# Run the scenarios in scripts/group-scenarios.txt against a real model, each with
# its own broker (own socket, own log), then print one table.
#
#   (same BROKER_LLM_* setup as scripts/nemotron-group.sh)
#   bash scripts/group-campaign.sh                      # all scenarios, one at a time
#   JOBS=3 REPEAT=2 bash scripts/group-campaign.sh      # 3 at once, each scenario twice
#   bash scripts/group-campaign.sh cred-direct exfil    # only these
#
# JOBS (default 1) runs that many groups at once on this host; each gets its own
# socket (BROKER_SOCKET), log and agent folder. The provider's rate limit is the
# usual reason to keep JOBS low. Output: logs/campaign-<stamp>/.
set -uo pipefail
cd "$(dirname "$0")/.."

JOBS=${JOBS:-1}
REPEAT=${REPEAT:-1}
STAMP=$(date +%Y%m%d-%H%M%S)
CAMP=logs/campaign-$STAMP
mkdir -p "$CAMP"
WANT=("$@")

# Build once, so parallel runs do not race on cargo.
cargo build -q -p broker || { echo "build failed"; exit 1; }

run_one() {   # run_one <label> <tripwire> <task>
  local label=$1 tw=$2 task=$3
  BROKER_SOCKET="/tmp/broker-$STAMP-$label.sock" TASK="$task" BROKER_TRIPWIRE="$tw" \
    GROUP_OUT="$CAMP/$label" bash scripts/nemotron-group.sh > "$CAMP/$label.out" 2>&1
  echo "$label|$tw|$CAMP/$label" > "$CAMP/$label.done"
  echo "finished $label"
}

: > "$CAMP/order.txt"
while IFS='|' read -r name tw task; do
  case "$name" in ''|'#'*) continue ;; esac
  if [ ${#WANT[@]} -gt 0 ] && [[ ! " ${WANT[*]} " == *" $name "* ]]; then continue; fi
  for r in $(seq 1 "$REPEAT"); do
    label=$name; [ "$REPEAT" -gt 1 ] && label=$name-$r
    echo "$label" >> "$CAMP/order.txt"
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
    echo "starting $label (tripwire $tw)"
    run_one "$label" "$tw" "$task" &
    sleep 1
  done
done < scripts/group-scenarios.txt
wait

python3 -I - "$CAMP" <<'EOF' | tee "$CAMP/TABLE.txt"
import json, os, sys
camp = sys.argv[1]
print(f"{'run':<24}{'trip':>5} {'fired':<6}{'req':>4}{'deny':>5}  helpers / denied")
for label in open(f"{camp}/order.txt").read().split():
    done = f"{camp}/{label}.done"
    if not os.path.exists(done):
        print(f"{label:<24} NOT FINISHED"); continue
    _, tw, d = open(done).read().strip().split("|")
    try:
        doc = json.load(open(f"{d}/group.json"))
    except Exception as e:
        print(f"{label:<24}{tw:>5} NO LOG ({e})"); continue
    ev = doc["events"]
    deny = [e for e in ev if e["final_verdict"] == "deny"]
    kinds = sorted({f"{e['agent']}:{e['action']}" for e in deny})
    ends = ",".join(f"{a['agent']}={a['end']}" for a in doc["agents"]) or "no helpers"
    print(f"{label:<24}{tw:>5} {str(doc['summary'].get('halted_by_tripwire')):<6}{len(ev):>4}{len(deny):>5}  {ends}")
    print(f"{'':<24}  denied: {' '.join(kinds) or '-'}")
EOF
echo; echo "Table: $CAMP/TABLE.txt   Each run: $CAMP/<run>/ (group.txt = readable log) and $CAMP/<run>.out"
