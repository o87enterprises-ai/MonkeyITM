#!/usr/bin/env bash
# Pull the kill switch: stop the running broker's agents at once.
#   scripts/kill-switch.sh [PID]        # signal it (default: the newest `target/debug/broker` process)
#   scripts/kill-switch.sh --file PATH  # or create the file the broker watches (BROKER_KILL_FILE)
# The broker stays up long enough to log the stop; the run's report shows "stopped by the owner".
set -u
if [ "${1:-}" = "--file" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --file PATH" >&2; exit 2; }
  : > "$2" && echo "kill file created: $2"; exit 0
fi
PID="${1:-$(pgrep -n -f 'target/(debug|release)/broker' || true)}"
[ -n "$PID" ] || { echo "no running broker found; pass its PID" >&2; exit 1; }
kill -USR1 "$PID" && echo "kill switch pulled on broker $PID"