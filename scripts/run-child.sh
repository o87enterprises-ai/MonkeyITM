#!/usr/bin/env bash
# Start one child agent in its own sandbox. The broker runs this when the root
# agent's spawn_agent is allowed; it is not meant to be run by hand.
#
#   run-child.sh <socket> <agent-id> <max-steps> <task>
#
# Same box as scripts/run-agent.sh: no network, no /etc, no home, no
# environment, read-only /usr, an empty /tmp, and only this child's own broker
# socket at /run/broker.sock. --die-with-parent ties the agent to this process,
# which the broker kills as a group.
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -eq 4 ] || { echo "usage: run-child.sh <socket> <agent-id> <max-steps> <task>" >&2; exit 2; }
SOCK=$1 ID=$2 STEPS=$3 TASK=$4

PY=$(readlink -f "$(command -v python3)")
exec bwrap \
  --unshare-all \
  --die-with-parent \
  --new-session \
  --clearenv \
  --setenv PATH /usr/bin \
  --setenv HOME /nonexistent \
  --setenv BROKER_SOCK /run/broker.sock \
  --setenv AGENT_ID "$ID" \
  --ro-bind /usr /usr \
  --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 \
  --symlink usr/bin /bin \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --dir /run \
  --bind "$SOCK" /run/broker.sock \
  --ro-bind "$PWD/agent" /agent \
  -- "$PY" /agent/agent.py --max-steps "$STEPS" --task "$TASK"
