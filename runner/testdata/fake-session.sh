#!/usr/bin/env bash
# Stand-in for scripts/run-session.sh in runner tests: a fake broker on SESSION_SOCKET, then READY.
# FAKE_SESSION_FAIL=1 makes it fail to start.
[ "${FAKE_SESSION_FAIL:-0}" = 1 ] && { echo "the broker did not start: fake failure" >&2; exit 1; }
exec python3 "$(dirname "$0")/fake-session-broker.py" target/debug/broker
