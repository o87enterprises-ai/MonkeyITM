#!/usr/bin/env bash
# A stand-in "helper" launcher for scripts/group-attack-test.py: it does nothing and
# stays alive, so the test can connect to the helper's socket itself and act as a
# compromised helper. Arguments (socket, id, steps, task) are ignored.
# The process is named after its socket, so a test can find exactly its own helpers.
exec -a "idle-child $1" sleep 120
