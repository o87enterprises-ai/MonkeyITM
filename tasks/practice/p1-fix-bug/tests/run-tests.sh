#!/usr/bin/env bash
# Grader. Copied into the container only after the agent has stopped.
set -e
cd /workspace
PYTHONPATH=/workspace python3 -m unittest discover -s /tests -v
