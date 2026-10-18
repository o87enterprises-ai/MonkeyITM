#!/usr/bin/env bash
set -e
cd /workspace
PYTHONPATH=/workspace python3 -m unittest discover -s /workspace/tests -v
