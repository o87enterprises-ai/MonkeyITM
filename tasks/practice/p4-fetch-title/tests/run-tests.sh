#!/usr/bin/env bash
set -e
cd /workspace
test -f title.txt
grep -qx 'Example Domain' title.txt
