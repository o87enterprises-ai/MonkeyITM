#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"

mkdir -p /tmp/safe
echo "hello from the safe zone" > /tmp/safe/test.txt
rm -f /tmp/safe/escape_link
ln -s /etc/passwd /tmp/safe/escape_link

"$CARGO" build -p broker --quiet

rm -f /tmp/broker.sock /tmp/broker.out
START=$(date +%s)
echo n | "$CARGO" run -p broker --quiet > /tmp/broker.out 2>&1 &
BPID=$!

for i in $(seq 1 40); do
  [ -S /tmp/broker.sock ] && break
  sleep 0.1
done

if [ ! -S /tmp/broker.sock ]; then
  echo "broker socket never appeared"
  cat /tmp/broker.out || true
  kill "$BPID" 2>/dev/null || true
  exit 1
fi

send() {
  printf '%s\n' "$1" | python3 scripts/test-broker.py
}

echo "--- 1. read /tmp/safe/test.txt  (expect: allow) ---"
send '{"id":"t1","action":"read_file","params":{"path":"/tmp/safe/test.txt"},"justification":"smoke"}'

echo "--- 2. read /etc/passwd         (expect: approve_required) ---"
send '{"id":"t2","action":"read_file","params":{"path":"/etc/passwd"},"justification":"smoke"}'

echo "--- 3. read ~/.aws/credentials  (expect: deny, no rule matched) ---"
send '{"id":"t3","action":"read_file","params":{"path":"/home/someone/.aws/credentials"},"justification":"smoke"}'

echo "--- 4. exec ls                  (expect: deny, explicit) ---"
send '{"id":"t4","action":"exec","params":{"cmd":"ls"},"justification":"smoke"}'

echo "--- 5. ../ traversal          (expect: deny) ---"
send '{"id":"t5","action":"read_file","params":{"path":"/tmp/safe/../../etc/shadow"},"justification":"smoke"}'

echo "--- 6. symlink to /etc/passwd   (expect: deny, executor refused) ---"
send '{"id":"t6","action":"read_file","params":{"path":"/tmp/safe/escape_link"},"justification":"smoke"}'

echo "--- 7. malformed json           (expect: deny, unparseable) ---"
send '{"this": "is not an intent"}'

kill "$BPID" 2>/dev/null || true
wait "$BPID" 2>/dev/null || true

echo
echo "=== broker stderr ==="
cat /tmp/broker.out

STAMP=$(date +%Y%m%d-%H%M%S)
"$CARGO" run -q -p broker -- export --since "$START" --format json --out "logs/smoke-$STAMP.json"
"$CARGO" run -q -p broker -- export --since "$START" --format text --out "logs/smoke-$STAMP.txt"
