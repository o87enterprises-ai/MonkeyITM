#!/usr/bin/env python3
"""Tests of how the agent reads a model's reply (agent/agent.py), with scripted models.

    cargo build -p broker
    python3 scripts/agent-format-test.py

A model that writes its tool call in <tool_call> notation instead of JSON used to end the run
as if it had answered (a real model did this in a group task). Now such a reply is re-prompted
for the JSON format, a few times at most; a reply that is really an answer still ends the run.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER = os.path.join(ROOT, "target", "debug", "broker")
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:300]}]" if detail and not ok else ""))


def run_agent(tmp, script, port, task="Read /tmp/safe/report.txt and tell me what it says."):
    sock = os.path.join(tmp, f"{script}.sock")
    policy = os.path.join(tmp, "policy.yaml")
    open(policy, "w").write('''rules:
  - name: think
    action: llm_chat
    verdict: allow
  - name: safe
    action: read_file
    match: { path_prefix: "/tmp/safe/" }
    verdict: allow
  - name: default-deny
    action: any
    verdict: deny
''')
    mock = subprocess.Popen([sys.executable, os.path.join(ROOT, "scripts", "mock-llm.py")],
                            env=dict(os.environ, MOCK_SCRIPT=script, MOCK_PORT=str(port)),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ, BROKER_SOCKET=sock, BROKER_POLICY=policy, BROKER_LOG=os.path.join(tmp, f"{script}.db"),
               BROKER_UNATTENDED="1", BROKER_LLM_URL=f"http://127.0.0.1:{port}/v1/chat/completions")
    broker = subprocess.Popen([BROKER], cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        time.sleep(1)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "agent", "agent.py"), "--task", task, "--max-steps", "8"],
                             env=dict(os.environ, BROKER_SOCK=sock, NO_COLOR="1"), capture_output=True, text=True, timeout=60)
        return re.sub(r"\x1b\[[0-9;]*m", "", out.stdout + out.stderr)
    finally:
        broker.send_signal(signal.SIGINT)
        broker.wait(timeout=10)
        mock.terminate()


def main():
    os.makedirs("/tmp/safe", exist_ok=True)
    open("/tmp/safe/report.txt", "w").write("Q3 revenue up 12%.\n")
    tmp = tempfile.mkdtemp(prefix="agentfmt-")

    print("\nA call in <tool_call> notation")
    out = run_agent(tmp, "markup", 8197)
    check("the first reply is re-prompted instead of taken as the answer", "(no JSON)" in out and "<tool_call>" in out, out)
    check("then the agent makes the real call", "model wants read_file" in out, out)
    check("and finishes with the model's own final answer", "final answer: Revenue is up 12%" in out and "(plain text)" not in out, out)

    print("\nA plain answer")
    out = run_agent(tmp, "plain", 8196)
    check("a reply that is just words still ends the run as the final answer", "final answer (plain text): The report says revenue" in out, out)
    check("it is not re-prompted", "(no JSON)" not in out, out)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
