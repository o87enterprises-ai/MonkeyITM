#!/usr/bin/env python3
"""Total up exported broker logs (logs/run-*.json) into a table.

    python3 scripts/summarize-logs.py logs/            # every run-*.json in the folder
    python3 scripts/summarize-logs.py logs/run-A.json logs/run-B.json

Counts, per action, how the broker decided each request, and flags any request
other than `llm_chat` that was allowed. Use it to replace hand-tallied numbers
before a write-up is shared. It reads the files only; nothing is changed.
"""
import glob
import json
import os
import sys
from collections import Counter, defaultdict


def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "run-*.json")))
        else:
            files.append(p)
    return files


def main(argv):
    files = collect(argv or ["logs"])
    if not files:
        print("no run-*.json files found", file=sys.stderr)
        return 2

    total = defaultdict(Counter)  # action -> verdict -> count
    human = Counter()
    flagged = []
    print("| run | intents | model calls | other requests | allowed (not llm_chat) | denied |")
    print("|---|---|---|---|---|---|")
    for f in files:
        try:
            doc = json.load(open(f, encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"skipping {f}: {e}", file=sys.stderr)
            continue
        events = doc.get("events", [])
        n_llm = n_other = n_allow = n_deny = 0
        for e in events:
            action = e.get("action", "?")
            verdict = e.get("final_verdict") or "none"
            total[action][verdict] += 1
            if action == "llm_chat":
                n_llm += 1
                continue
            n_other += 1
            if verdict == "allow":
                n_allow += 1
                flagged.append((os.path.basename(f), e.get("seq"), action, e.get("params")))
            else:
                n_deny += 1
        for k, v in doc.get("summary", {}).get("human_escalations", {}).items():
            human[k] += v
        name = os.path.basename(f).replace("run-", "").replace(".json", "")
        print(f"| {name} | {len(events)} | {n_llm} | {n_other} | {n_allow} | {n_deny} |")

    print()
    print("| action | allow | deny | approve_required | none |")
    print("|---|---|---|---|---|")
    other_allowed = other_total = 0
    for action in sorted(total):
        c = total[action]
        print(f"| {action} | {c['allow']} | {c['deny']} | {c['approve_required']} | {c['none']} |")
        if action != "llm_chat":
            other_total += sum(c.values())
            other_allowed += c["allow"]
    print()
    print(f"Requests other than llm_chat: {other_total}; allowed: {other_allowed}")
    print(f"Human escalations: {dict(human)}")
    if flagged:
        print("\nALLOWED requests to review:")
        for name, seq, action, params in flagged:
            print(f"  {name} seq {seq}: {action} {json.dumps(params)[:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
