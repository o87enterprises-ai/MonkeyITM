"""Stand-in for scripts/eval-job.py in runner tests. The mode comes from BROKER_LLM_MODEL:
mode-ok (finishes in a moment), mode-wait (runs until its broker is told to stop),
mode-stubborn (its broker ignores the kill switch, and so does it), mode-noreport."""
import json, os, signal, subprocess, sys, time

a = sys.argv[1:]
arg = lambda name: a[a.index(name) + 1] if name in a else None
out, task = arg("--out"), arg("--only")
mode = os.environ.get("BROKER_LLM_MODEL", "mode-ok")
listing = {}
tdir = arg("--tasks") or ""
if tdir.endswith("bundle-tasks"):
    for dp, _, fns in os.walk(tdir):
        for fn in fns:
            full = os.path.join(dp, fn)
            listing[os.path.relpath(full, tdir).replace(os.sep, "/")] = open(full, encoding="utf-8").read()
json.dump({"argv": a, "env_keys": sorted(os.environ), "key": os.environ.get("BROKER_LLM_KEY"), "tasks_listing": listing}, open(os.path.join(out, "fake-seen.json"), "w"))

if mode == "mode-stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
broker = None
if mode in ("mode-wait", "mode-stubborn", "mode-lost"):
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, FAKE_IGNORE_KILL="1" if mode == "mode-stubborn" else "0")
    broker = subprocess.Popen([sys.executable, os.path.join(here, "fake-broker.py"), "target/debug/broker"], env=env)
    t0 = time.time()
    while time.time() - t0 < 60 and (broker.poll() is None):
        time.sleep(0.1)
elif mode == "mode-noreport":
    sys.exit(3)
else:
    time.sleep(1.2)

killed = os.path.exists("fake-broker-killed")
bundle = os.path.join("runs", task + "-fake")
os.makedirs(bundle, exist_ok=True)
big = os.environ.get("FAKE_BIG") == "1"
open(os.path.join(bundle, "log.json"), "w").write(json.dumps({"summary": {"chain": {"algorithm": "sha256", "rows": 9, "head": "ab" * 32}}, "events": [{"seq": i, "result": "x" * (5000 if big else 1)} for i in range(400 if big else 2)]}))
open(os.path.join(bundle, "agent.txt"), "w").write("transcript with the key " + (os.environ.get("BROKER_LLM_KEY") or "") + " in it\n")
os.makedirs(os.path.join(out, task), exist_ok=True)
score = {"result": {"overall": "pass", "completed": not killed}, "halt": {"halted": killed, "cause": "stopped by the owner (kill switch)" if killed else None}}
json.dump(score, open(os.path.join(out, task, "alignment-score.json"), "w"))
open(os.path.join(out, "job-report.md"), "w").write("# report\n")
json.dump({"tasks": [{"task": task, "result": "pass", "completed": not killed, "attempts_beyond_scope": 0,
                      "critical_attempts": 0, "halted": killed, "run_bundle": bundle, "flagged_injection": False}]}, open(os.path.join(out, "job-report.json"), "w"))