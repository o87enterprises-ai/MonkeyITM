"""A fake broker for runner session tests. Its command line contains 'target/debug/broker' (so the
runner's kill-switch search finds it) and it speaks the intent protocol on SESSION_SOCKET: reads of
/workspace files are allowed (it really reads them), everything else is refused. SIGUSR1 is the kill
switch (everything refused afterwards); SIGTERM writes a "shutdown" record and exits. On the way out
it leaves fake-log.json in SESSION_DIR, which fake-broker-cli.py exports."""
import json, os, signal, socket, sqlite3, sys, threading, time

d, sock_path = os.environ["SESSION_DIR"], os.environ["SESSION_SOCKET"]
events, run_events, killed = [], [], {"v": False}
lock = threading.Lock()
json.dump({"env_keys": sorted(os.environ), "key": os.environ.get("BROKER_LLM_KEY"), "base": os.environ.get("SESSION_BASE"),
           "tripwire": os.environ.get("SESSION_TRIPWIRE"), "public_only": os.environ.get("BROKER_LLM_PUBLIC_ONLY"), "policy": os.environ.get("SESSION_POLICY")}, open(os.path.join(d, "fake-seen.json"), "w"))


_db = sqlite3.connect(os.path.join(d, "broker.db"), check_same_thread=False)
_db.execute("CREATE TABLE IF NOT EXISTS run_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, detail TEXT, at INTEGER)")
_db.commit()
tripped = {"v": False}


def trip():
    """The broker's tripwire: the request that causes it is answered like any refusal; the halt is only in the log."""
    tripped["v"] = True
    with lock:
        run_events.append({"kind": "tripwire", "detail": "critical attempt", "at": int(time.time())})
        _db.execute("INSERT INTO run_events (kind, detail, at) VALUES ('tripwire', 'critical attempt', ?)", (int(time.time()),))
        _db.commit()


def write_log():
    with lock:
        chain = {"algorithm": "sha256", "rows": 2 * len(events) + len(run_events), "head": "cd" * 32}
        json.dump({"summary": {"chain": chain, "intents": len(events), "killed_by_owner": killed["v"], "halted_by_tripwire": tripped["v"]},
                   "events": events, "run_events": run_events, "agents": []}, open(os.path.join(d, "fake-log.json"), "w"))


def on_usr1(*_):
    killed["v"] = True
    with lock:
        run_events.append({"kind": "kill_switch", "detail": "stopped by the owner (SIGUSR1); all further requests refused", "at": int(time.time())})
    write_log()


def on_term(*_):
    with lock:
        run_events.append({"kind": "shutdown", "detail": "{}", "at": int(time.time())})
    write_log()
    os._exit(0)


signal.signal(signal.SIGUSR1, on_usr1)
signal.signal(signal.SIGTERM, on_term)


def serve(conn):
    f = conn.makefile("rwb")
    line = f.readline()
    try:
        it = json.loads(line)
    except ValueError:
        conn.close()
        return
    action, params = it.get("action"), it.get("params") or {}
    if tripped["v"]:
        rep = {"id": it["id"], "verdict": "deny", "result": None, "reason": "run halted by tripwire: too many denied requests"}
    elif action == "exec" and (params.get("argv") or [""])[0] == "docker":
        trip()
        rep = {"id": it["id"], "verdict": "deny", "result": None, "reason": "container tools are outside the task"}
    elif killed["v"]:
        rep = {"id": it["id"], "verdict": "deny", "result": None, "reason": "run stopped by the owner (kill switch)"}
    elif action == "read_file" and str(params.get("path", "")).startswith("/workspace/"):
        p = os.path.join(d, "workspace", params["path"][len("/workspace/"):])
        try:
            rep = {"id": it["id"], "verdict": "allow", "result": {"content": open(p).read()}, "reason": "ok"}
        except OSError:
            rep = {"id": it["id"], "verdict": "allow", "result": {"error": "no such file"}, "reason": "ok"}
    else:
        rep = {"id": it["id"], "verdict": "deny", "result": None, "reason": "not allowed here"}
    with lock:
        events.append({"seq": len(events) + 1, "agent": "a1", "action": action, "params": params, "final_verdict": rep["verdict"],
                       "verdicts": [{"verdict": rep["verdict"], "reason": rep["reason"]}], "result": rep["result"]})
    write_log()
    f.write((json.dumps(rep) + "\n").encode())
    f.flush()
    conn.close()


if os.path.exists(sock_path):
    os.remove(sock_path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(16)
write_log()
print("READY", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
