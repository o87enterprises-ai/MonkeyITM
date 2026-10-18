#!/usr/bin/env python3
"""Black-box probes of the live API, with no credentials: the outside view an attacker starts from.

    python3 scripts/live-api-probe.py [https://monkeyitm-vm.o87enterprises.workers.dev]

Low volume (about 30 requests), read-only, no accounts: run it only against a deployment you own or are authorized to
test. It checks that everything protected refuses without the right credential, that refusals look the same, and that
bad input is refused cleanly (never a 500).
"""
import json
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://monkeyitm-vm.o87enterprises.workers.dev").rstrip("/")
UA = "monkeyitm-live-probe/1"
results = []


def call(method, path, key=None, body=None, raw=None, headers=None):
    h = {"User-Agent": UA, **(headers or {})}
    data = None
    if key:
        h["Authorization"] = f"Bearer {key}"
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if raw is not None:
        data = raw
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{str(detail)[:160]}]" if not ok else ""))


print(f"Live API probes against {BASE}")
check("health is public", call("GET", "/v1/healthz")[0] == 200)
for path in ("/v1/jobs", "/v1/keys", "/v1/usage", "/v1/audit", "/v1/sessions", "/v1/bundles", "/v1/model-keys"):
    s, _ = call("GET", path)
    check(f"GET {path} without a key is refused (401)", s == 401, s)
s1, t1 = call("GET", "/v1/jobs", key="mitm_live_" + "0" * 32)
s2, t2 = call("GET", "/v1/jobs", key="nonsense")
check("a well-formed unknown key and a malformed key get the same refusal", s1 == s2 == 401 and t1 == t2, (s1, s2))
check("POST /v1/jobs without a key is refused", call("POST", "/v1/jobs", body={"name": "x"})[0] == 401)
check("POST /v1/kill (org-wide stop) without a key is refused", call("POST", "/v1/kill")[0] == 401)
for path in ("/admin/runners", "/admin/orgs", "/admin/usage"):
    s, _ = call("GET", path)
    check(f"{path} without the admin token is refused", s in (401, 403, 404), s)
check("an admin path with a guessed token is refused", call("GET", "/admin/runners", key="admin")[0] in (401, 403, 404))
for path in ("/runner/v1/lease", "/runner/v1/heartbeat"):
    s, _ = call("POST", path, body={})
    check(f"{path} without a runner token is refused", s in (401, 403), s)
check("a runner path with an API-key-shaped token is refused", call("POST", "/runner/v1/lease", key="mitm_live_" + "0" * 32, body={})[0] in (401, 403))
sid = "ses_0123456789abcdef"
check("a session intent without a token is refused", call("POST", f"/v1/sessions/{sid}/intent", body={"action": "read_file"})[0] == 401)
check("a session intent with a guessed token is refused", call("POST", f"/v1/sessions/{sid}/intent", key="mts_" + "0" * 32, body={})[0] == 401)
check("an MCP call without a token is refused", call("POST", f"/v1/sessions/{sid}/mcp", body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[0] == 401)
check("a session path with a bad id is refused, not a 500", call("POST", "/v1/sessions/../../admin/intent", body={})[0] in (400, 401, 404))
check("a cross-origin key request from the site is refused", call("POST", "/api/keys", body={}, headers={"Origin": "https://evil.example"})[0] in (401, 403))
check("a cross-origin tester signature is refused", call("POST", "/api/tester-accept", body={"accept": True}, headers={"Origin": "https://evil.example"})[0] in (401, 403))
check("a malformed cookie is not a 500", call("GET", "/account", headers={"Cookie": "mitm_s=%"})[0] < 500)
check("a garbage session cookie is not signed in", call("GET", "/api/me", headers={"Cookie": "mitm_s=" + "a" * 64})[0] == 401)
check("a body that is not JSON is refused cleanly", call("POST", "/api/request-access", raw=b"{not json", headers={"Origin": BASE})[0] in (400, 415))
s, _ = call("POST", "/api/request-access", raw=b"x" * (5 * 1024 * 1024), headers={"Origin": BASE})
check("a 5 MiB body is refused, not a 500", s in (400, 413), s)
check("an unknown API path is a clean 404 or 401", call("GET", "/v1/nope")[0] in (401, 404))
check("the challenge page is still off", call("GET", "/challenge")[0] == 404)
s, body = call("GET", "/v1/jobs")
check("refusals do not leak stack traces", "at " not in body and "Error:" not in body and "worker" not in body.lower(), body[:120])
print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
sys.exit(0 if all(results) else 1)
