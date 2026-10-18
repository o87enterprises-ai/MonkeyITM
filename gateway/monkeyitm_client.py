"""A small client for a team's own agent to talk to its MonkeyITM broker (docs/EVALUATION_PLATFORM.md).

Standard library only; copy this one file into your agent. Every action your agent wants goes
through the broker as a request; the broker decides, runs it (or refuses it) and logs it.

    from monkeyitm_client import Broker

    b = Broker("https://<your-target-url>", "<your-token>")
    r = b.read_file("/workspace/notes.txt")
    if r["verdict"] == "allow":
        print(r["result"]["content"])
    else:
        print("refused:", r["reason"])

    b.exec(["python3", "-m", "pytest", "-x"], cwd="/workspace")
    b.write_file("/workspace/out.txt", "done\\n")
    b.http_get("https://example.com/")      # only sites on your task's list
    b.finish()                              # tell the broker you are done; it grades the run

Verdicts come back as the broker's own JSON: {"verdict": "allow" | "deny", "result": ..., "reason": ...}.
A refusal is a normal answer, not an error. Network and protocol problems raise `BrokerError`.
"""

import json
import urllib.error
import urllib.request
import uuid


class BrokerError(Exception):
    pass


class Broker:
    def __init__(self, url, token, timeout=140):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", "")
            except ValueError:
                msg = ""
            raise BrokerError(f"{e.code} {msg}".strip()) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise BrokerError(str(e)) from None

    def ask(self, action, params=None, why=""):
        """Send one request; returns the broker's verdict (a dict)."""
        return self._call("POST", "/v1/intent", {"id": str(uuid.uuid4()), "action": action,
                                                 "params": params or {}, "justification": why})

    def read_file(self, path, why=""):
        return self.ask("read_file", {"path": path}, why)

    def write_file(self, path, content, mode="overwrite", why=""):
        return self.ask("write_file", {"path": path, "content": content, "mode": mode}, why)

    def exec(self, argv, cwd="/workspace", timeout_s=120, why=""):
        return self.ask("exec", {"argv": list(argv), "cwd": cwd, "timeout_s": timeout_s}, why)

    def http_get(self, url, why=""):
        return self.ask("http_get", {"url": url}, why)

    def status(self):
        return self._call("GET", "/v1/status")

    def finish(self):
        return self._call("POST", "/v1/finish", {})
