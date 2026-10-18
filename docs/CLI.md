# The command line client and Python library

`cli/monkeyitm.py`: one file, standard library only (Python 3.9+), for everything the API does.
Copy it anywhere; the same file is a library (`from monkeyitm import Client`).

## First time

```
python3 cli/monkeyitm.py login
```

It asks for your API key with a hidden prompt, checks it against the API, and saves it to
`~/.monkeyitm/config.json` (mode 0600). On Windows use `python cli\monkeyitm.py ...`. To keep the key
out of the file, set `MITM_KEY` (and `MITM_API`) in the environment instead; they win over the file.
`logout` deletes the saved key.

Where to get a key: sign in on the site, then `POST /api/keys` (see `docs/RUNNER.md`); once you have
one key with `keys:admin`, `api-keys create` makes more.

## Everyday commands

| Task | Command |
|---|---|
| Store a model key once (pinned to its provider) | `model-keys add --label nvidia --url-prefix https://integrate.api.nvidia.com/` (asks for the key) |
| Run the practice suite and wait for the verdict | `jobs create --suite practice --model-url https://integrate.api.nvidia.com/v1/chat/completions --model-name z-ai/glm-5.3 --key-id mk_... --wait` |
| Run one task, or your own tasks | `--only p6-no-outside-filing`, or `--bundle tb_...` |
| Several runs of each task | `--repeat 3` |
| Watch, list, inspect | `jobs wait ID`, `jobs list`, `jobs show ID`, `jobs runs ID` |
| Read the report | `jobs report ID --md` |
| Read one run in detail | `jobs score ID RUN`, `jobs log ID RUN`, `jobs transcript ID RUN` |
| Signed incident export | `jobs incident ID` |
| **Kill switch for one job** | `jobs kill ID` |
| **Stop everything in your organization** | `kill-all` (lift it with `kill-all --clear`) |
| Upload your own tasks | `bundles upload bundle.json` (make it with `scripts/pack-bundle.py`) |
| Keys | `api-keys list`, `api-keys create --label ci`, `api-keys revoke ID` |
| Usage and audit trail | `usage`, `audit` |

`--json` (before the command) prints raw JSON for anything that lists. Without `--key-id`, `jobs create`
asks for the model key with a hidden prompt, or reads the variable named by `--key-env`.

## Secrets are never arguments

There is deliberately no `--key` option: a key typed on the command line sits in your shell history
and in the process list. Keys come only from a hidden prompt or an environment variable.

## Exit codes

`jobs create --wait`, `jobs wait` and `jobs report` exit **0** for pass or pass with concerns, **1**
for fail, **2** for incomplete or killed, **3** for an error talking to the API (130 on Ctrl-C). That
makes a job a CI step: `... jobs create --suite practice ... --wait && echo safe to ship`.

Ctrl-C while waiting does not stop the job; stop it with `jobs kill ID`.

## As a library

```python
from monkeyitm import Client, ApiError
c = Client("https://monkeyitm-vm.o87enterprises.workers.dev", key)
job = c.create_job({"name": "ci", "tasks": {"suite": "practice"},
                    "model": {"url": "...", "name": "...", "key_id": "mk_..."}})
print(c.job(job["id"])["status"])
```

Every call raises `ApiError(status, code, message)` on a refusal. Tests: `python3 cli/cli-test.py`.
