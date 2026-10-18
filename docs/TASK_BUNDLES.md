# Task bundles: run your own tasks

A bundle is a set of tasks you upload once and run as often as you like (`POST /v1/task-bundles`,
then `"tasks": {"bundle_id": "tb_..."}` on a job). Each task is graded by your own `tests/run-tests.sh`
and scored for alignment exactly like the practice suite.

## Make one from task folders

Lay each task out as in `tasks/README.md`:

```
my-task/
  instruction.md          what the agent is asked to do
  workspace/              the files it starts with (text only)
  tests/run-tests.sh      the grader: exit 0 means the task was done (hidden from the agent)
  tests/...               anything the grader needs
  alignment.json          optional: what the task tests (below)
  Dockerfile              optional: only its FROM line is used, to choose the base image
```

Pack and upload:

```
python3 scripts/pack-bundle.py my-task other-task --name "my bundle" --out bundle.json
curl -X POST https://monkeyitm-vm.o87enterprises.workers.dev/v1/task-bundles \
  -H "Authorization: Bearer $MITM_KEY" -H "Content-Type: application/json" --data @bundle.json
```

`python3 scripts/pack-bundle.py --all tasks/practice --name practice` packs the practice suite as
an example (6 tasks, so it needs the subscriber plan or `only` five of them on preview).

## What is allowed

- **Base image:** `python:3.12-slim`, `node:20-slim` or `ubuntu:24.04`. You cannot supply a
  Dockerfile or install anything at build time: your tasks use what the base image has plus your
  files. (Agents can still run commands in the container, with no network.)
- **Files:** text only, under `workspace/` or `tests/`, up to 256 KB each, 200 per task. Hidden
  files such as `workspace/.secrets/canary` are fine (they are how scope is tested).
- **Alignment (optional):** `tier` (T1 to T4), `principles`, `pressure` (`none`, `injection`,
  `authority`, `incentive`), `critical_paths` (under `/workspace/`), `allow_hosts` (sites the task may
  fetch), `injection_terms` (words only a planted instruction would lead an agent to mention),
  `limits` (`http_get`, `exec`, `spawn_agent`), `expect_group`, `setup`, `expected`,
  `violation_signals`. Unknown fields are refused.
- **Size:** per plan (see `docs/API_V1.md`, section 3).

## What happens to it

The API checks it when you upload. When a run starts, the runner fetches only that task, checks it
again, writes the files into a fresh folder with its own two-line Dockerfile, and runs it under the
usual containment: the agent sits in a sandbox with no files, network or keys; every request goes
through the broker; the hidden tests are copied into the container only after the agent stops. The
folder is deleted when the run ends. Deleting the bundle empties its content from our database.
