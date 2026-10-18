# The runner

`runner/runner.py` is the process that actually executes jobs. The control plane (the Worker at
`site/worker/api.js`) only queues runs; a runner polls it, runs one task at a time with
`scripts/eval-job.py`, and sends back the log, score, transcript, report and result. Standard
library only; Linux only (it uses `/proc` and signals).

## What it does for each run

1. `POST /runner/v1/lease`: take the next queued run (`204` = nothing to do).
2. Re-check the lease. The task must be a folder under `tasks/practice`; mode, limits, tripwire,
   allowed hosts and model URL are validated again here. Nothing from the API is used as a path or
   a command.
3. `POST .../model-key`: fetch the job's model key (refused once the run is stopped).
4. Start `scripts/eval-job.py --only <task> ...` in its own process group. The job's environment
   has `BROKER_LLM_URL`, `BROKER_LLM_MODEL` and `BROKER_LLM_KEY` and a short allow-list of system
   variables. It does **not** receive the runner token or the API address.
5. Heartbeat every 2 s. If the reply says `kill`, the runner pulls the broker's kill switch
   (SIGUSR1), gives the job `MITM_KILL_GRACE_S` (15 s) to stop, then terminates, then kills the
   whole process group.
6. If the control plane is unreachable for `MITM_LOST_S` (30 s), the runner stops its own run the
   same way. No agent outlives its connection to the control plane.
7. Upload `log`, `score`, `transcript` and `report` (the model key is redacted from all of them;
   oversized ones are trimmed), then `POST .../complete` with the overall result, whether the work
   was completed, requests beyond scope, critical attempts, and the halt cause.
8. Delete the run folders (set `MITM_KEEP=1` to keep them).

One run at a time per machine: the broker's socket path is fixed, so concurrency means more
machines or sandboxes, each with its own runner process.

## Live sessions

A lease of `kind: "session"` (docs/SESSIONS_DESIGN.md) starts a different mode:

1. The lease is re-checked (session id, expiry within a day, limits, tripwire, hosts, model, workspace).
2. The model key is fetched; the session's workspace (the `workspace/` files of a bundle task, if it
   was opened on one) is written into `<work>/<run>/workspace/`, checked by the same rules as a bundle.
3. `scripts/make-eval-policy.py` writes the session's policy; `scripts/run-session.sh` starts a
   workbench container (no network, the workspace as `/workspace`, running as the host user) and a broker
   on its own short socket, and prints `READY`. The runner's token never enters that environment.
4. The runner tells the control plane the session is ready and holds a long-poll open
   (`GET /runner/v1/sessions/{id}/next`). Each intent that arrives is passed to the broker's socket (only
   `id`, `action`, `params` and `justification` are forwarded) in a worker thread, and the broker's
   verdict is posted back (`.../reply`). A broker that cannot be reached is answered as a refusal.
5. The session ends when the relay says so (owner kill, `end`, halt, expiry), the heartbeat says kill,
   the control plane is out of reach for `MITM_LOST_S`, the broker dies, or Ctrl-C. For a kill, a lost
   control plane or Ctrl-C the runner pulls the broker's **kill switch first and waits until the broker
   has written the stop to its log** (tearing the broker down at once could lose that record), then
   terminates the script (the broker logs its shutdown, the container is removed).
6. The broker's log is exported (`broker export`), scored with `scripts/score-run.py` (no task, so the
   default alignment), uploaded as `log` and `score` with the model key redacted, and the run is completed
   with the result, the halt cause and the chain head.

Tests: `runner/runner-test.py` runs sessions against a fake control plane and a fake broker (workspace
seeding, intents, kill by message, by heartbeat and by a lost control plane, expiry, a broker that will not
start, a refused workspace, Ctrl-C) and, when `cargo build -p broker` has been run, against the **real
broker** through the same socket protocol (an allowed read, a refusal, the kill switch, the export, the
score).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `MITM_API` | required | API base URL (https; http only for localhost) |
| `MITM_RUNNER_TOKEN` | required | the `mitr_...` token from `POST /admin/runners` |
| `MITM_POLL_S` | 5 | seconds between polls when idle |
| `MITM_HEARTBEAT_S` | 2 | heartbeat interval |
| `MITM_LOST_S` | 30 | stop the run after this long without a good heartbeat |
| `MITM_KILL_GRACE_S` | 15 | time the job gets to stop after the kill switch |
| `MITM_WORK` | `/tmp/mitm-runner` | scratch folder |
| `MITM_TASKS` | `tasks/practice` | tasks folder, relative to the repository |
| `MITM_ONCE` | off | `1`: exit after one poll or one run |
| `MITM_KEEP` | off | `1`: keep run folders |

## Tests

`python3 runner/runner-test.py` (39 checks, Linux): a fake control plane and a fake job and broker
exercise the lease check, the environment the job receives, redaction, the owner's kill (the fake
broker really receives SIGUSR1), a job that ignores the kill (terminated, then killed), a lost
control plane, bad leases, size trimming and the loop. It does not run Docker or a model.

## First real run on a Vercel Sandbox

Two windows: **PowerShell** on your computer and the **sandbox shell**. Type secrets only where
shown. Never paste a key or token into chat or a file.

### 1. PowerShell: make the archive, create the sandbox, copy, connect

```
cd C:\Users\there\o87DevMobile\Builds\MonkeyITM\MonkeyITM-VM
git checkout main
git pull
git archive --format=tar.gz --prefix=MonkeyITM-VM/ -o "$env:USERPROFILE\Downloads\monkeyitm-eval.tar.gz" HEAD
vercel --scope o87enterprises-2864s-projects sandbox create --project tinker --name mitm-runner --timeout 45m
vercel --scope o87enterprises-2864s-projects sandbox copy "\Users\there\Downloads\monkeyitm-eval.tar.gz" mitm-runner:/tmp/monkeyitm.tar.gz --project tinker
vercel --scope o87enterprises-2864s-projects sandbox connect mitm-runner --project tinker
```

### 2. Sandbox shell: set up (ends with "Ready"), then start the runner

```
bash
mkdir -p ~/work && tar xzf /tmp/monkeyitm.tar.gz -C ~/work && cd ~/work/MonkeyITM-VM
bash scripts/vercel-sandbox-setup.sh
export MITM_API=https://monkeyitm-vm.o87enterprises.workers.dev
read -rs MITM_RUNNER_TOKEN; export MITM_RUNNER_TOKEN
python3 runner/runner.py
```

(Type the runner token after the `read` line and press Enter; nothing shows.) The runner prints
`started; polling ...` and waits. Leave this window open.

### 3. A second window: submit a job with the command line

The client in `docs/CLI.md` replaces the PowerShell below:

```
python3 cli/monkeyitm.py jobs create --suite practice --only p6-no-outside-filing \
  --model-url https://integrate.api.nvidia.com/v1/chat/completions --model-name z-ai/glm-5.3 --wait
```

(It asks for the model key with a hidden prompt, or use `--key-id mk_...` for a stored key.) The
long-hand PowerShell version, for reference:

```
$api = "https://monkeyitm-vm.o87enterprises.workers.dev"
$custkey = ((Get-Content "$HOME\mitm-secrets.txt" | Where-Object { $_ -like 'CUSTOMER_KEY=*' } | Select-Object -Last 1) -split '=',2)[1]
$mk = Read-Host "Model API key" -AsSecureString
$plain = [System.Net.NetworkCredential]::new("", $mk).Password
$body = @{ name = "first real run"; tasks = @{ suite = "practice"; only = @("p6-no-outside-filing") }
           model = @{ url = "https://integrate.api.nvidia.com/v1/chat/completions"; name = "z-ai/glm-5.3"; key = $plain }   # or key_id = "mk_..." for a stored key (docs/API_V1.md, section 4)
           mode = "single" } | ConvertTo-Json -Depth 5
$job = Invoke-RestMethod -Method Post -Uri "$api/v1/jobs" -Headers @{ Authorization = "Bearer $custkey" } -ContentType "application/json" -Body $body
$plain = $null
$job
```

It prints the job id. Watch it:

```
Invoke-RestMethod "$api/v1/jobs/$($job.id)" -Headers @{ Authorization = "Bearer $custkey" }
```

When `status` is `finished`:

```
Invoke-RestMethod "$api/v1/jobs/$($job.id)/report?format=md" -Headers @{ Authorization = "Bearer $custkey" }
```

To test the kill switch on a running job:

```
Invoke-RestMethod -Method Post "$api/v1/jobs/$($job.id)/kill" -Headers @{ Authorization = "Bearer $custkey" }
```

### 4. Clean up

In the sandbox shell press Ctrl-C to stop the runner, then in PowerShell
`vercel --scope o87enterprises-2864s-projects sandbox remove mitm-runner --project tinker`.
Rotate the model key.
