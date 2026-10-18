# Run the practice suite with a real model (on a Vercel Sandbox)

Why a sandbox: the workbench needs Docker, which WSL here does not have. A Vercel Sandbox is a
fresh disposable machine with it, on the free plan (45 minutes per session). Two windows:
**PowerShell** on your Windows computer, and the **sandbox shell** (prompt `▲ /vercel/`).
Paste only the command line, never the prompt. Type your model key only in the sandbox shell,
never in chat or a file, and rotate it afterwards.

## 1. PowerShell: make the archive, create the sandbox, copy, connect

```
cd C:\Users\there\o87DevMobile\Builds\MonkeyITM\MonkeyITM-VM
git pull
git archive --format=tar.gz --prefix=MonkeyITM-VM/ -o "$env:USERPROFILE\Downloads\monkeyitm-eval.tar.gz" HEAD
vercel --scope o87enterprises-2864s-projects sandbox create --project tinker --name mitm-real --timeout 45m
vercel --scope o87enterprises-2864s-projects sandbox copy "\Users\there\Downloads\monkeyitm-eval.tar.gz" mitm-real:/tmp/monkeyitm.tar.gz --project tinker
vercel --scope o87enterprises-2864s-projects sandbox connect mitm-real --project tinker
```

## 2. Sandbox shell: unpack and set up (3 to 6 minutes, ends with "Ready")

```
bash
mkdir -p ~/work && tar xzf /tmp/monkeyitm.tar.gz -C ~/work && cd ~/work/MonkeyITM-VM
bash scripts/vercel-sandbox-setup.sh
```

## 3. Sandbox shell: your key and model

```
read -rs BROKER_LLM_KEY; export BROKER_LLM_KEY
export BROKER_LLM_URL=https://integrate.api.nvidia.com/v1/chat/completions BROKER_LLM_MODEL=z-ai/glm-5.3 BROKER_LLM_MAX_TOKENS=4096
```

(Type the key after the first command and press Enter; nothing shows.)

## 4. Sandbox shell: run the suite in the background and watch it

```
nohup python3 scripts/eval-job.py --tasks tasks/practice --max-steps 20 --timeout 600 --out /tmp/job-real > /tmp/job.out 2>&1 &
tail -f /tmp/job.out        # Ctrl-C stops watching, not the job
```

It runs five tasks one after another (about 3 to 6 minutes each, the first includes a Docker
image download). When it ends:

```
cat /tmp/job-real/job-report.md
cat /tmp/job-real/*/alignment-score.txt
```

To run just the group task with helpers:

```
python3 scripts/eval-job.py --tasks tasks/practice --only p5-group-summaries --mode group --max-steps 20 --out /tmp/job-group
```

## 5. Bring the results back, then clean up

Sandbox shell: `tar czf /tmp/job-real.tgz -C /tmp job-real`. Then PowerShell:

```
vercel --scope o87enterprises-2864s-projects sandbox copy mitm-real:/tmp/job-real.tgz "\Users\there\Downloads\job-real.tgz" --project tinker
vercel --scope o87enterprises-2864s-projects sandbox remove mitm-real --project tinker
```

Then rotate the model key. Paste `job-report.md` and the `alignment-score.txt` files back to the
build session; each flagged attempt names the request in the run's `log.json`.

## If the shell drops

The sandbox keeps running (`sandbox list --project tinker`). Reconnect with
`sandbox connect mitm-real --project tinker`; the background job and `/tmp/job.out` are still
there. A sandbox that was stopped has lost Docker and the setup: run step 2 again.
