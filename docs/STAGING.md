# Pre-run web staging (`broker stage`)

The agent never gets a network. When a task needs web content, an operator
approves a list of URLs before the run. The broker fetches them through a
separate, short-lived process, checks and sanitizes the result, and releases
plain text into a read-only folder the agent can already read with `read_file`.
No new channel to the agent is opened.

## Use

```bash
cat > urls.txt <<'EOF'
# approved for the docs task, 2026-10-08
https://docs.python.org/3/library/json.html
EOF
cargo run -p broker -- stage --job docs-json --urls urls.txt
```

The broker shows the URL list and asks for approval (`--yes` takes the URL
file itself as the approval). The released files are at
`/tmp/safe/staged/<job>/001.txt`, `002.txt`, ..., with a `manifest.json` that
lists each file's source and SHA-256. The agent reads them with `read_file`.
The default policy already allows that and denies writes there.

## What happens, step by step

Every step is a row in the log's `job_events`, tagged with its source.
`broker export` prints them as `JOB <id> <source> <step>` lines.

| Step | Source | What it does |
|---|---|---|
| 1 | broker | Checks the job ID and URLs: HTTPS only, no credentials in URLs, at most 20. The operator approves the fetch (**key 1**). |
| 2 | fetcher | A child process (`broker fetch-job`) gets the request as a file. Its environment is cleared, so it has no model key. It fetches only the approved hosts, refuses internal addresses, re-checks every redirect, caps the size, and exits. There is no connection between it and the broker while it runs. It is killed at a time limit. |
| 3 | broker | Re-hashes every file the fetcher wrote and checks it against the fetcher's manifest and the approved hosts (**key 2**). |
| 4 | sanitizer | Plain-text extraction, with no network and no model. Removes scripts, styles, embedded objects, tags, comments, control characters and invisible characters, then scans for instruction-like text and secrets. |
| 5 | broker | Releases the files read-only, quarantines them, or asks a human (below). The holding folder is deleted in every case. |

## Flags

| Severity | Examples | Result |
|---|---|---|
| Block | binary or non-text content; a hash mismatch; a file the fetcher didn't list; a final URL on an unapproved host; the fetcher failing or timing out | **Quarantine:** the content is discarded, the logs are kept, and an alarm is logged (`job_events` and `run_events`) and printed |
| Review | instruction-like text ("ignore previous instructions", ...); something that looks like a key; invisible Unicode tag characters | Released only if a human answers yes; refused with no terminal. The flags are recorded in the manifest. |
| Info | scripts removed; zero-width characters removed; text cut to 32 KB | Recorded only |

A review flag is a hint, not a verdict. Staged text is untrusted input to the
agent, like the planted `notes.txt` in the field tests. Staging stops the agent
from sending data out. It does not stop the agent from being steered by what
it reads.

## Not built yet

- **Container and egress firewall for the fetcher.** Today the fetcher is a
  separate process with a cleared environment. The plan is a throwaway
  container per job, with network access limited to the approved hosts. That
  needs Docker, which hasn't been set up on the test laptop.
- **Agent-requested sources.** The agent can't yet submit a plan with the URLs
  it wants. For now the operator writes the URL file.
- **Model summaries.** Output is extracted text only. A summarizing model would
  run with no network and its output would be treated as untrusted.

## Tests

`cargo test -p broker --test staging` and the `stage::tests` unit tests cover:
a clean release (read-only files, manifest hashes, all log sources); no
request leaving without the grant; review flags refused or released by a
human; tampered content, a planted extra file and an off-list final host
(all quarantined, with the alarm logged and the earlier rows kept); binary
content; a hung fetcher killed at the time limit; the fetcher's cleared
environment; the real fetcher binary refusing internal addresses; bad and
reused job IDs; and the default policy (read allowed, write and `http_get`
denied).
