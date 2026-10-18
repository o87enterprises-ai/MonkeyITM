# The log's hash chain

Every record the broker writes (an intent, a verdict, a result, a run event such as the tripwire or
the kill switch, a staging step, an escalation and its answer) is also chained: an entry in the
`chain` table holding `hash = SHA-256(previous hash, kind, the record's content)`, written in the same
database transaction as the record. The first entry follows `000...0` (64 zeros). The hash of the
last entry is the log's **head**. Capability tokens are never part of an entry, only whether one was
issued.

## What it gives you

`broker verify --db broker.db` rebuilds the chain and checks every table row against it. It finds:

| Change made to the database file | Found because |
|---|---|
| a record edited (a verdict flipped, a command or result rewritten) | the row no longer matches the content its entry recorded |
| a record deleted | its entry refers to a row that is gone |
| a record inserted without going through the broker | the table has a row no entry refers to |
| a chain entry edited | its hash no longer matches its content |
| a chain entry removed, or one edited *and* its own hash recomputed | the next entry's `prev` no longer matches |

Exit status: 0 intact, 1 problems found (listed), 2 could not check. It opens the log read-only, so it is
safe while the broker is running.

## What it does not give you (be honest about this)

- **A log cut short, or rewritten from the start**, is invisible to the chain alone: an attacker who
  can write the file can delete the last entries and their rows, or rebuild the whole chain. This is why
  the head and entry count are recorded **somewhere the log's keeper cannot change**:
  `broker verify --head <head> --rows <n>` then reports a cut-short or rewritten log.
- **A dishonest runner.** The chain proves the log was not changed after the head was recorded; it
  does not prove the runner wrote the truth.
- Legacy logs written before chaining have no chain (`verify` says so).

## Where the head goes

- The export (`broker export`, the run's `log.json`) carries `summary.chain`: `{algorithm: "sha256",
  rows, head}`.
- The runner sends the head and count with the run's result; the control plane stores them on the run
  (`runs.log_chain_head`, `log_chain_rows`) and shows them as `log_chain` in the run's API view, in the
  `jobs runs` listing and in the **signed incident export** (HMAC with the `REPORT_SIGNING_KEY`).
- An enterprise that keeps the runner's database (self-hosted runners) can hold the head independently
  and verify the whole log at any time.

## What to build next

- Ship the chain payloads with the export on request, so a third party can verify an export without the
  database (today they need the SQLite file).
- Sign the head with a key held outside the runner (a hardware key or the control plane) at the end of
  a run, so even the runner cannot rewrite the head.

Tests: `log/tests/chain.rs` (13: honest log, every kind of tampering above, a cut-short log, a legacy
log), `scripts/broker-live-tests.py` part H (the real broker and `broker verify`), `site/api-test.mjs`,
`runner/runner-test.py`.
