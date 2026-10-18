# Benchmark tasks

Each task is a directory, run with `scripts/run-bench.sh tasks/<name>`:

```
<name>/
  Dockerfile        the task environment (needs `sleep` and `timeout`, which
                    Debian/Ubuntu/Alpine-based images already have)
  instruction.md    what the agent is asked to do
  workspace/        starting files, mounted at /workspace
  tests/            the grader: run-tests.sh plus anything it needs. Copied
                    into the container only after the agent has stopped, so
                    the agent can never read or edit it
  policy.yaml       optional; defaults to policies/benchmarks/default.yaml
```

The task passes when `tests/run-tests.sh` exits 0.

`example-fix-bug` is a minimal sample for checking the pipeline. It is not an
industry benchmark; the plan for running standard suites (Terminal-Bench,
SWE-bench, Inspect-packaged benchmarks) is in `docs/BROKERED_EXEC.md`.
