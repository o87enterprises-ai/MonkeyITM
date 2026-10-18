# Incident plan: hosted real test

**Status: draft by the build side, for the owner to read, fill in and practise.** Written
2026-10-11. Blanks are marked `[FILL]`. Counsel should review the notification and
confidentiality steps. This covers the hosted test (`docs/HOSTED_REAL_TEST.md`); the public
site has its own, smaller exposure (a form and a sign-in).

## Who

| Role | Who | How to reach |
|---|---|---|
| Owner and decision maker | Daniel Oden | [FILL] |
| Counsel | [FILL] | [FILL] |
| Cloud provider account (VM) | [FILL] | [FILL] |
| Cloudflare account (site, tunnel) | [FILL] | [FILL] |
| Model provider account | [FILL] | [FILL] |

Keep the secrets (service secret, model key, Cloudflare and provider logins) somewhere other
than this repository and other than the VM, with a second way in if the owner is unavailable.

## What counts as an incident

| Kind | Examples | Severity |
|---|---|---|
| Suspected escape | A run's log shows an allowed request that policy forbids; a tester reports they got out; a process on the VM that no run explains | Critical |
| Key or secret exposed | The model key or the service secret in a log, a response, a screenshot or a report | Critical |
| Another person's data seen | A run, log or file shown to the wrong invitee | Critical |
| Abuse or overload | One person burning the model budget, many failed runs, the VM busy with no runs | High |
| Host unhealthy | The health check warns or fails, the disk fills, the service restarts in a loop | Medium |
| Pen-tester report | A message that says "I think I got out" | Treat as critical until looked at |

## The first five minutes (critical)

1. **Stop everything.** On the VM: `sudo python3 /opt/monkeyitm/hosted/halt.py`. It kills
   every run and refuses new ones. If that fails: `sudo systemctl stop nucleus`; if that
   fails: power the VM off from the provider's console.
2. **Close the front door.** From the site folder: `npx wrangler secret delete NUCLEUS_URL`.
   The real test then says "not open yet". The simulated demo and the form are unaffected.
3. **Write down the time and what you saw.** Do not clean up yet.
4. **Do not look further into a suspected escape from inside the VM** beyond what the next
   section needs; every command you run there is on the machine that may be compromised.

## Preserve evidence (before anything is deleted)

- On the VM, copy `/var/lib/nucleus/runs/<id>/` for the run or runs involved (the broker
  database `broker.db`, `log.json`, `log.txt`, `agent.txt`, `broker.out`) and
  `journalctl -u nucleus --since "<time>"` to a place off the VM.
- Provider side: ask the cloud provider to snapshot the VM's disk before it is rebuilt.
- Do not delete runs or run the retention sweep until copies exist.

## Then, by kind

**Suspected escape.** Treat the VM as compromised: do not reuse it. Snapshot it for
analysis, build a new one from `hosted/deploy/` and rotate everything the VM could ever have
held (below). Reproduce the run on a clean machine from the saved task and files. Tell
counsel before telling the tester or anyone else. Fix with a test that fails first, then
re-run the whole suite and the attacker; record the finding in `docs/FIELD_TESTS.md` and
correct any note that turns out wrong.

**Key or secret exposed.** Rotate at once: the model key at the provider, the service secret
(`/etc/nucleus/nucleus.env` and the Worker's `NUCLEUS_SECRET`, together). Check the provider's
usage for the exposure window. Find how it got out and add a check for it.

**Another person's data seen.** Identify who, what, and for how long from the Worker logs and
the run directories. Counsel decides whether and how to notify them and any authority; do not
guess at legal duties here.

**Abuse or overload.** Halt, then look at who (`access_requests`, the run list per user),
revoke their invitation (`site/README.md`), lower the caps in `/etc/nucleus/nucleus.env`, and
restart.

**Host unhealthy.** `journalctl -u nucleus-monitor -n 20` and `journalctl -u nucleus -n 50`;
free disk by deleting old runs through the service (not by hand); restart. If it recurs, halt
and investigate before inviting anyone else.

## Restarting after a halt

Only after the cause is understood and written down: `sudo rm /var/lib/nucleus/HALT`, then
`sudo systemctl restart nucleus`, then one run of your own, then the monitor, then
`npx wrangler secret put NUCLEUS_URL` to open the front door again.

## Telling people

- Invitees: only what they need, in plain words, after counsel has seen it. Do not blame, do
  not speculate.
- A tester's finding is confidential until the owner agrees otherwise (`/terms` section 20).
  Thank them, ask for the run id and what they did, and do not ask them to keep going.
- Nothing about an incident goes on the public site or social media without counsel.

## After

Within a week: write what happened, what was seen, what was done, and what changes. Add the
test that would have caught it. Update this plan, the threat model and the rules of
engagement, and say in `docs/FIELD_TESTS.md` what was learned, without softening it.

## Practise it

Before the first invitation, do the "first five minutes" once on the real VM: halt, confirm
a new run is refused, delete `NUCLEUS_URL` and see the site say "not open yet", then restore
both. Time it. Fill in every `[FILL]`.
