# Start here (for the security tester)

Thanks for doing this. You are testing MonkeyITM-VM **the way a real customer uses it**: through the live
site, the API, the command line client and MCP. Try to break it. A finding is a success.

**Rules, short version** (full version: `PENTEST_PLAN.md`): only the live site below, only your own
accounts; no flooding or denial-of-service (describe it instead); nothing against Cloudflare, Vercel, GitHub
or anyone else; if you reach real data or a secret of ours, stop and tell the owner.

## 1. Get in (5 minutes)

1. Send the owner **two GitHub usernames** (two accounts, so you can attack one organization from the other).
   The owner invites them and tells you when it's done.
2. Open **https://monkeyitm-vm.o87enterprises.workers.dev**, sign in with GitHub, open the test
   environment, and accept the terms. You'll then be shown the **Security Testing Authorization and
   Confidentiality Agreement**: type your full name and sign. It is what permits your testing (and it
   overrides the site's no-probing terms, for you only).
3. Go to **https://monkeyitm-vm.o87enterprises.workers.dev/account** and press **Create an API key**.
   Copy it; it is shown once.
4. Repeat 2-3 with the second account.

## 2. Use it like a customer

- **API**: `API_V1.md` (every endpoint, with examples). Base URL: the site above. Header:
  `Authorization: Bearer <your key>`.
- **Command line client**: `cli/monkeyitm.py` (Python 3, no dependencies); `CLI.md`.
- **Live sessions** (your own agent's tool calls go through our broker): `SESSIONS_DESIGN.md`, `MCP.md`.
  A session needs a runner, which the owner starts for each test window (it lives about 45 minutes). Tell the
  owner when you want one.
- **Jobs** (we run an agent on tasks and score it), **task bundles**, **stored model keys**: `API_V1.md`.
  For a model, use **your own** OpenAI-compatible endpoint; you will not get ours.

## 3. What we most want to know

1. Can an agent get out (files outside its workspace, the network, the runner's secrets, the host)?
2. Can account A see or touch anything of account B's?
3. Can you get a credential you were not given (another key, a model key, a runner or admin token)?
4. Can you stop the kill switch from working, or change a log without it being detected?
5. Which claims in `CLAIMS_REGISTER.md` would you **not** repeat to a customer?

The full list is in `PENTEST_PLAN.md` section 3. The source is in `source-snapshot.zip` if you want it.

## 4. Report

For each finding: what, where, how bad, steps to reproduce. Then, for the claims register: which rows survive,
which are weaker than stated, which are false. Plain text or Markdown to the owner is fine.
