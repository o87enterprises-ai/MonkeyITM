# site

The unlisted, invitation-only early-access site for MonkeyITM-VM: a Cloudflare
Worker (`worker/index.js`) in front of static pages (`public/`), with a D1
database for sign-in, the request-access form and invitations.

- `/` announces the program and has the request-access form (`POST /api/request-access`).
- `/demo` is the simulated test environment. It needs GitHub sign-in **and an
  invitation**; signed-in people without one see an "access is by invitation" page.
- The site is unlisted: every page is `noindex`, `robots.txt` disallows all, and
  there is no sitemap. Share it by link only.

Before sharing the link with anyone outside: the patent question goes to counsel
first (`docs/LAUNCH_PLAN.md` section 5). Do not name AI companies on any page.

## Deploy

From this folder, logged in to Cloudflare (`npx wrangler login` once):

```bash
npx wrangler d1 migrations apply monkeyitm-vm --remote
npx wrangler deploy
```

Optional secret, a random string that salts the hash used to rate-limit the form:

```bash
npx wrangler secret put REQUEST_SALT
```

GitHub sign-in needs `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` as secrets; without
them `/demo` says sign-in is not open yet.

## The real test (not live until the host exists)

`/demo/real` runs real, contained agent runs on a separate host (`docs/HOSTED_REAL_TEST.md`).
It needs the Worker settings `NUCLEUS_URL`, `NUCLEUS_SECRET` (secrets) and `NUCLEUS_MODELS`
(variable), migration `0004`, and the host running. Locally, put them in `site/.dev.vars`
(git-ignored) and run the host with `hosted/nucleus_host.py`.

## Reading requests and sending invitations

List new requests:

```bash
npx wrangler d1 execute monkeyitm-vm --remote --command "SELECT id, datetime(created_at,'unixepoch') AS at, name, email, organization, role, use_case FROM access_requests WHERE status='new' ORDER BY id"
```

Invite someone (by the email their GitHub account has verified, or by GitHub login),
then mark the request:

```bash
npx wrangler d1 execute monkeyitm-vm --remote --command "INSERT INTO invites (email, note, created_at) VALUES ('person@example.org', 'request 1', unixepoch()); UPDATE access_requests SET status='invited' WHERE id=1"
```

Invite a **security tester** (`tester = 1`): before they can enter the test environment or create API keys,
they must sign the Security Testing Authorization and Confidentiality Agreement (`worker/tester.js`) at
`/security-agreement`. Their typed name, the version and the time are stored on their `users` row.

```bash
npx wrangler d1 execute monkeyitm-vm --remote --command "INSERT INTO invites (email, github_login, tester, note, created_at) VALUES ('tester@example.org', 'their-github-login', 1, 'pentest', unixepoch())"
npx wrangler d1 execute monkeyitm-vm --remote --command "SELECT login, tester_signed_name, tester_terms_version, datetime(tester_accepted_at,'unixepoch') FROM users WHERE tester_accepted_at IS NOT NULL"
```

Revoke an invitation (they keep their account but lose access to `/demo`):

```bash
npx wrangler d1 execute monkeyitm-vm --remote --command "UPDATE invites SET revoked_at=unixepoch() WHERE email='person@example.org'"
```

Delete a request on the sender's request:

```bash
npx wrangler d1 execute monkeyitm-vm --remote --command "DELETE FROM access_requests WHERE email='person@example.org'"
```

The invitation email itself is sent by hand; the site sends no email.

## Local test

```bash
npx wrangler d1 migrations apply monkeyitm-vm --local
npx wrangler dev
```

Then open the printed `localhost` address. Use `--local` instead of `--remote` in the
commands above to work against the local database.
