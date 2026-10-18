# Capacity: start free, pay when traffic proves it

Decided 2026-10-17: the hosted service stays on free plans until real demand exceeds them. Running out of capacity
is the signal to pay, not a failure. The site degrades gracefully instead of crashing.

## What the free plans give (checked 2026-10-15; [VERIFY] before relying on them)

| Service | Free plan limit | What hits it first |
|---|---|---|
| Cloudflare Workers | 100,000 requests a day | page views, API calls, runner polls |
| Durable Objects (session relay) | 100,000 requests and 13,000 GB-s a day | live sessions: about 57 thirty-minute sessions a day |
| D1 database | 5 GB, 5 million rows read and 100,000 rows written a day | sign-ins, keys, jobs, logs |
| Vercel Sandbox (runner) | free allowance, 45-minute sandboxes | jobs and live sessions that run agents |

## What happens when a limit is hit

- Every Worker request that fails (quota exhausted or anything else) gets an **"At capacity, try again in an hour"**
  page, or a `503 at_capacity` JSON error on the API, with `Retry-After: 3600`. No stack traces, no broken pages.
- Each address is limited to 300 requests a minute (`RL_IP`), so one visitor cannot use up the day's quota.
- Static pages (home, terms) are served without the Worker and keep working.
- The page says the code is open source, so people who cannot get in can still run it themselves.

## When to pay, and what it costs

| Signal | Action | Cost [VERIFY current prices] |
|---|---|---|
| "At capacity" pages on two or more days in a week (Workers logs show `at_capacity` 503s) | Workers Paid plan: 10 million requests a month included, D1 and Durable Object allowances far higher | about $5 a month base |
| More than about 50 live sessions a day | the same Workers Paid plan (Durable Object duration) | included, then usage-based |
| Runner queue regularly waiting | more runners: the home machines (`docs/PROJECT_REFERENCE.md`), or paid sandbox time | hardware already owned; power and bandwidth |

How to upgrade: Cloudflare dashboard, Workers & Pages, Plans, Workers Paid. No code change is needed; the limits rise
on the next request.

## Watching it

- Cloudflare dashboard, Workers & Pages, monkeyitm-vm, Metrics: requests and errors per day.
- `npx wrangler tail monkeyitm-vm` shows live requests and the `request failed` log lines behind any capacity page.
