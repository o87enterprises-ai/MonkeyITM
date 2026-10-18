# Security policy

MonkeyITM-VM is security software, so reports are very welcome. Please report privately.

## How to report

- Use GitHub's **private vulnerability reporting** on this repository (Security tab, "Report a vulnerability").
  Do not open a public issue for a vulnerability.
- Include what you found, where (file and line, or endpoint), how to reproduce it, and which row of
  `docs/CLAIMS_REGISTER.md` it affects, if any.

## What happens next

- We aim to acknowledge within 5 business days (this is a small project; please be patient).
- We fix, add a test that fails without the fix, update the claims register, and credit you (unless you prefer not).
- Please keep the details private until a fix is released, or for 90 days after your report, whichever comes first.

## Scope

In scope: this repository's code (broker, policy, log chain, runner, guard, CLI, the hosted control plane in
`site/`), run on systems you control.

**Not in scope without written permission:** the owner's hosted service and infrastructure (the live site and its
runners), and any third party (GitHub, Cloudflare, Vercel, model providers). Invited testers sign the Security
Testing Authorization and Confidentiality Agreement on the site first. No denial-of-service, social engineering or
access to other people's data, ever.

Good-faith research within this policy will not be pursued legally by the owner.
