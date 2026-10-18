# Deploying the nucleus host

For the owner. Nothing here has been run on a real VM yet: the scripts are checked for syntax
and the service and monitor are tested locally, but the first deployment is a first run, so
do it on a throwaway VM and read what each step prints.

## 1. The VM

A small Debian 12 or Ubuntu 22.04/24.04 server (2 vCPU, 4 GB RAM, 20 GB disk is plenty to
start), in a provider account of its own. **It holds nothing else, and no credentials that
matter**: the thing it runs is the thing under test. Note the owner's address you will SSH
from.

Check the kernel allows what bubblewrap needs (unprivileged user namespaces): on Ubuntu 24.04
an AppArmor setting may block it, and the check in step 2 will say so. If it does, the fix is
a distro setting (for example `kernel.apparmor_restrict_unprivileged_userns=0`), a decision
for the owner; the service will not work until it is made.

## 2. Install

On the VM, from a checkout of this repository (as root):

```
sudo NUCLEUS_SSH_FROM=<your address> bash hosted/deploy/setup-vm.sh
sudo bash hosted/deploy/setup-vm.sh --check
```

Then edit `/etc/nucleus/nucleus.env`: put the owner's model key in `NUCLEUS_LLM_KEY` and check
`NUCLEUS_LLM_MODELS`. Copy `NUCLEUS_SECRET` (printed once in the file) for the Worker.

```
sudo systemctl start nucleus
curl -s http://127.0.0.1:8099/healthz           # {"ok": true, "halted": false}
sudo -u nucleus python3 /opt/monkeyitm/hosted/monitor.py     # {"status": "ok", ...}
```

## 3. Reach it from the Worker without opening a port

The firewall allows no inbound traffic except your SSH. Use a Cloudflare Tunnel: it dials
out from the VM, so nothing listens on the internet.

1. In the Cloudflare dashboard: Zero Trust, Networks, Tunnels, create a tunnel, and install
   `cloudflared` on the VM with the command it shows.
2. Add a public hostname for the tunnel (for example `nucleus.<your domain>`) that points to
   `http://127.0.0.1:8099`.
3. Add an Access policy (service token) in front of that hostname if you want a second lock;
   the signed requests are the first.

## 4. Turn it on in the site

From the `site` folder (secrets are typed at the prompt, not put on the command line):

```
npx wrangler secret put NUCLEUS_URL        # https://nucleus.<your domain>
npx wrangler secret put NUCLEUS_SECRET     # the value from /etc/nucleus/nucleus.env
npx wrangler d1 migrations apply monkeyitm-vm --remote
```

and set `NUCLEUS_MODELS` in `site/wrangler.jsonc` under `vars` to match the host's models, then
`npx wrangler deploy`. Without these the real test says "not open yet".

## 5. First real test, before inviting anyone

1. Sign in with your own invited account and run a single-agent task, then a group task.
2. Try to make it fail: a task pointing at `{canary}`, a file with an injected instruction.
3. Run `sudo -u nucleus python3 /opt/monkeyitm/hosted/monitor.py` and read the journal:
   `journalctl -u nucleus -n 50`.
4. Practice the halt: `sudo python3 /opt/monkeyitm/hosted/halt.py`, confirm a new run is
   refused, then `sudo rm /var/lib/nucleus/HALT && sudo systemctl restart nucleus`.
5. Read `docs/INCIDENT_PLAN.md` once through, with the phone numbers filled in.

## Switching it all off

- Fastest: `sudo python3 /opt/monkeyitm/hosted/halt.py` (kills every run, refuses new ones).
- From the site: `npx wrangler secret delete NUCLEUS_URL` (the real test says "not open yet").
- Hard stop: `sudo systemctl stop nucleus`, or power the VM off.
