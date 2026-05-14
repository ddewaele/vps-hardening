# SSH Connectivity Issues — Debugging Guide

When you see something like:

```
ssh vbox-ubuntu-server-1
Received disconnect from 192.168.0.185 port 2222:2: Too many authentication failures
Disconnected from 192.168.0.185 port 2222
```

…there are **two very different causes** that produce nearly identical-looking errors. Diagnose in this order.

---

## 1. First, figure out which problem you have

On the server, look at the sshd log entries around the time of the failed attempt:

```bash
# all sshd activity, follow live
sudo journalctl -u ssh -f

# just the last few minutes
sudo journalctl -u ssh --since "10 min ago"

# filter to a specific client IP
sudo journalctl -u ssh --since today | grep 192.168.0.210
```

Then decide:

| Log line you see | Cause | Section |
|---|---|---|
| `error: maximum authentication attempts exceeded for <user> from <ip>` followed by `Disconnecting authenticating user … Too many authentication failures [preauth]` | **Client offered too many keys.** `sshd` hit `MaxAuthTries` before reaching the correct one. No ban involved. | [§2](#2-client-side-too-many-keys-offered) |
| `Connection refused` from the client, **and** the server log shows no attempt at all | **IP is banned by fail2ban** (UFW dropped the SYN before sshd ever saw it). | [§3](#3-server-side-ip-banned-by-fail2ban) |
| `Connection timed out` from the client | UFW rule missing, server down, network issue — not auth-related. See [ufw-and-existing-connections.md](ufw-and-existing-connections.md). | — |

The screenshot in the issue that prompted this doc shows the **first** pattern (`maximum authentication attempts exceeded`) — so it's almost certainly §2, not a ban.

---

## 2. Client-side: too many keys offered

### What's happening

`ssh-agent` holds N keys. By default `ssh` offers **every key in the agent** until one succeeds. The server's `MaxAuthTries` (default `6`) counts each offered key as one attempt — public-key offers, password tries, keyboard-interactive prompts all share the same counter. If you have 7+ keys loaded, you can get kicked before the right one is tried.

### Check what your client is offering

```bash
# list keys currently loaded in your agent
ssh-add -l

# verbose SSH — watch which keys are offered and in what order
ssh -vvv vbox-ubuntu-server-1 2>&1 | grep -E "Offering|Authentications|Trying private key|debug1: Next authentication"
```

You'll see lines like `Offering public key: /Users/.../id_ed25519` for every key tried.

### Fix: pin the right key for this host

In `~/.ssh/config`:

```
Host vbox-ubuntu-server-1
    HostName 192.168.0.185
    Port 2222
    User deploy
    IdentityFile ~/.ssh/vbox_deploy_ed25519
    IdentitiesOnly yes
```

The critical line is **`IdentitiesOnly yes`** — without it, `IdentityFile` is *additive* to the agent's keys, not exclusive. With it, only the listed key is offered.

### Quick one-off test (no config change)

```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/vbox_deploy_ed25519 -p 2222 deploy@192.168.0.185
```

### Less-good fix: raise the server limit

Edit `/etc/ssh/sshd_config.d/99-hardening.conf` (or wherever your `MaxAuthTries` lives) and bump it, then `sudo systemctl reload ssh`. **Not recommended** — fixing the client is cleaner and keeps the brute-force protection tight.

---

## 3. Server-side: IP banned by fail2ban

This setup installs fail2ban with `banaction = ufw`, `maxretry = 3`, `findtime = 10m`, `bantime = 1h` (see [scripts/harden.sh:464-474](scripts/harden.sh#L464-L474)). After 3 failed auths in 10 minutes, the client IP gets a UFW deny rule added at the top of the chain.

### See which IPs are currently banned

```bash
# overall fail2ban status — lists active jails
sudo fail2ban-client status

# detailed status of the sshd jail — shows banned IPs and counts
sudo fail2ban-client status sshd
```

Example output:

```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     12
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned:     4
   `- Banned IP list:   192.168.0.210
```

### Cross-check with UFW (fail2ban inserts rules here)

```bash
# numbered list — banned IPs show up as 'DENY IN' rules at the top
sudo ufw status numbered

# raw iptables view (more detail, shows the f2b-sshd chain)
sudo iptables -L f2b-sshd -n --line-numbers
```

### Why a specific IP got banned

```bash
# everything fail2ban has logged about an IP
sudo grep 192.168.0.210 /var/log/fail2ban.log

# the underlying sshd events that triggered the ban
sudo grep 192.168.0.210 /var/log/auth.log

# common patterns worth grepping
sudo grep -E "Failed password|Invalid user|maximum authentication|Connection closed by authenticating user" /var/log/auth.log | tail -50
```

### Useful log files at a glance

| File | What's in it |
|---|---|
| `/var/log/auth.log` | Every sshd auth attempt (success and failure), sudo, PAM |
| `/var/log/fail2ban.log` | Ban/unban decisions with timestamps and IPs |
| `journalctl -u ssh` | Same content as auth.log for sshd, plus service start/stop |
| `journalctl -u fail2ban` | Fail2ban service-level events |

---

## 4. Unbanning an IP

### Unban one IP from one jail

```bash
sudo fail2ban-client set sshd unbanip 192.168.0.210
```

This removes both the fail2ban record **and** the corresponding UFW rule. Verify:

```bash
sudo fail2ban-client status sshd
sudo ufw status | grep 192.168.0.210   # should return nothing
```

### Unban everything in a jail (nuke from orbit)

```bash
sudo fail2ban-client unban --all
```

### Manual UFW cleanup (only if fail2ban left a stray rule)

```bash
sudo ufw status numbered
sudo ufw delete <number>
```

### Whitelist your own IP so it never gets banned

Edit `/etc/fail2ban/jail.local` and add `ignoreip` under `[DEFAULT]`:

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/24
bantime  = 1h
findtime = 10m
maxretry = 3
banaction = ufw
```

Then:

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd     # confirm jail is back up
```

---

## 5. Quick triage cheat-sheet

Run these in order when SSH is misbehaving:

```bash
# 1. Is sshd even running and listening on the right port?
sudo systemctl status ssh
sudo ss -ltnp | grep ssh

# 2. Is your IP currently banned?
sudo fail2ban-client status sshd

# 3. What does sshd say about your most recent attempt?
sudo journalctl -u ssh --since "5 min ago"

# 4. From the client, what keys are being offered?
ssh-add -l
ssh -vvv <host> 2>&1 | grep -E "Offering|Authentications that can continue"

# 5. If banned, unban yourself:
sudo fail2ban-client set sshd unbanip <your-ip>
```

## Related docs

- [check-ssh.md](check-ssh.md) — verifying sshd is up before hardening
- [ufw-and-existing-connections.md](ufw-and-existing-connections.md) — UFW rules and existing sessions
- [connectivity-checks.md](connectivity-checks.md) — general network/DNS/HTTP checks
