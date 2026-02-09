# 02 — Firewall (UFW) & Fail2Ban

## 1. UFW — Uncomplicated Firewall

UFW is pre-installed on Ubuntu. It wraps iptables into a simple interface.

### Default Policy

Deny everything incoming, allow everything outgoing:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### Allow Required Ports

> **Important:** Allow your SSH port **before** enabling the firewall, or you will lock yourself out.

```bash
# SSH (use your custom port from the SSH hardening step)
sudo ufw allow 2222/tcp comment 'SSH'

# HTTP & HTTPS (for Nginx / Let's Encrypt)
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
```

### Enable the Firewall

```bash
sudo ufw enable
```

### Verify

```bash
sudo ufw status verbose
```

Expected output:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere                   # SSH
80/tcp                     ALLOW IN    Anywhere                   # HTTP
443/tcp                    ALLOW IN    Anywhere                   # HTTPS
```

### Useful UFW Commands

```bash
sudo ufw status numbered        # list rules with numbers
sudo ufw delete 3               # delete rule #3
sudo ufw allow from 203.0.113.0/24 to any port 2222  # allow SSH from specific subnet
sudo ufw reload                 # reload rules
sudo ufw disable                # disable (rules are preserved)
```

---

## 2. Fail2Ban — Brute-Force Protection

Fail2Ban monitors log files and bans IPs that show malicious signs (too many password failures, seeking exploits, etc.).

### Install

```bash
sudo apt install fail2ban -y
```

### Configure

Never edit the main config directly — create a local override:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

Find the `[DEFAULT]` section and set:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
banaction = ufw
```

Then find (or add) the `[sshd]` jail:

```ini
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 1h
```

### Start & Enable

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Verify

```bash
# Check jail status
sudo fail2ban-client status sshd

# View banned IPs
sudo fail2ban-client get sshd banip

# Manually unban an IP
sudo fail2ban-client set sshd unbanip 203.0.113.42
```

### Check Logs

```bash
sudo tail -f /var/log/fail2ban.log
```

---

## 3. Optional: Rate-Limit with UFW

For extra protection, rate-limit SSH connections (limits to 6 connections per 30 seconds from a single IP):

```bash
sudo ufw limit 2222/tcp comment 'SSH rate limit'
```

> This replaces the simple `allow` rule for port 2222.

## What's Next

Proceed to [03 - Software Installation](03-software-installation.md) to install Docker, Python, and Node.js.
