# 01 — Initial Setup & SSH Hardening

## 1. Update the System

Always start with a fully updated system.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
```

If security updates are still showing after `upgrade` (e.g. kernel or dependency changes), use `dist-upgrade`:

```bash
sudo apt dist-upgrade -y
```

> `apt upgrade` skips updates that require adding/removing dependencies. `dist-upgrade` handles these, ensuring all security patches are applied. May require a reboot if a kernel update is included.

Enable automatic security updates:

```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

## 2. Set the Timezone

```bash
sudo timedatectl set-timezone UTC
```

## 3. Create a Non-Root User

Never run your server as root. Create a dedicated user with sudo privileges.

```bash
# Replace 'deploy' with your preferred username
sudo adduser deploy
sudo usermod -aG sudo deploy
```

If you want to allow passwordless sudo for convenience (optional):

```bash
echo "deploy ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/deploy
sudo chmod 440 /etc/sudoers.d/deploy
```

Verify the syntax is valid:

```bash
sudo visudo -cf /etc/sudoers
```

Verify sudo works by switching to the new user:

```bash
su - deploy
sudo whoami   # should print: root
```

## 4. Generate SSH Keys (on your local machine)

If you don't already have an SSH key pair, generate one using Ed25519 (recommended):

```bash
# Run this on your LOCAL machine, not the server
ssh-keygen -t ed25519 -C "your_email@example.com"
```

Copy the public key to your server:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@YOUR_SERVER_IP
```

Or manually:

```bash
# On the server, as the deploy user
mkdir -p ~/.ssh
chmod 700 ~/.ssh
# Paste your public key into authorized_keys
nano ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Test the key-based login before proceeding:**

```bash
ssh deploy@YOUR_SERVER_IP
```

## 5. Pre-Flight Checks (before touching SSH)

Before making any SSH changes, verify these things first. Getting locked out of your VPS means using the provider's emergency console (if available), so take this seriously.

### 5a. Confirm key-based login works for your user

Open a **second terminal** and verify you can log in with your key:

```bash
ssh deploy@YOUR_SERVER_IP
```

If this fails, do **not** proceed — fix key-based auth first.

### 5b. Confirm your user has sudo

While logged in as `deploy`:

```bash
sudo whoami
# Must print: root
```

### 5c. Check that your public key is in place

```bash
cat ~/.ssh/authorized_keys
# Should show your Ed25519 public key
```

### 5d. Know your VPS provider's emergency access

Most providers offer a web-based console (VNC/KVM) that bypasses SSH entirely. **Locate this now** before you need it:
- DigitalOcean: Droplet > Access > Launch Recovery Console
- Hetzner: Server > Rescue > Console
- Vultr: Server > View Console
- AWS Lightsail: Connect using SSH (browser-based)

---

## 6. Harden SSH Configuration

> **Golden rule:** Keep your current SSH session open at all times. Never close it until you have verified the new config works from a separate terminal.

### Step-by-step approach (do NOT combine these into one big change)

The safest approach is to make changes incrementally — one setting at a time — so you can isolate what broke if something goes wrong.

### 6a. Change the SSH port first (and test)

Create the hardening drop-in config:

```bash
sudo vi /etc/ssh/sshd_config.d/00-hardening.conf
```

Start with **only the port change**:

```
Port 2222
```

Update the socket to match (Ubuntu 22.10+ uses socket-based activation):

```bash
sudo systemctl edit ssh.socket
```

Add the following (the empty `ListenStream=` clears the default):

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=[::]:2222
```

> **Why explicit addresses?** The base unit file may contain `BindIPv6Only=ipv6-only`, which is still inherited by the override. A bare `ListenStream=2222` combined with that setting can result in SSH only binding to IPv6, locking you out of IPv4 connections. Always specify both `0.0.0.0:PORT` (IPv4) and `[::]:PORT` (IPv6) explicitly.

Restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo systemctl restart ssh.service
```

**Verify in a NEW terminal** (keep the old one open!):

```bash
ssh -p 2222 deploy@YOUR_SERVER_IP
```

If it fails, use your existing session to revert.

### 6b. Validate the config before every restart

Always check for syntax errors before restarting SSH:

```bash
sudo sshd -t
```

If it prints nothing, the config is valid. If it shows errors, fix them before restarting.

### 6c. Disable password auth (and test)

Only after the port change works, add to `/etc/ssh/sshd_config.d/00-hardening.conf`:

```
PasswordAuthentication no
PermitEmptyPasswords no
```

Validate and restart:

```bash
sudo sshd -t && sudo systemctl restart ssh.service
```

**Test** from a new terminal:

```bash
ssh -p 2222 deploy@YOUR_SERVER_IP
# Should work (using your key)

ssh -p 2222 -o PubkeyAuthentication=no deploy@YOUR_SERVER_IP
# Should be REJECTED — that confirms password auth is off
```

### 6d. Add remaining hardening options (and test)

Add the rest to `/etc/ssh/sshd_config.d/00-hardening.conf`:

```
# Disable root login
PermitRootLogin no

# Restrict to your user
AllowUsers deploy

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 3

# Disconnect idle sessions (5 min)
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding (if not needed)
AllowTcpForwarding no
```

> **Watch out for `AllowUsers`** — if you typo the username, nobody can log in via SSH.

Validate and restart:

```bash
sudo sshd -t && sudo systemctl restart ssh.service
```

**Test** from a new terminal:

```bash
ssh -p 2222 deploy@YOUR_SERVER_IP
```

### 6e. Final verification checklist

Run these checks from your working session to confirm everything is locked down:

```bash
# 1. Confirm sshd is listening on the right port
sudo ss -tlnp | grep sshd

# 2. Confirm the active SSH config
sudo sshd -T | grep -E 'port|passwordauthentication|permitrootlogin|allowusers'

# Expected output:
#   port 2222
#   passwordauthentication no
#   permitrootlogin no
#   allowusers deploy

# 3. Confirm your key is still authorized
ssh -p 2222 -o BatchMode=yes deploy@YOUR_SERVER_IP echo "SSH OK"

# 4. Confirm password login is rejected
ssh -p 2222 -o PubkeyAuthentication=no deploy@YOUR_SERVER_IP 2>&1 | grep -i "permission denied"
```

---

## 7. Disable Root Login via Password

Only do this **after** you've confirmed everything works:

```bash
sudo passwd -l root
```

## What's Next

Proceed to [02 - Firewall & Fail2Ban](02-firewall-fail2ban.md) to lock down network access.
