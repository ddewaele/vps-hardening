# 01 — Initial Setup & SSH Hardening

## 1. Update the System

Always start with a fully updated system.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
```

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

## 5. Harden SSH Configuration

> **Warning:** Keep your current SSH session open while making these changes. Open a second terminal to test before closing the original session.

Create a hardening drop-in config (Ubuntu 24.10 uses `/etc/ssh/sshd_config.d/`):

```bash
sudo nano /etc/ssh/sshd_config.d/00-hardening.conf
```

Add the following:

```
# Use a non-default port (choose a port between 1024-65535)
Port 2222

# Disable root login
PermitRootLogin no

# Disable password authentication (key-only)
PasswordAuthentication no
PermitEmptyPasswords no

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

### Restart SSH

Since Ubuntu 22.10+, SSH uses socket-based activation:

```bash
# Update the socket to listen on the new port
sudo systemctl edit ssh.socket
```

Add the following (replacing the default port):

```ini
[Socket]
ListenStream=
ListenStream=2222
```

Then restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo systemctl restart ssh.service
```

### Test the New Configuration

In a **new terminal** (keep the old session open!):

```bash
ssh -p 2222 deploy@YOUR_SERVER_IP
```

If it works, you're good. If not, use your existing session to fix the config.

## 6. Disable Root Login via Password

As a final step, lock the root account password:

```bash
sudo passwd -l root
```

## What's Next

Proceed to [02 - Firewall & Fail2Ban](02-firewall-fail2ban.md) to lock down network access.
