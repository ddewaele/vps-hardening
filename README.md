# VPS Hardening Guide — Ubuntu 24.10

Harden a fresh Ubuntu 24.10 VPS in minutes. One script takes you from a vanilla install to a secured server with SSH hardening, firewall, brute-force protection, Docker, and Nginx with Let's Encrypt SSL.

## Quick Start

SSH into your fresh VPS, download the script, configure it, and run it:

```bash
# Download the script
curl -sO https://raw.githubusercontent.com/ddewaele/vps-hardening/main/scripts/harden.sh
chmod +x harden.sh

# Edit the configuration section at the top
nano harden.sh

# Run it
sudo ./harden.sh
```

Or clone the full repo (includes all documentation):

```bash
git clone https://github.com/ddewaele/vps-hardening.git
cd vps-hardening/scripts
nano harden.sh          # edit the configuration section
sudo ./harden.sh
```

### Prerequisites

- A VPS running **Ubuntu 24.10** (Oracular Oriole)
- Logged in as **root** or **ubuntu** (the default user on most VPS providers)
- An SSH key pair on your local machine (already on the server — that's how you logged in)
- A domain name pointed at your VPS IP (optional — for Nginx/SSL)

## What the Script Does

The script automates everything documented in the [docs/](docs/) folder. Edit the configuration variables at the top before running:

```bash
DEPLOY_USER="deploy"              # Non-root user to create
SSH_PORT="2222"                   # Custom SSH port
DOMAIN=""                         # Your domain (leave empty to skip Nginx)
CERTBOT_EMAIL=""                  # Email for Let's Encrypt (leave empty to skip SSL)
ENABLE_PASSWORDLESS_SUDO="true"   # Passwordless sudo for DEPLOY_USER
ENABLE_UFW_RATE_LIMIT="true"      # Rate-limit SSH connections
NODE_VERSION="22"                 # Node.js version to install
```

Here's what each step does, mapped to the corresponding documentation:

| Step | What it does | Docs |
|------|-------------|------|
| System update | `apt update/upgrade/dist-upgrade`, enable `unattended-upgrades` | [01](docs/01-initial-setup-ssh-hardening.md) |
| Timezone | Set to UTC | [01](docs/01-initial-setup-ssh-hardening.md) |
| User creation | Create `deploy` user with sudo, copy SSH keys from current user | [01](docs/01-initial-setup-ssh-hardening.md) |
| SSH hardening | Custom port, key-only auth, disable root login, `AllowUsers`, session limits, disable X11/TCP forwarding | [01](docs/01-initial-setup-ssh-hardening.md) |
| Lock root | `passwd -l root` | [01](docs/01-initial-setup-ssh-hardening.md) |
| UFW firewall | Default deny incoming, allow SSH/HTTP/HTTPS, optional rate limiting | [02](docs/02-firewall-fail2ban.md) |
| Fail2Ban | 3 attempts → 1h ban, UFW banaction, custom SSH port | [02](docs/02-firewall-fail2ban.md) |
| Docker CE | Official repo, GPG key, engine + compose + buildx, add user to docker group | [03](docs/03-software-installation.md) |
| Python | python3, pip, venv, pipx | [03](docs/03-software-installation.md) |
| Node.js | NVM + Node.js (installed as deploy user, not root) | [03](docs/03-software-installation.md) |
| Build tools | build-essential, git | [03](docs/03-software-installation.md) |
| Nginx | Server block, security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy) | [04](docs/04-nginx-letsencrypt.md) |
| Let's Encrypt | Certbot with auto-renewal, SSL hardening (TLSv1.2+, strong ciphers, HSTS) | [04](docs/04-nginx-letsencrypt.md) |
| Verification | Prints active SSH config, firewall rules, Fail2Ban status, listening ports | — |

## Usage Options

```bash
sudo ./harden.sh                    # Run all steps
sudo ./harden.sh --dry-run          # Preview what would happen (no changes made)
sudo ./harden.sh --skip-docker      # Skip Docker installation
sudo ./harden.sh --skip-nginx       # Skip Nginx + Certbot
sudo ./harden.sh --skip-node        # Skip Node.js (NVM)
sudo ./harden.sh --skip-python      # Skip Python setup
```

Flags can be combined: `sudo ./harden.sh --skip-docker --skip-nginx`

## Safety Features

The script is designed to not lock you out:

- **Pre-flight checks** — verifies root access, detects OS, warns before proceeding
- **SSH key auto-detection** — finds your SSH keys from the current user (root/ubuntu) and copies them to the new deploy user. Refuses to continue if no keys are found
- **SSH config validation** — runs `sshd -t` before restarting SSH. If validation fails, reverts changes automatically
- **Confirmation prompt** — asks before starting
- **Dry run mode** — `--dry-run` shows every step without making changes

> **Always keep your current SSH session open.** Do not close it until you've verified SSH access works from a new terminal on the new port.

## Documentation

The docs/ folder tells the full story behind every step the script takes. If you want to understand **why** each change is made, what the risks are, and how to troubleshoot — read the docs:

| Guide | Description |
|-------|-------------|
| [01 - Initial Setup & SSH Hardening](docs/01-initial-setup-ssh-hardening.md) | System updates, non-root user, SSH keys, disable password auth, custom SSH port |
| [02 - Firewall & Fail2Ban](docs/02-firewall-fail2ban.md) | UFW configuration, Fail2Ban brute-force protection |
| [03 - Software Installation](docs/03-software-installation.md) | Docker, Python, Node.js (via NVM) |
| [04 - Nginx & Let's Encrypt](docs/04-nginx-letsencrypt.md) | Nginx server blocks, Certbot SSL, security headers, SSL hardening |
| [Quick Reference Checklist](docs/quick-checklist.md) | Copy-paste commands for manual execution |

The docs are the manual version of what the script automates. They cover safety precautions (like keeping a second terminal open), explain the reasoning behind each setting, and include verification commands to confirm things work.

## Extra Docs

Deeper dives and gotchas discovered along the way:

| Topic | Description |
|-------|-------------|
| [Docker Bypasses UFW](extra-docs/docker-ufw-gotcha.md) | Why Docker-published ports ignore UFW and how to fix it |
| [Snap vs Apt Docker](extra-docs/snap-vs-apt-docker.md) | Differences between Snap Docker and Docker CE, migration steps |
| [UFW & Existing Connections](extra-docs/ufw-and-existing-connections.md) | Why `ufw default deny` won't kill your SSH session (and what will) |

## References

- [Ubuntu Server Guide](https://ubuntu.com/server/docs)
- [CIS Benchmarks for Ubuntu](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Docker Official Install Guide](https://docs.docker.com/engine/install/ubuntu/)
- [Certbot / Let's Encrypt](https://certbot.eff.org/)
- [NVM GitHub](https://github.com/nvm-sh/nvm)
