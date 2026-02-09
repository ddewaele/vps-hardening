# VPS Hardening Guide — Ubuntu 24.10

A practical guide for hardening a vanilla Ubuntu 24.10 VPS exposed to the internet. Takes you from a fresh install to a secured server running Nginx with Let's Encrypt SSL.

## What's Covered

| Guide | Description |
|-------|-------------|
| [01 - Initial Setup & SSH Hardening](docs/01-initial-setup-ssh-hardening.md) | System updates, non-root user, SSH keys, disable password auth, custom SSH port |
| [02 - Firewall & Fail2Ban](docs/02-firewall-fail2ban.md) | UFW configuration, Fail2Ban brute-force protection |
| [03 - Software Installation](docs/03-software-installation.md) | Docker, Python, Node.js (via nvm), npm |
| [04 - Nginx & Let's Encrypt](docs/04-nginx-letsencrypt.md) | Nginx reverse proxy on 80/443, Certbot SSL, welcome page |
| [Quick Reference Checklist](docs/quick-checklist.md) | Copy-paste commands to execute in order |

## Prerequisites

- A VPS running **Ubuntu 24.10** (Oracular Oriole)
- Root or sudo access
- A domain name pointed at your VPS IP (for SSL)
- An SSH key pair on your local machine

## References

- [Ubuntu Server Guide](https://ubuntu.com/server/docs)
- [CIS Benchmarks for Ubuntu](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Docker Official Install Guide](https://docs.docker.com/engine/install/ubuntu/)
- [Certbot / Let's Encrypt](https://certbot.eff.org/)
- [NVM GitHub](https://github.com/nvm-sh/nvm)
