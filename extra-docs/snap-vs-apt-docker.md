# Snap Docker vs Docker CE (apt)

## Quick Comparison

| | Docker CE (apt) | Snap Docker |
|---|---|---|
| Maintained by | Docker Inc (official) | Community |
| Update speed | Latest stable, fast | Often lags behind |
| Config location | `/etc/docker/daemon.json` | `/var/snap/docker/current/config/daemon.json` |
| Data location | `/var/lib/docker/` | `/var/snap/docker/common/var-lib-docker/` |
| Compose | `docker compose` (v2 plugin, built-in) | May need separate install |
| Volume mounts | Standard Linux permissions | Snap confinement can cause permission issues |
| Recommended for | Production, servers | Quick testing |

## Installing Docker CE (replacing Snap)

### Remove Snap Docker

```bash
sudo snap remove docker
```

### Install Docker CE from official repo

```bash
sudo apt install ca-certificates curl gnupg -y
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
```

> If Ubuntu 24.10 (`oracular`) isn't in Docker's repo yet, replace `$VERSION_CODENAME` with `noble`.

## Keeping Snap Docker

If you prefer to stay on Snap, be aware of:

- **Config path:** `/var/snap/docker/current/config/daemon.json`
- **Restart command:** `sudo snap restart docker`
- **Permissions:** Snap confinement may block access to paths outside `/home` — use `sudo snap connect docker:removable-media` if needed
- **Compose:** Check if `docker compose` is available; if not, install the compose plugin separately
