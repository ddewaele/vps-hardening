# Docker Bypasses UFW — Why and How to Fix It

## The Problem

You set up UFW, only allow ports 22/80/443, enable the firewall — and then discover that Docker containers with published ports (e.g. `-p 3080:3080`) are **still accessible from the internet**.

This happens because Docker manipulates **iptables directly**, inserting its own rules at a higher priority than UFW. UFW never even sees the traffic.

```bash
# You'd expect this to block port 3080, but it doesn't:
sudo ufw status
# Shows only 22, 80, 443 allowed — yet 3080 is reachable
```

Verify with:

```bash
sudo iptables -L -n | grep 3080
# You'll see Docker's ACCEPT rule here
```

## Fix 1: Bind containers to localhost (recommended)

Instead of exposing ports to all interfaces, bind to `127.0.0.1`:

```bash
# Instead of:
docker run -p 3080:3080 myapp

# Use:
docker run -p 127.0.0.1:3080:3080 myapp
```

In `docker-compose.yml`:

```yaml
ports:
  - "127.0.0.1:3080:3080"   # only reachable from the host
```

Then use **Nginx as a reverse proxy** to expose the app on 80/443 with SSL. This is the safest approach and works with both Docker CE and Snap Docker.

## Fix 2: Disable Docker's iptables manipulation

Add to Docker's daemon config:

```json
{
  "iptables": false
}
```

**Config file location:**
- Docker CE (apt): `/etc/docker/daemon.json`
- Snap Docker: `/var/snap/docker/current/config/daemon.json`

Restart Docker:

```bash
# Docker CE
sudo systemctl restart docker

# Snap Docker
sudo snap restart docker
```

**Warning:** With `"iptables": false`, containers lose outbound internet access (can't pull images, call APIs, etc.) unless you manually configure iptables/NAT rules. This is usually more trouble than it's worth — prefer Fix 1.

## The Recommended Pattern

```
Internet → Nginx (80/443 with SSL) → localhost:3080 → Docker container
```

- Container bound to `127.0.0.1` — not directly reachable from internet
- Nginx handles SSL termination and proxying
- UFW controls what's exposed (only 80, 443, SSH)
