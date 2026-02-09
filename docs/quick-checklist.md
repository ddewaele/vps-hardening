# Quick Reference Checklist

Copy-paste commands for hardening an Ubuntu 24.10 VPS from scratch.

> Replace `deploy` with your username, `2222` with your SSH port, and `example.com` with your domain.

---

## 1. System Update

```bash
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
sudo timedatectl set-timezone UTC
```

## 2. Create Non-Root User

```bash
sudo adduser deploy
sudo usermod -aG sudo deploy
```

## 3. SSH Keys (run on your LOCAL machine)

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@YOUR_SERVER_IP
```

## 4. Harden SSH (run on server)

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf << 'EOF'
Port 2222
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
AllowUsers deploy
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
EOF

sudo systemctl edit ssh.socket
# Add:
# [Socket]
# ListenStream=
# ListenStream=2222

sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo systemctl restart ssh.service
sudo passwd -l root
```

> **Test with a new terminal before closing your session:** `ssh -p 2222 deploy@YOUR_SERVER_IP`

## 5. Firewall (UFW)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw enable
sudo ufw status verbose
```

## 6. Fail2Ban

```bash
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

sudo tee /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 1h
findtime = 10m
banaction = ufw
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client status sshd
```

## 7. Docker

```bash
sudo apt install ca-certificates curl gnupg -y
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo usermod -aG docker deploy
newgrp docker
docker run hello-world
```

## 8. Python

```bash
sudo apt install python3-pip python3-venv python3-full pipx -y
pipx ensurepath
```

## 9. Node.js (via NVM)

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc
nvm install --lts
node --version && npm --version
```

## 10. Nginx + Welcome Page

```bash
sudo apt install nginx -y

# Replace example.com with your domain everywhere below
sudo mkdir -p /var/www/example.com/html
sudo chown -R $USER:$USER /var/www/example.com/html

cat << 'HTMLEOF' | sudo tee /var/www/example.com/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0f172a; color: #e2e8f0; }
        .c { text-align: center; }
        h1 { font-size: 2.5rem; }
        p { color: #94a3b8; }
    </style>
</head>
<body><div class="c"><h1>Welcome</h1><p>This server is secured and ready.</p></div></body>
</html>
HTMLEOF

sudo tee /etc/nginx/sites-available/example.com << 'NGINXEOF'
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    root /var/www/example.com/html;
    index index.html;
    location / { try_files $uri $uri/ =404; }
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
}
NGINXEOF

sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

## 11. Let's Encrypt SSL

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d example.com -d www.example.com
sudo certbot renew --dry-run
```

## 12. Verify Everything

```bash
# SSH on custom port
ssh -p 2222 deploy@YOUR_SERVER_IP

# Firewall
sudo ufw status

# Fail2Ban
sudo fail2ban-client status sshd

# Docker
docker ps

# Node
node --version

# Nginx & SSL
curl -I https://example.com

# Certbot auto-renewal
sudo systemctl status certbot.timer
```

---

## Quick Troubleshooting

| Problem | Fix |
|---------|-----|
| Locked out of SSH | Use VPS provider's console; check `/etc/ssh/sshd_config.d/00-hardening.conf` |
| UFW blocked SSH | Boot into recovery; `sudo ufw allow 2222/tcp && sudo ufw enable` |
| Certbot fails | Ensure ports 80/443 open, DNS A record points to VPS IP, Nginx is running |
| Docker permission denied | `sudo usermod -aG docker $USER` then log out/in |
| NVM not found after install | `source ~/.bashrc` or `source ~/.nvm/nvm.sh` |
