# 03 — Software Installation

## 1. Docker

Install Docker CE from the official Docker repository (not the Ubuntu `docker.io` package).

### Add Docker's Official GPG Key and Repository

```bash
# Install prerequisites
sudo apt install ca-certificates curl gnupg -y

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

> **Note:** If Ubuntu 24.10 (oracular) is not yet in Docker's repo, use the Ubuntu 24.04 (noble) codename instead:
> Replace `$(. /etc/os-release && echo "$VERSION_CODENAME")` with `noble`.

### Install Docker Engine

```bash
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
```

### Run Docker Without sudo

```bash
sudo usermod -aG docker ubuntu
sudo usermod -aG docker deploy
# Log out and back in for group change to take effect
newgrp docker
```

### Verify

```bash
docker run hello-world
docker compose version
```

---

## 2. Python

Ubuntu 24.10 ships with Python 3.12. Install pip and venv:

```bash
sudo apt install python3-pip python3-venv python3-full -y
```

### Verify

```bash
python3 --version
pip3 --version
```

### Create a Virtual Environment (recommended)

```bash
python3 -m venv ~/myenv
source ~/myenv/bin/activate
```

> On Ubuntu 24.10, system-wide pip installs are restricted by PEP 668. Always use a venv or `pipx` for installing Python packages.

### Install pipx (for CLI tools)

```bash
sudo apt install pipx -y
pipx ensurepath
```

---

## 3. Node.js via NVM

Use NVM (Node Version Manager) to install and manage Node.js versions. This is preferred over the system package.

### Install NVM

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
```

Reload your shell:

```bash
source ~/.bashrc
```

### Install Node.js

```bash
# Install the latest LTS version
nvm install --lts

# Or install a specific version
nvm install 22

# Set default version
nvm alias default 22
```

### Verify

```bash
node --version
npm --version
nvm ls
```

### Useful NVM Commands

```bash
nvm ls-remote --lts          # list available LTS versions
nvm install 20               # install Node 20.x
nvm use 20                   # switch to Node 20
nvm alias default 20         # set Node 20 as default
```

> NVM installs Node.js per-user (into `~/.nvm/`), so each user that needs Node must install NVM separately.

---

## 4. Build Essentials (optional)

Some npm packages and Python packages need native compilation:

```bash
sudo apt install build-essential git -y
```

## What's Next

Proceed to [04 - Nginx & Let's Encrypt](04-nginx-letsencrypt.md) to set up your web server with SSL.
