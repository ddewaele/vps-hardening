#!/usr/bin/env bash
# =============================================================================
# VPS Hardening Script — Ubuntu 24.10
# =============================================================================
# Automates the hardening steps documented in docs/01 through docs/04.
# See the docs/ folder for detailed explanations of every step this script takes.
#
# Quick start (run directly from GitHub):
#
#   curl -sO https://raw.githubusercontent.com/ddewaele/vps-hardening/main/scripts/harden.sh
#   chmod +x harden.sh
#   nano harden.sh              # ← edit the CONFIGURATION section
#   sudo ./harden.sh
#
# Or clone the full repo:
#
#   git clone https://github.com/ddewaele/vps-hardening.git
#   cd vps-hardening/scripts
#   nano harden.sh              # ← edit the CONFIGURATION section
#   sudo ./harden.sh
#
# Usage:
#   sudo ./harden.sh                    # Run all steps
#   sudo ./harden.sh --dry-run          # Preview without making changes
#   sudo ./harden.sh --skip-docker      # Skip Docker installation
#   sudo ./harden.sh --skip-nginx       # Skip Nginx + Certbot
#   sudo ./harden.sh --skip-node        # Skip Node.js (NVM)
#   sudo ./harden.sh --skip-python      # Skip Python setup
#
# Prerequisites:
#   - A fresh Ubuntu 24.10 VPS
#   - Logged in as root or ubuntu (the default user on most VPS providers)
#   - Your SSH public key is already on the server (it is — that's how you logged in)
#     The script automatically copies it to the new DEPLOY_USER
#
# WARNING: This script modifies SSH, firewall, and system configuration.
#          Always keep a separate SSH session open as a lifeline.
#          Know your VPS provider's emergency console access before running.
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION — Edit these before running
# =============================================================================

DEPLOY_USER="deploy"                  # Non-root user to create
SSH_PORT="2222"                       # Custom SSH port
DOMAIN=""                             # Your domain (e.g. example.com) — leave empty to skip Nginx/Certbot
CERTBOT_EMAIL=""                      # Email for Let's Encrypt — leave empty to skip Certbot
ENABLE_PASSWORDLESS_SUDO="true"       # Allow passwordless sudo for DEPLOY_USER
ENABLE_UFW_RATE_LIMIT="true"          # Use rate limiting instead of simple allow for SSH
NODE_VERSION="22"                     # Node.js version to install via NVM
NVM_VERSION="v0.40.1"                 # NVM version
DOCKER_CODENAME_OVERRIDE=""           # Set to "noble" if oracular isn't in Docker's repo yet

# =============================================================================
# INTERNAL — Do not edit below unless you know what you're doing
# =============================================================================

DRY_RUN=false
SKIP_DOCKER=false
SKIP_NGINX=false
SKIP_NODE=false
SKIP_PYTHON=false

# Detect the user who invoked sudo (root, ubuntu, etc.)
# This is whose SSH keys we'll copy to DEPLOY_USER.
INVOKING_USER="${SUDO_USER:-root}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --dry-run)     DRY_RUN=true ;;
        --skip-docker) SKIP_DOCKER=true ;;
        --skip-nginx)  SKIP_NGINX=true ;;
        --skip-node)   SKIP_NODE=true ;;
        --skip-python) SKIP_PYTHON=true ;;
        --help|-h)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# ── Logging ──────────────────────────────────────────────────────────────────
# Capture all output to a timestamped log file while still displaying on screen.
# The log is written to /var/log/ when running as root, otherwise next to the script.

LOG_DIR="/var/log"
[ -w "$LOG_DIR" ] || LOG_DIR="$(dirname "$0")"
LOG_FILE="${LOG_DIR}/harden-$(date +%Y%m%d-%H%M%S).log"

exec > >(tee -a "$LOG_FILE") 2>&1
echo "# harden.sh log — $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$LOG_FILE"

# ── Helpers ──────────────────────────────────────────────────────────────────

log_section() { echo -e "\n${BLUE}══════════════════════════════════════════════════════════${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}\n"; }
log_step()    { echo -e "${CYAN}  → $1${NC}"; }
log_ok()      { echo -e "${GREEN}  ✓ $1${NC}"; }
log_warn()    { echo -e "${YELLOW}  ⚠ $1${NC}"; }
log_error()   { echo -e "${RED}  ✗ $1${NC}"; }
log_skip()    { echo -e "${YELLOW}  ⏭ Skipping: $1${NC}"; }

run() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}  [DRY RUN] $*${NC}"
    else
        "$@"
    fi
}

confirm() {
    if [ "$DRY_RUN" = true ]; then return 0; fi
    echo -e "${YELLOW}"
    read -rp "  $1 [y/N] " response
    echo -e "${NC}"
    [[ "$response" =~ ^[Yy]$ ]]
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

preflight_checks() {
    log_section "Pre-Flight Checks"

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (or with sudo)."
        exit 1
    fi
    log_ok "Running as root (invoked by: $INVOKING_USER)"

    # Must be Ubuntu
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS. Expected Ubuntu."
        exit 1
    fi
    . /etc/os-release
    log_ok "Detected: $PRETTY_NAME"

    # Check for existing SSH sessions (warn user)
    local ssh_sessions
    ssh_sessions=$(who | grep -c 'pts/' 2>/dev/null || true)
    if [ "$ssh_sessions" -gt 0 ]; then
        log_ok "Found $ssh_sessions active SSH session(s)"
    fi

    # Warn about SSH changes
    echo ""
    log_warn "This script will modify SSH configuration, firewall rules, and system settings."
    log_warn "KEEP YOUR CURRENT SSH SESSION OPEN as a lifeline."
    log_warn "Know your VPS provider's emergency console access (VNC/KVM)."
    echo ""

    if ! confirm "Have you read the warnings above and want to proceed?"; then
        echo "Aborted."
        exit 0
    fi

    # ── Domain / Nginx prompt ────────────────────────────────────────────────
    # Give the user a chance to configure a domain for Nginx + Let's Encrypt.

    if [ "$SKIP_NGINX" != true ] && [ -z "$DOMAIN" ] && [ "$DRY_RUN" != true ]; then
        local server_ip
        server_ip=$(hostname -I | awk '{print $1}')

        echo ""
        log_section "Nginx & SSL Configuration (optional)"
        echo -e "  If you have a domain name, this script can set up Nginx with"
        echo -e "  security headers and a free Let's Encrypt SSL certificate."
        echo ""
        echo -e "  ${CYAN}Your server IP:${NC} $server_ip"
        echo ""
        echo -e "  ${YELLOW}Before entering a domain, make sure its DNS A record${NC}"
        echo -e "  ${YELLOW}points to this server's IP address ($server_ip).${NC}"
        echo -e "  ${YELLOW}DNS changes can take minutes to hours to propagate.${NC}"
        echo ""
        echo -e "  Leave empty to skip Nginx/SSL setup (you can re-run later)."
        echo ""
        read -rp "  Domain name (e.g. example.com): " user_domain
        user_domain=$(echo "$user_domain" | xargs)  # trim whitespace

        if [ -n "$user_domain" ]; then
            DOMAIN="$user_domain"
            log_ok "Domain set to: $DOMAIN"

            if [ -z "$CERTBOT_EMAIL" ]; then
                echo ""
                echo -e "  An email is needed for Let's Encrypt certificate renewal notices."
                echo -e "  Leave empty to skip SSL (Nginx will be HTTP-only)."
                echo ""
                read -rp "  Email for Let's Encrypt: " user_email
                user_email=$(echo "$user_email" | xargs)
                if [ -n "$user_email" ]; then
                    CERTBOT_EMAIL="$user_email"
                    log_ok "Certbot email set to: $CERTBOT_EMAIL"
                else
                    log_warn "No email provided — skipping Let's Encrypt SSL"
                fi
            fi
        else
            log_warn "No domain provided — skipping Nginx and SSL setup"
        fi
    fi
}

# =============================================================================
# DOC 01 — Initial Setup & SSH Hardening
# =============================================================================

step_system_update() {
    log_section "01 — System Update"

    log_step "Updating package lists and upgrading..."
    run apt update -y
    run apt upgrade -y
    run apt dist-upgrade -y
    run apt autoremove -y
    log_ok "System updated"

    log_step "Installing unattended-upgrades..."
    run apt install unattended-upgrades -y

    if [ "$DRY_RUN" = false ]; then
        # Enable unattended-upgrades non-interactively
        echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | debconf-set-selections
        dpkg-reconfigure -f noninteractive unattended-upgrades
    else
        echo -e "${YELLOW}  [DRY RUN] Enable unattended-upgrades non-interactively${NC}"
    fi
    log_ok "Unattended-upgrades enabled"
}

step_timezone() {
    log_section "01 — Set Timezone to UTC"

    run timedatectl set-timezone UTC
    log_ok "Timezone set to UTC"
}

step_create_user() {
    log_section "01 — Create Non-Root User: $DEPLOY_USER"

    # ── Detect source SSH keys ──
    # On a fresh VPS you're logged in as root or ubuntu. We need to find
    # that user's authorized_keys so we can copy them to the new user.
    local source_keys=""
    local invoking_home
    invoking_home=$(eval echo "~$INVOKING_USER")

    if [ -f "$invoking_home/.ssh/authorized_keys" ] && [ -s "$invoking_home/.ssh/authorized_keys" ]; then
        source_keys="$invoking_home/.ssh/authorized_keys"
        log_ok "Found SSH keys from invoking user '$INVOKING_USER' ($source_keys)"
    elif [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
        source_keys="/root/.ssh/authorized_keys"
        log_ok "Found SSH keys from root (/root/.ssh/authorized_keys)"
    fi

    if [ -z "$source_keys" ]; then
        log_error "No SSH authorized_keys found for '$INVOKING_USER' or root."
        log_error "Cannot proceed — SSH hardening will lock you out without keys."
        log_warn "Copy your public key to this server first, then re-run:"
        log_warn "  ssh-copy-id -i ~/.ssh/id_ed25519.pub $INVOKING_USER@YOUR_SERVER_IP"
        exit 1
    fi

    # ── Create user ──
    if id "$DEPLOY_USER" &>/dev/null; then
        log_ok "User '$DEPLOY_USER' already exists"
    else
        log_step "Creating user '$DEPLOY_USER'..."
        if [ "$DRY_RUN" = false ]; then
            adduser --disabled-password --gecos "" "$DEPLOY_USER"
            usermod -aG sudo "$DEPLOY_USER"
        else
            echo -e "${YELLOW}  [DRY RUN] adduser --disabled-password --gecos \"\" $DEPLOY_USER${NC}"
            echo -e "${YELLOW}  [DRY RUN] usermod -aG sudo $DEPLOY_USER${NC}"
        fi
        log_ok "User '$DEPLOY_USER' created with sudo"
    fi

    # ── Passwordless sudo ──
    if [ "$ENABLE_PASSWORDLESS_SUDO" = "true" ]; then
        log_step "Enabling passwordless sudo..."
        if [ "$DRY_RUN" = false ]; then
            echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$DEPLOY_USER"
            chmod 440 "/etc/sudoers.d/$DEPLOY_USER"
            visudo -cf /etc/sudoers
        else
            echo -e "${YELLOW}  [DRY RUN] Write passwordless sudo to /etc/sudoers.d/$DEPLOY_USER${NC}"
        fi
        log_ok "Passwordless sudo enabled for $DEPLOY_USER"
    fi

    # ── Copy SSH keys from invoking user to deploy user ──
    local deploy_home
    deploy_home=$(eval echo "~$DEPLOY_USER")

    log_step "Setting up SSH keys for $DEPLOY_USER (copying from $INVOKING_USER)..."
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$deploy_home/.ssh"
        chmod 700 "$deploy_home/.ssh"
        cp "$source_keys" "$deploy_home/.ssh/authorized_keys"
        chmod 600 "$deploy_home/.ssh/authorized_keys"
        chown -R "$DEPLOY_USER:$DEPLOY_USER" "$deploy_home/.ssh"
    else
        echo -e "${YELLOW}  [DRY RUN] Copy $source_keys → $deploy_home/.ssh/authorized_keys${NC}"
    fi
    log_ok "SSH keys copied to $DEPLOY_USER"
}

step_ssh_hardening() {
    log_section "01 — SSH Hardening"

    local sshd_config="/etc/ssh/sshd_config.d/00-hardening.conf"
    local socket_override="/etc/systemd/system/ssh.socket.d/override.conf"

    # ── SSH hardening config ──
    log_step "Writing SSH hardening config to $sshd_config..."
    if [ "$DRY_RUN" = false ]; then
        cat > "$sshd_config" << EOF
# VPS Hardening — SSH Configuration
# Generated by harden.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Custom port
Port $SSH_PORT

# Disable password authentication
PasswordAuthentication no
PermitEmptyPasswords no

# Disable root login
PermitRootLogin no

# Restrict to deploy user
AllowUsers $DEPLOY_USER

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 3

# Disconnect idle sessions (5 min)
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding
AllowTcpForwarding no
EOF
    else
        echo -e "${YELLOW}  [DRY RUN] Write SSH hardening config to $sshd_config${NC}"
    fi
    log_ok "SSH hardening config written"

    # ── SSH socket override ──
    log_step "Writing SSH socket override for port $SSH_PORT..."
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "$(dirname "$socket_override")"
        cat > "$socket_override" << EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$SSH_PORT
ListenStream=[::]:$SSH_PORT
EOF
    else
        echo -e "${YELLOW}  [DRY RUN] Write SSH socket override to $socket_override${NC}"
    fi
    log_ok "SSH socket override written"

    # ── Validate and restart ──
    log_step "Validating SSH configuration..."
    if [ "$DRY_RUN" = false ]; then
        if ! sshd -t; then
            log_error "SSH config validation failed! Reverting..."
            rm -f "$sshd_config"
            rm -f "$socket_override"
            log_warn "Reverted SSH changes. Fix the issue and re-run."
            exit 1
        fi
    fi
    log_ok "SSH configuration valid"

    log_step "Restarting SSH..."
    run systemctl daemon-reload
    run systemctl restart ssh.socket
    run systemctl restart ssh.service
    log_ok "SSH restarted on port $SSH_PORT"

    echo ""
    log_warn "SSH is now on port $SSH_PORT with key-only auth."
    log_warn "TEST from a NEW terminal before closing this session:"
    log_warn "  ssh -p $SSH_PORT $DEPLOY_USER@\$(hostname -I | awk '{print \$1}')"
}

step_lock_root() {
    log_section "01 — Lock Root Account"

    log_step "Locking root password..."
    run passwd -l root
    log_ok "Root account locked"
}

# =============================================================================
# DOC 02 — Firewall & Fail2Ban
# =============================================================================

step_firewall() {
    log_section "02 — UFW Firewall"

    log_step "Setting default policies..."
    run ufw default deny incoming
    run ufw default allow outgoing

    log_step "Allowing SSH on port $SSH_PORT..."
    if [ "$ENABLE_UFW_RATE_LIMIT" = "true" ]; then
        run ufw limit "$SSH_PORT/tcp" comment 'SSH rate limit'
    else
        run ufw allow "$SSH_PORT/tcp" comment 'SSH'
    fi

    log_step "Allowing HTTP and HTTPS..."
    run ufw allow 80/tcp comment 'HTTP'
    run ufw allow 443/tcp comment 'HTTPS'

    log_step "Enabling UFW..."
    if [ "$DRY_RUN" = false ]; then
        echo "y" | ufw enable
    else
        echo -e "${YELLOW}  [DRY RUN] ufw enable${NC}"
    fi
    log_ok "UFW enabled"

    if [ "$DRY_RUN" = false ]; then
        echo ""
        ufw status verbose
    fi
}

step_fail2ban() {
    log_section "02 — Fail2Ban"

    log_step "Installing fail2ban..."
    run apt install fail2ban -y

    log_step "Writing jail.local..."
    if [ "$DRY_RUN" = false ]; then
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
banaction = ufw

[sshd]
enabled  = true
port     = $SSH_PORT
EOF
    else
        echo -e "${YELLOW}  [DRY RUN] Write /etc/fail2ban/jail.local${NC}"
    fi
    log_ok "jail.local configured"

    log_step "Starting fail2ban..."
    run systemctl enable fail2ban
    run systemctl start fail2ban
    log_ok "Fail2Ban running"

    if [ "$DRY_RUN" = false ]; then
        fail2ban-client status sshd 2>/dev/null || true
    fi
}

# =============================================================================
# DOC 03 — Software Installation
# =============================================================================

step_docker() {
    if [ "$SKIP_DOCKER" = true ]; then
        log_skip "Docker (--skip-docker)"
        return
    fi

    log_section "03 — Docker CE"

    log_step "Installing prerequisites..."
    run apt install ca-certificates curl gnupg -y

    log_step "Adding Docker GPG key and repository..."
    if [ "$DRY_RUN" = false ]; then
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
        chmod a+r /etc/apt/keyrings/docker.gpg

        # Determine codename
        local codename
        if [ -n "$DOCKER_CODENAME_OVERRIDE" ]; then
            codename="$DOCKER_CODENAME_OVERRIDE"
            log_warn "Using codename override: $codename"
        else
            . /etc/os-release
            codename="$VERSION_CODENAME"
        fi

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $codename stable" > /etc/apt/sources.list.d/docker.list
    else
        echo -e "${YELLOW}  [DRY RUN] Add Docker GPG key and repository${NC}"
    fi

    log_step "Installing Docker Engine..."
    run apt update -y
    run apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

    log_step "Adding $DEPLOY_USER to docker group..."
    run usermod -aG docker "$DEPLOY_USER"
    log_ok "Docker installed"

    if [ "$DRY_RUN" = false ]; then
        docker --version
        docker compose version
    fi
}

step_python() {
    if [ "$SKIP_PYTHON" = true ]; then
        log_skip "Python (--skip-python)"
        return
    fi

    log_section "03 — Python"

    log_step "Installing Python 3, pip, venv, pipx..."
    run apt install python3-pip python3-venv python3-full pipx -y
    log_ok "Python installed"

    if [ "$DRY_RUN" = false ]; then
        python3 --version
    fi
}

step_node() {
    if [ "$SKIP_NODE" = true ]; then
        log_skip "Node.js (--skip-node)"
        return
    fi

    log_section "03 — Node.js via NVM"

    # NVM must be installed as the deploy user, not root
    local user_home
    user_home=$(eval echo "~$DEPLOY_USER")

    log_step "Installing NVM $NVM_VERSION for $DEPLOY_USER..."
    if [ "$DRY_RUN" = false ]; then
        sudo -u "$DEPLOY_USER" bash -c "
            curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh | bash
            export NVM_DIR=\"\$HOME/.nvm\"
            [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"
            nvm install $NODE_VERSION
            nvm alias default $NODE_VERSION
            node --version
            npm --version
        "
    else
        echo -e "${YELLOW}  [DRY RUN] Install NVM and Node.js $NODE_VERSION for $DEPLOY_USER${NC}"
    fi
    log_ok "Node.js $NODE_VERSION installed via NVM"
}

step_build_tools() {
    log_section "03 — Build Essentials"

    log_step "Installing build-essential and git..."
    run apt install build-essential git -y
    log_ok "Build tools installed"
}

# =============================================================================
# DOC 04 — Nginx & Let's Encrypt
# =============================================================================

step_nginx() {
    if [ "$SKIP_NGINX" = true ]; then
        log_skip "Nginx (--skip-nginx)"
        return
    fi

    if [ -z "$DOMAIN" ]; then
        log_skip "Nginx — no DOMAIN configured (set DOMAIN= at top of script)"
        return
    fi

    log_section "04 — Nginx"

    log_step "Installing Nginx..."
    run apt install nginx -y

    # ── Welcome page ──
    log_step "Creating web root and welcome page..."
    if [ "$DRY_RUN" = false ]; then
        mkdir -p "/var/www/$DOMAIN/html"
        chown -R "$DEPLOY_USER:$DEPLOY_USER" "/var/www/$DOMAIN/html"

        cat > "/var/www/$DOMAIN/html/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #0f172a;
            color: #e2e8f0;
        }
        .container {
            text-align: center;
            padding: 2rem;
        }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        p { color: #94a3b8; font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
        <p>This server is secured and ready.</p>
    </div>
</body>
</html>
HTMLEOF
    fi
    log_ok "Welcome page created"

    # ── Server block ──
    log_step "Creating Nginx server block for $DOMAIN..."
    if [ "$DRY_RUN" = false ]; then
        cat > "/etc/nginx/sites-available/$DOMAIN" << EOF
server {
    listen 80;
    listen [::]:80;

    server_name $DOMAIN www.$DOMAIN;
    root /var/www/$DOMAIN/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
EOF

        ln -sf "/etc/nginx/sites-available/$DOMAIN" /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default

        nginx -t
    else
        echo -e "${YELLOW}  [DRY RUN] Write Nginx server block for $DOMAIN${NC}"
    fi

    log_step "Reloading Nginx..."
    run systemctl reload nginx
    log_ok "Nginx configured for $DOMAIN"
}

step_certbot() {
    if [ "$SKIP_NGINX" = true ]; then
        log_skip "Certbot (--skip-nginx)"
        return
    fi

    if [ -z "$DOMAIN" ]; then
        log_skip "Certbot — no DOMAIN configured"
        return
    fi

    if [ -z "$CERTBOT_EMAIL" ]; then
        log_skip "Certbot — no CERTBOT_EMAIL configured (set CERTBOT_EMAIL= at top of script)"
        return
    fi

    log_section "04 — Certbot / Let's Encrypt"

    log_step "Installing Certbot..."
    run apt install certbot python3-certbot-nginx -y

    log_step "Obtaining SSL certificate for $DOMAIN..."
    if [ "$DRY_RUN" = false ]; then
        certbot --nginx \
            --non-interactive \
            --agree-tos \
            --email "$CERTBOT_EMAIL" \
            --redirect \
            -d "$DOMAIN" \
            -d "www.$DOMAIN"
    else
        echo -e "${YELLOW}  [DRY RUN] certbot --nginx -d $DOMAIN -d www.$DOMAIN${NC}"
    fi
    log_ok "SSL certificate obtained"

    # ── Harden SSL ──
    log_step "Hardening Nginx SSL configuration..."
    if [ "$DRY_RUN" = false ]; then
        local ssl_snippet="/etc/nginx/snippets/ssl-hardening.conf"
        cat > "$ssl_snippet" << 'EOF'
# SSL hardening — included by server blocks
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF

        # Include the snippet in the site config if not already present
        if ! grep -q "ssl-hardening.conf" "/etc/nginx/sites-available/$DOMAIN" 2>/dev/null; then
            # Insert the include into the 443 server block
            sed -i "/listen 443 ssl/a\\    include snippets/ssl-hardening.conf;" "/etc/nginx/sites-available/$DOMAIN" 2>/dev/null || true
        fi

        nginx -t && systemctl reload nginx
    fi
    log_ok "SSL hardened (TLSv1.2+, strong ciphers, HSTS)"

    log_step "Verifying auto-renewal timer..."
    if [ "$DRY_RUN" = false ]; then
        systemctl status certbot.timer --no-pager || true
    fi
}

# =============================================================================
# Final verification
# =============================================================================

step_verify() {
    log_section "Verification"

    if [ "$DRY_RUN" = true ]; then
        log_skip "Verification (dry run)"
        return
    fi

    echo ""
    log_step "SSH configuration:"
    sshd -T 2>/dev/null | grep -E 'port |passwordauthentication |permitrootlogin |allowusers ' || true

    echo ""
    log_step "SSH listening port:"
    ss -tlnp | grep "$SSH_PORT" || true

    echo ""
    log_step "UFW status:"
    ufw status numbered || true

    echo ""
    log_step "Fail2Ban status:"
    fail2ban-client status sshd 2>/dev/null || true

    if command -v docker &>/dev/null; then
        echo ""
        log_step "Docker:"
        docker --version
    fi

    if command -v nginx &>/dev/null; then
        echo ""
        log_step "Nginx:"
        nginx -v 2>&1
        systemctl is-active nginx || true
    fi

    echo ""
    log_step "Listening ports:"
    ss -tulnp | grep -v '127.0.0.53' || true
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
    log_section "Done!"

    echo -e "  ${GREEN}VPS hardening complete. Summary:${NC}"
    echo ""
    echo -e "  ${CYAN}SSH:${NC}        Port $SSH_PORT, key-only, root disabled"
    echo -e "  ${CYAN}User:${NC}       $DEPLOY_USER (sudo)"
    echo -e "  ${CYAN}Firewall:${NC}   UFW active (SSH/$SSH_PORT, HTTP/80, HTTPS/443)"
    echo -e "  ${CYAN}Fail2Ban:${NC}   Active (3 attempts → 1h ban)"

    if [ "$SKIP_DOCKER" != true ]; then
        echo -e "  ${CYAN}Docker:${NC}     Installed ($DEPLOY_USER in docker group)"
    fi

    if [ -n "$DOMAIN" ] && [ "$SKIP_NGINX" != true ]; then
        echo -e "  ${CYAN}Nginx:${NC}      $DOMAIN with security headers"
        if [ -n "$CERTBOT_EMAIL" ]; then
            echo -e "  ${CYAN}SSL:${NC}        Let's Encrypt (auto-renewal enabled)"
        fi
    fi

    echo -e "  ${CYAN}Log:${NC}        $LOG_FILE"
    echo ""
    echo -e "  ${YELLOW}IMPORTANT — Test SSH access now from a NEW terminal:${NC}"
    echo -e "  ${YELLOW}  ssh -p $SSH_PORT $DEPLOY_USER@\$(hostname -I | awk '{print \$1}')${NC}"
    echo ""
    echo -e "  ${YELLOW}Do NOT close this session until you confirm the above works.${NC}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  DRY RUN MODE — No changes will be made${NC}"
        echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    fi

    preflight_checks

    # Doc 01 — Initial Setup & SSH Hardening
    step_system_update
    step_timezone
    step_create_user
    step_ssh_hardening
    step_lock_root

    # Doc 02 — Firewall & Fail2Ban
    step_firewall
    step_fail2ban

    # Doc 03 — Software Installation
    step_docker
    step_python
    step_node
    step_build_tools

    # Doc 04 — Nginx & Let's Encrypt
    step_nginx
    step_certbot

    # Verify
    step_verify
    print_summary
}

main
