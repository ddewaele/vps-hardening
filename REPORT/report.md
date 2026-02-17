# Linux VPS Hardening Research Report

> **Date:** February 2026
> **Target OS:** Ubuntu 24.10 (Oracular Oriole)
> **Scope:** Open-source hardening tools, gap analysis against this repo's docs, additional hardening measures, and automation strategies

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What This Repo Currently Covers](#2-what-this-repo-currently-covers)
3. [Open-Source Automated Hardening Tools](#3-open-source-automated-hardening-tools)
   - 3.1 [Auditing & Scanning Tools](#31-auditing--scanning-tools)
   - 3.2 [Automated Hardening Scripts & Frameworks](#32-automated-hardening-scripts--frameworks)
   - 3.3 [Intrusion Prevention & Detection](#33-intrusion-prevention--detection)
   - 3.4 [File Integrity & Rootkit Detection](#34-file-integrity--rootkit-detection)
   - 3.5 [Mandatory Access Control](#35-mandatory-access-control)
4. [Tool-to-Repo Mapping: What Each Tool Covers vs Our Docs](#4-tool-to-repo-mapping-what-each-tool-covers-vs-our-docs)
5. [Gap Analysis: What's Missing From This Repo](#5-gap-analysis-whats-missing-from-this-repo)
   - 5.1 [Kernel Hardening (sysctl)](#51-kernel-hardening-sysctl)
   - 5.2 [Audit Logging (auditd)](#52-audit-logging-auditd)
   - 5.3 [File Integrity Monitoring (AIDE)](#53-file-integrity-monitoring-aide)
   - 5.4 [Rootkit Detection](#54-rootkit-detection)
   - 5.5 [AppArmor Profiles](#55-apparmor-profiles)
   - 5.6 [Two-Factor Authentication for SSH](#56-two-factor-authentication-for-ssh)
   - 5.7 [CrowdSec (Modern Fail2Ban Alternative)](#57-crowdsec-modern-fail2ban-alternative)
   - 5.8 [Docker-Specific Hardening](#58-docker-specific-hardening)
   - 5.9 [Secure Shared Memory (/dev/shm, /tmp)](#59-secure-shared-memory-devshm-tmp)
   - 5.10 [Disable Unnecessary Services](#510-disable-unnecessary-services)
   - 5.11 [Log Management & Monitoring](#511-log-management--monitoring)
   - 5.12 [Network Hardening Beyond UFW](#512-network-hardening-beyond-ufw)
6. [Automation Strategy: Should We Automate This Repo?](#6-automation-strategy-should-we-automate-this-repo)
   - 6.1 [Automation Approaches Compared](#61-automation-approaches-compared)
   - 6.2 [What to Automate vs Keep Manual](#62-what-to-automate-vs-keep-manual)
   - 6.3 [Recommended Approach](#63-recommended-approach)
7. [Prioritized Recommendations](#7-prioritized-recommendations)
8. [Sources](#8-sources)

---

## 1. Executive Summary

This repo provides a solid foundation for hardening a fresh Ubuntu VPS — covering SSH hardening, UFW firewall, Fail2Ban, software installation, and Nginx with Let's Encrypt. These are the essential first steps that every internet-facing server needs.

However, compared to industry benchmarks like [CIS Ubuntu Linux Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux), there are significant hardening areas not yet covered. The major gaps are:

| Gap | Impact | Effort |
|-----|--------|--------|
| Kernel hardening (sysctl) | High | 5 min |
| Secure shared memory | High | 2 min |
| Disable unnecessary services | Medium-High | 10 min |
| CrowdSec (complement/replace Fail2Ban) | High | 15 min |
| AppArmor enforcement | Medium | 10 min |
| Audit logging (auditd) | Medium | 15 min |
| File integrity monitoring (AIDE) | Medium | 10 min |
| 2FA for SSH | Medium | 15 min |
| Docker hardening | Medium | 20 min |
| Rootkit detection | Low-Medium | 5 min |
| Log management | Medium | 15 min |

Additionally, several mature open-source tools exist that can **audit** or **automate** the hardening steps already documented in this repo. The most practical are **Lynis** (auditing), **dev-sec Ansible collection** (automation), and **CrowdSec** (intrusion prevention).

For automation, an **Ansible playbook** is the recommended approach — it's idempotent, readable, and aligns with the dev-sec community's battle-tested roles.

---

## 2. What This Repo Currently Covers

| Doc | Topics | Hardening Areas |
|-----|--------|----------------|
| **01 - Initial Setup & SSH Hardening** | System updates, unattended-upgrades, timezone, non-root user, SSH keys, SSH port change, disable password auth, disable root login, AllowUsers, session timeouts, X11/TCP forwarding disabled | Access control, authentication, update management |
| **02 - Firewall & Fail2Ban** | UFW default-deny, port allowlisting, Fail2Ban with UFW banaction, rate limiting | Network filtering, brute-force protection |
| **03 - Software Installation** | Docker CE, Python, Node.js (NVM), build tools | Runtime setup (minimal security focus) |
| **04 - Nginx & Let's Encrypt** | Nginx server blocks, security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy), Certbot SSL, HSTS, cipher hardening, reverse proxy | Web server hardening, TLS |
| **Quick Checklist** | Copy-paste commands for all above | Operational reference |

**Summary:** The repo covers ~40% of what a CIS Level 1 benchmark would require. The covered areas are well-written with good operational safety advice (incremental changes, keeping sessions open, pre-flight checks). The main gaps are in OS-level hardening, monitoring, and detection.

---

## 3. Open-Source Automated Hardening Tools

### 3.1 Auditing & Scanning Tools

These tools **assess** your system and report what needs fixing — they don't make changes themselves (unless configured to).

#### Lynis

| | |
|---|---|
| **URL** | [github.com/CISOfy/lynis](https://github.com/CISOfy/lynis) |
| **Stars** | ~13k |
| **Language** | Shell (POSIX) |
| **License** | GPL v3 |
| **Maintained** | Yes — actively maintained since 2007 |
| **Install** | `sudo apt install lynis` or `git clone` |

**What it does:** Performs an extensive security audit of your system, scanning hundreds of configuration items across SSH, firewall, kernel, filesystem permissions, authentication, logging, and more. Produces a hardening index score and specific recommendations.

**How it works:** Pure shell script with no dependencies. Runs opportunistically — tests what it finds installed. Produces a report with warnings, suggestions, and a hardening score (0-100).

**What it checks (relevant to this repo):**
- SSH configuration (port, key auth, root login, ciphers)
- Firewall status and rules
- Fail2Ban presence and configuration
- Nginx configuration and security headers
- SSL/TLS certificate validity
- Kernel hardening parameters
- File permissions
- User accounts and sudo config
- Running services
- Automatic updates

**Usage:**
```bash
sudo apt install lynis -y
sudo lynis audit system
# Review: /var/log/lynis.log and /var/log/lynis-report.dat
```

**Verdict:** **Must-have.** Run this after applying the hardening in this repo to see what score you get and what else needs attention. It's the single best tool to validate your hardening work.

---

#### OpenSCAP

| | |
|---|---|
| **URL** | [open-scap.org](https://www.open-scap.org/) / [github.com/OpenSCAP/openscap](https://github.com/OpenSCAP/openscap) |
| **Stars** | ~1.3k |
| **Language** | C |
| **License** | LGPL v2.1 |
| **Maintained** | Yes — backed by Red Hat |
| **Install** | `sudo apt install libopenscap8 openscap-scanner openscap-utils` |

**What it does:** Scans systems against formal compliance profiles (CIS Benchmarks, DISA STIG, PCI DSS, HIPAA). Generates HTML reports showing pass/fail for each benchmark item.

**How it works:** Uses SCAP (Security Content Automation Protocol) — a standardized format for expressing security checklists. You feed it a profile (XCCDF/OVAL) and it evaluates your system against it.

**Relevant profiles for Ubuntu:**
- CIS Level 1 Server
- CIS Level 2 Server
- DISA STIG (if applicable)

**Usage:**
```bash
sudo apt install libopenscap8 openscap-scanner ssg-ubuntu -y
# Scan against CIS Level 1
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml
# Open report.html in a browser
```

**Verdict:** Excellent for compliance-oriented environments. More formal than Lynis but harder to set up. Best if you need to demonstrate compliance against specific standards (CIS, PCI DSS). For a personal VPS, Lynis is more practical.

---

### 3.2 Automated Hardening Scripts & Frameworks

These tools **make changes** to your system — they actively harden it.

#### dev-sec Ansible Collection (devsec.hardening)

| | |
|---|---|
| **URL** | [github.com/dev-sec/ansible-collection-hardening](https://github.com/dev-sec/ansible-collection-hardening) |
| **Stars** | ~3.4k |
| **Language** | Ansible (YAML) |
| **License** | Apache 2.0 |
| **Maintained** | Yes — very active, latest release v10.4.0 |
| **Install** | `ansible-galaxy collection install devsec.hardening` |

**What it does:** Battle-tested Ansible roles for hardening Linux, SSH, Nginx, and MySQL. Implements CIS benchmark-aligned settings. This is the gold standard for automated server hardening.

**Available roles:**
| Role | What it hardens |
|------|----------------|
| `devsec.hardening.os_hardening` | Kernel params (sysctl), file permissions, user config, PAM, auditd, service disabling, filesystem mounts |
| `devsec.hardening.ssh_hardening` | SSH ciphers, MACs, key exchange algorithms, authentication settings, port, login restrictions |
| `devsec.hardening.nginx_hardening` | Nginx security config, headers, SSL settings, directory listing, server tokens |
| `devsec.hardening.mysql_hardening` | MySQL/MariaDB security settings |

**How it maps to this repo's docs:**

| This Repo's Doc | dev-sec Role |
|-----------------|-------------|
| 01 - SSH Hardening | `ssh_hardening` — covers everything in doc 01 plus cipher/MAC/KEX hardening |
| 02 - Firewall | Not covered (firewall is considered deployment-specific) |
| 02 - Fail2Ban | Not covered |
| 03 - Software Installation | Not covered (not a hardening concern) |
| 04 - Nginx & Let's Encrypt | `nginx_hardening` — covers security config, not SSL cert provisioning |

**What dev-sec adds beyond this repo:**
- Kernel sysctl hardening (IP forwarding, SYN cookies, ICMP, etc.)
- File permission lockdown (/etc/shadow, /etc/gshadow, etc.)
- PAM configuration hardening
- Login.defs (password policies)
- Core dump restrictions
- Disable unused filesystems and network protocols
- SSH cipher suite hardening (goes far beyond what doc 01 covers)

**Verdict:** **Highly recommended** as the automation backbone. Covers most of the OS-level gaps in this repo. Can be combined with custom Ansible roles for UFW, Fail2Ban, and Certbot.

---

#### konstruktoid/hardening

| | |
|---|---|
| **URL** | [github.com/konstruktoid/hardening](https://github.com/konstruktoid/hardening) |
| **Stars** | ~500+ |
| **Language** | Bash |
| **License** | Apache 2.0 |
| **Maintained** | Yes — tested on Ubuntu 22.04 and 24.04 |

**What it does:** Comprehensive bash script (`ubuntu.sh`) that hardens Ubuntu servers following CIS guidelines. Includes ~760 Bats tests. Covers sysctl, AppArmor, auditd, disabling services, filesystem hardening, PAM, and much more.

**Key features:**
- Single-script hardening (read config, run script)
- Integrates Lynis and OpenSCAP CIS scans in its test suite
- Covers kernel, filesystem, network, authentication, logging
- Not idempotent (run once, or use the companion Ansible role)

**Verdict:** Good reference implementation. The bash approach is simple but risky for production (not idempotent). Better to use the Ansible equivalent for repeatable setups, but the script is excellent for understanding what CIS hardening actually involves.

---

#### JShielder

| | |
|---|---|
| **URL** | [github.com/Jsitech/JShielder](https://github.com/Jsitech/JShielder) |
| **Stars** | ~700+ |
| **Language** | Bash |
| **License** | GPL v3 |
| **Maintained** | Limited — last significant updates for Ubuntu 18.04 |

**What it does:** Interactive bash script that creates admin users, generates SSH keys, configures iptables, installs and configures ModSecurity for Apache/Nginx, and applies CIS benchmark hardening.

**Verdict:** **Outdated** — last tested on Ubuntu 18.04. Not recommended for Ubuntu 24.10. Useful as a reference for what a comprehensive hardening script covers, but don't run it on modern systems.

---

#### ansible-lockdown/UBUNTU24-CIS

| | |
|---|---|
| **URL** | [github.com/ansible-lockdown](https://github.com/ansible-lockdown) |
| **Language** | Ansible |
| **Maintained** | Yes — community maintained with CIS benchmark updates |

**What it does:** Ansible playbooks that implement CIS Benchmarks for specific Ubuntu versions. Highly configurable — toggle individual benchmark items on/off.

**Verdict:** Excellent if you need strict CIS compliance. More granular than dev-sec but also more complex to configure. Good complement to dev-sec.

---

### 3.3 Intrusion Prevention & Detection

#### CrowdSec

| | |
|---|---|
| **URL** | [crowdsec.net](https://www.crowdsec.net/) / [github.com/crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec) |
| **Stars** | ~9k+ |
| **Language** | Go |
| **License** | MIT |
| **Maintained** | Very active |
| **Install** | `curl -s https://install.crowdsec.net \| sudo sh && sudo apt install crowdsec crowdsec-firewall-bouncer-iptables` |

**What it does:** Modern, community-driven intrusion prevention system. Parses logs, detects attacks using behavior-based scenarios, and blocks offending IPs. Its killer feature: **crowdsourced IP reputation** — when any CrowdSec instance detects an attacking IP, that intelligence is shared with the entire network.

**CrowdSec vs Fail2Ban (detailed comparison):**

| Feature | Fail2Ban | CrowdSec |
|---------|----------|----------|
| **Architecture** | Monolithic Python | Modular Go (engine + bouncers) |
| **Detection** | Regex-based jails | Behavior-based YAML scenarios |
| **IP reputation** | Local only | Crowdsourced global blocklist |
| **Performance** | Slower on large logs | Significantly faster (Go vs Python) |
| **Dashboard** | CLI only | Web console (free cloud tier) |
| **Scalability** | Struggles with 1000s of rules | Uses IP sets (handles millions) |
| **Remediation** | Direct iptables/ufw | Pluggable "bouncers" (firewall, nginx, Cloudflare, etc.) |
| **API** | No | Full REST API |
| **IPv6** | Limited | Full support |
| **Container-aware** | No | Yes |
| **Resource usage** | Very low | Low-moderate |
| **Maturity** | 20+ years, proven | 5 years, rapidly maturing |

**When to use which:**
- **Fail2Ban** remains optimal for resource-constrained VPS (512MB RAM), simple deployments, and proven reliability
- **CrowdSec** shines for public-facing servers, multi-service protection, and when community threat intelligence matters
- **Both together** is valid — Fail2Ban for SSH (simple, proven), CrowdSec for web services (better detection, community intel)

**Installation:**
```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec -y
sudo apt install crowdsec-firewall-bouncer-iptables -y

# Install collections for your services
sudo cscli collections install crowdsecurity/sshd
sudo cscli collections install crowdsecurity/nginx
sudo cscli collections install crowdsecurity/linux

# Verify
sudo cscli decisions list
sudo cscli metrics
```

**Verdict:** **Strongly recommended** as a complement or replacement for Fail2Ban. The community blocklist alone makes it worth installing — you get protection from known malicious IPs before they even attack you.

---

#### OSSEC / Wazuh

| | |
|---|---|
| **OSSEC URL** | [ossec.net](https://www.ossec.net/) |
| **Wazuh URL** | [wazuh.com](https://wazuh.com/) (OSSEC fork, more actively developed) |
| **Type** | Host-based Intrusion Detection System (HIDS) |

**What they do:** Monitor logs, detect anomalies, perform file integrity monitoring, rootkit detection, and active response (auto-blocking). Wazuh adds vulnerability detection, compliance dashboards, and Elasticsearch/Kibana integration.

| | OSSEC | Wazuh |
|---|---|---|
| Resource usage | Low-moderate | Moderate-high (needs Elasticsearch) |
| Setup complexity | Moderate | High |
| Best for single VPS | Good | Overkill |
| Active development | Slow | Very active |

**Verdict:** For a single VPS, OSSEC is a good all-in-one HIDS (includes FIM + rootkit detection + log analysis). Wazuh is best for fleets of servers. For a simpler setup, use individual tools (CrowdSec + AIDE + rkhunter).

---

#### Suricata

| | |
|---|---|
| **URL** | [suricata.io](https://suricata.io/) |
| **Type** | Network IDS/IPS |

**What it does:** Deep packet inspection of network traffic. Detects network-level attacks using rule sets (Emerging Threats).

**Verdict:** High resource usage and complex to manage. **Not recommended for a typical single VPS** unless you specifically need network-level intrusion detection. CrowdSec covers most practical use cases with far less overhead.

---

### 3.4 File Integrity & Rootkit Detection

#### AIDE (Advanced Intrusion Detection Environment)

| | |
|---|---|
| **Install** | `sudo apt install aide -y` |
| **License** | GPL |

**What it does:** Creates a database of file checksums, permissions, and attributes. On subsequent runs, reports any changes. Detects unauthorized modifications to system files, configs, and binaries.

**Setup:**
```bash
sudo apt install aide -y
sudo aideinit                    # Build initial database (takes a few minutes)
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo aide --check                # Compare current state to database
```

**Verdict:** Essential for detecting unauthorized changes. Lightweight and straightforward. Should be run on a schedule (daily cron job) and the database updated after legitimate changes.

---

#### rkhunter & chkrootkit

| Tool | Install | What it detects |
|------|---------|----------------|
| rkhunter | `sudo apt install rkhunter -y` | Rootkits, backdoors, local exploits, suspicious files |
| chkrootkit | `sudo apt install chkrootkit -y` | Known rootkits, suspicious modifications to system binaries |

**Setup:**
```bash
sudo apt install rkhunter chkrootkit -y
sudo rkhunter --update
sudo rkhunter --propupd          # Set baseline
sudo rkhunter --check            # Scan
sudo chkrootkit                  # Quick rootkit scan
```

**Verdict:** Low effort, low overhead. Not bulletproof (a sophisticated attacker can evade them), but catches common rootkits and serves as a basic tripwire. Worth installing and running weekly via cron.

---

### 3.5 Mandatory Access Control

#### AppArmor

| | |
|---|---|
| **Pre-installed** | Yes — Ubuntu ships with AppArmor enabled |
| **License** | GPL |

**What it does:** Confines programs to a limited set of resources. Even if a service is compromised, AppArmor limits what the attacker can access.

**Current state on Ubuntu 24.10:**
```bash
sudo aa-status     # Shows loaded profiles and their enforcement mode
```

Ubuntu ships with profiles for common services (MySQL, Nginx, etc.) in `/etc/apparmor.d/`. Many are in "complain" mode (logs violations but doesn't block them).

**Action items:**
1. Check which profiles are loaded: `sudo aa-status`
2. Move profiles from complain to enforce mode: `sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx`
3. For custom applications, generate profiles with `aa-genprof`

**Verdict:** Already installed — just needs to be configured. Low-hanging fruit for additional security.

---

## 4. Tool-to-Repo Mapping: What Each Tool Covers vs Our Docs

This matrix shows which tools address which hardening areas, compared to what this repo already documents.

| Hardening Area | This Repo | Lynis | dev-sec Ansible | OpenSCAP | CrowdSec | konstruktoid |
|---|---|---|---|---|---|---|
| System updates | 01 | Audit | - | Audit | - | Apply |
| Unattended upgrades | 01 | Audit | - | Audit | - | Apply |
| Non-root user | 01 | Audit | Apply | Audit | - | Apply |
| SSH key auth | 01 | Audit | Apply | Audit | - | Apply |
| SSH port change | 01 | Audit | Apply | - | - | Apply |
| Disable password auth | 01 | Audit | Apply | Audit | - | Apply |
| Disable root login | 01 | Audit | Apply | Audit | - | Apply |
| SSH cipher hardening | Partial (04) | Audit | Apply | Audit | - | Apply |
| UFW firewall | 02 | Audit | - | Audit | - | Apply |
| Fail2Ban | 02 | Audit | - | - | Replace | - |
| Nginx config | 04 | Audit | Apply | - | - | - |
| SSL/TLS | 04 | Audit | - | - | - | - |
| Security headers | 04 | Audit | Apply | - | - | - |
| **Kernel hardening** | **Missing** | Audit | Apply | Audit | - | Apply |
| **auditd** | **Missing** | Audit | Apply | Audit | - | Apply |
| **File integrity** | **Missing** | Audit | - | Audit | - | Apply |
| **Rootkit detection** | **Missing** | Audit | - | - | - | Apply |
| **AppArmor** | **Missing** | Audit | - | Audit | - | Apply |
| **2FA for SSH** | **Missing** | - | - | - | - | - |
| **Shared memory** | **Missing** | Audit | Apply | Audit | - | Apply |
| **Service hardening** | **Missing** | Audit | Apply | Audit | - | Apply |
| **Docker hardening** | **Missing** | Audit | - | - | - | - |
| **Log management** | **Missing** | Audit | - | Audit | - | Apply |

**Key takeaway:** Lynis audits almost everything. dev-sec Ansible applies most OS-level hardening. CrowdSec addresses intrusion prevention. The combination of **Lynis (audit) + dev-sec Ansible (apply) + CrowdSec (protect)** covers the vast majority of hardening needs.

---

## 5. Gap Analysis: What's Missing From This Repo

### 5.1 Kernel Hardening (sysctl)

**Priority: HIGH | Effort: 5 minutes**

The Linux kernel has many tunable parameters that are insecure by default. Adding sysctl settings is one of the highest-impact, lowest-effort hardening steps.

**Recommended `/etc/sysctl.d/99-hardening.conf`:**

```ini
# ── Network Hardening ──

# Enable SYN cookies (protects against SYN flood attacks)
net.ipv4.tcp_syncookies = 1

# Disable IP forwarding (unless running as a router/VPN)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects (prevents MITM routing attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing (prevents IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts (prevents Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Memory / Process Hardening ──

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Restrict ptrace (process tracing) — limits debugging to direct children
kernel.yama.ptrace_scope = 1

# Disable core dumps for SUID programs
fs.suid_dumpable = 0

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# ── Filesystem Hardening ──

# Restrict access to kernel logs
kernel.printk = 3 3 3 3

# Harden BPF JIT compiler
net.core.bpf_jit_harden = 2

# Restrict unprivileged user namespaces (reduces container escape surface)
kernel.unprivileged_userns_clone = 0

# Disable magic SysRq key
kernel.sysrq = 0
```

**Apply:**
```bash
sudo sysctl -p /etc/sysctl.d/99-hardening.conf
```

> **Note:** If running Docker, keep `net.ipv4.ip_forward = 1` (Docker requires it). Also, `kernel.unprivileged_userns_clone = 0` may break some container workloads.

---

### 5.2 Audit Logging (auditd)

**Priority: MEDIUM | Effort: 15 minutes**

auditd is the Linux audit framework. It logs security-relevant events: file access, command execution, authentication, privilege escalation, and system changes. Essential for forensics and compliance.

**Setup:**
```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Recommended rules in `/etc/audit/rules.d/hardening.rules`:**
```
# Monitor changes to authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor firewall changes
-w /etc/ufw/ -p wa -k firewall

# Log all commands run as root (via sudo)
-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd

# Log failed access attempts
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -k access_denied

# Monitor Docker socket
-w /var/run/docker.sock -p rwxa -k docker

# Monitor cron changes
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# Make audit config immutable (requires reboot to change)
-e 2
```

**Load rules:**
```bash
sudo augenrules --load
```

**Query audit logs:**
```bash
sudo ausearch -k identity --interpret     # Show identity-related events
sudo aureport --summary                   # Summary report
sudo aureport --auth                      # Authentication report
```

---

### 5.3 File Integrity Monitoring (AIDE)

**Priority: MEDIUM | Effort: 10 minutes**

AIDE creates a database of file checksums. On subsequent checks, it reports any changes — catching unauthorized modifications to system files, binaries, and configurations.

**Setup:**
```bash
sudo apt install aide -y
sudo aideinit                              # Build initial database
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**Daily scan via cron:**
```bash
echo '0 5 * * * root /usr/bin/aide --check | mail -s "AIDE Report" you@example.com' | sudo tee /etc/cron.d/aide-check
```

**After legitimate changes** (package updates, config changes):
```bash
sudo aide --update
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

### 5.4 Rootkit Detection

**Priority: LOW-MEDIUM | Effort: 5 minutes**

```bash
sudo apt install rkhunter chkrootkit -y
sudo rkhunter --update && sudo rkhunter --propupd
sudo rkhunter --check --sk                 # --sk skips interactive prompts
sudo chkrootkit
```

**Weekly scan via cron:**
```bash
echo '0 3 * * 0 root /usr/bin/rkhunter --check --sk --report-warnings-only | mail -s "rkhunter Report" you@example.com' | sudo tee /etc/cron.d/rkhunter
```

---

### 5.5 AppArmor Profiles

**Priority: MEDIUM | Effort: 10 minutes**

Ubuntu ships with AppArmor enabled. The action item is ensuring profiles are in **enforce** mode, not complain mode.

```bash
# Check current status
sudo aa-status

# Enforce all loaded profiles
sudo aa-enforce /etc/apparmor.d/*

# Install additional profiles
sudo apt install apparmor-profiles apparmor-profiles-extra -y
sudo aa-enforce /etc/apparmor.d/*

# For custom applications, generate a profile
sudo aa-genprof /usr/local/bin/myapp
```

---

### 5.6 Two-Factor Authentication for SSH

**Priority: MEDIUM | Effort: 15 minutes**

Adding TOTP to SSH means an attacker needs both your SSH key AND your phone.

**Setup:**
```bash
sudo apt install libpam-google-authenticator -y

# Run as the deploy user:
google-authenticator
# Scan the QR code with your authenticator app
# Save the emergency scratch codes
```

**Configure PAM** — add to `/etc/pam.d/sshd`:
```
auth required pam_google_authenticator.so nullok
```

**Configure SSH** — add to `/etc/ssh/sshd_config.d/00-hardening.conf`:
```
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

> **Important:** The comma in `publickey,keyboard-interactive` means BOTH are required. A space would mean either/or.

```bash
sudo sshd -t && sudo systemctl restart ssh.service
```

**Alternative:** For hardware security keys (YubiKey), SSH 8.2+ supports FIDO2 natively:
```bash
ssh-keygen -t ed25519-sk -C "your_email@example.com"
```

---

### 5.7 CrowdSec (Modern Fail2Ban Alternative)

**Priority: HIGH | Effort: 15 minutes**

See the detailed comparison in [Section 3.3](#crowdsec). Key advantages over Fail2Ban:

1. **Community blocklist** — preemptive blocking of known malicious IPs
2. **Written in Go** — faster log processing
3. **Modular bouncers** — block at firewall, Nginx, or Cloudflare level
4. **Better scalability** — IP sets instead of individual iptables rules

**Quick setup:**
```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec crowdsec-firewall-bouncer-iptables -y
sudo cscli collections install crowdsecurity/sshd
sudo cscli collections install crowdsecurity/nginx
sudo cscli collections install crowdsecurity/linux
sudo cscli decisions list
```

**Can coexist with Fail2Ban** — they don't conflict as long as they monitor different log files, or you can fully replace Fail2Ban.

---

### 5.8 Docker-Specific Hardening

**Priority: MEDIUM | Effort: 20 minutes**

Doc 03 covers Docker installation but not security. Key hardening steps:

**1. Daemon configuration** — `/etc/docker/daemon.json`:
```json
{
  "icc": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false
}
```

- `icc: false` — disables inter-container communication (require explicit networks)
- `no-new-privileges: true` — prevents privilege escalation inside containers
- `userland-proxy: false` — uses iptables instead of proxy process

**2. Container runtime security:**
```bash
# Drop all capabilities, add only what's needed
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx

# Read-only root filesystem
docker run --read-only --tmpfs /tmp --tmpfs /run nginx

# Resource limits
docker run --memory=512m --cpus=1.0 --pids-limit=100 \
  --security-opt=no-new-privileges:true nginx
```

**3. Don't run as root inside containers** — use `USER` directive in Dockerfiles.

**4. Network isolation:**
```bash
docker network create --internal backend    # No outbound internet
docker network create frontend              # External-facing
```

---

### 5.9 Secure Shared Memory (/dev/shm, /tmp)

**Priority: HIGH | Effort: 2 minutes**

Attackers commonly stage exploits in world-writable directories.

**Add to `/etc/fstab`:**
```
tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0
```

**Apply without reboot:**
```bash
sudo mount -o remount /dev/shm
```

> **Caveat:** Adding `noexec` to `/tmp` may break some package installations. If needed, temporarily remount: `sudo mount -o remount,exec /tmp`.

---

### 5.10 Disable Unnecessary Services

**Priority: MEDIUM-HIGH | Effort: 10 minutes**

```bash
# Audit what's running
systemctl list-units --type=service --state=running
sudo ss -tulnp

# Common services to disable on a VPS
sudo systemctl disable --now avahi-daemon 2>/dev/null   # mDNS (not needed)
sudo systemctl disable --now cups 2>/dev/null           # Printing
sudo systemctl disable --now bluetooth 2>/dev/null      # Bluetooth
sudo systemctl disable --now ModemManager 2>/dev/null   # Modem
sudo systemctl disable --now rpcbind 2>/dev/null        # NFS-related

# Disable unused kernel modules
cat <<EOF | sudo tee /etc/modprobe.d/disable-unused.conf
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF
```

After cleanup, verify only expected ports are listening:
```bash
sudo ss -tulnp
# Should only show: sshd (2222), nginx (80, 443), and internal services (127.0.0.1)
```

---

### 5.11 Log Management & Monitoring

**Priority: MEDIUM | Effort: 15 minutes**

**journald configuration** — `/etc/systemd/journald.conf`:
```ini
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=2week
Compress=yes
ForwardToSyslog=yes
```

**Logwatch for daily email summaries:**
```bash
sudo apt install logwatch -y
# Configure in /etc/logwatch/conf/logwatch.conf
# Daily email with auth failures, disk usage, service status
```

**Log file permissions:**
```bash
sudo chmod 640 /var/log/auth.log
sudo chmod 640 /var/log/syslog
```

---

### 5.12 Network Hardening Beyond UFW

**Priority: MEDIUM | Effort: 5 minutes**

Beyond UFW rules, these network-level settings improve security:

- **TCP SYN cookies** — covered in sysctl (Section 5.1)
- **Disable IPv6 if not used:**
  ```ini
  # In /etc/sysctl.d/99-hardening.conf
  net.ipv6.conf.all.disable_ipv6 = 1
  net.ipv6.conf.default.disable_ipv6 = 1
  ```
- **DNS over TLS** — configure systemd-resolved to use DoT:
  ```ini
  # /etc/systemd/resolved.conf
  [Resolve]
  DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
  DNSOverTLS=yes
  ```

---

## 6. Automation Strategy: Should We Automate This Repo?

### 6.1 Automation Approaches Compared

| Approach | Idempotent | Readable | Testable | Learning Curve | Best For |
|----------|-----------|----------|----------|---------------|----------|
| **Ansible playbook** | Yes | Very (YAML) | Yes (Molecule) | Medium | Repeatable server config |
| **Bash script** | No (risky) | Medium | Hard | Low | One-off setups |
| **Cloud-init** | Partial | YAML | Limited | Low | First-boot provisioning |
| **Terraform + provisioner** | Infra only | HCL | Yes | High | Infrastructure + initial config |
| **Packer** | N/A (images) | JSON/HCL | Yes | Medium | Golden image creation |

### 6.2 What to Automate vs Keep Manual

| Task | Automate? | Why |
|------|-----------|-----|
| System updates | Yes | Safe, repeatable |
| User creation | Yes | Standard across servers |
| SSH hardening | Yes | Well-defined config files |
| UFW rules | Yes | Declarative, low risk |
| Fail2Ban / CrowdSec | Yes | Standard config |
| sysctl hardening | Yes | File-based, no interaction needed |
| AppArmor enforcement | Yes | Simple state change |
| Docker installation | Yes | Well-documented process |
| Docker hardening | Yes | Config files |
| Nginx config | Partially | Templates work for standard setups, but site-specific config needs manual attention |
| Certbot SSL | Partially | Domain names are deployment-specific; initial run needs interaction |
| SSH key deployment | No | Keys are per-user, per-machine |
| 2FA setup | No | Requires interactive QR code scanning |
| AIDE initial database | Partially | Auto-install, but database should be created after all changes are done |

### 6.3 Recommended Approach

**Primary: Ansible playbook** using a combination of:

1. **dev-sec Ansible collection** (`devsec.hardening`) for OS and SSH hardening
2. **Custom roles** for what dev-sec doesn't cover:
   - UFW firewall rules
   - Fail2Ban / CrowdSec setup
   - Docker installation + daemon hardening
   - Nginx + Certbot
   - AIDE, rkhunter, auditd
   - Log management

**Proposed playbook structure:**
```
ansible/
├── inventory/
│   └── hosts.yml
├── group_vars/
│   └── all.yml              # Variables (SSH port, username, domain, etc.)
├── playbook.yml              # Main playbook
└── roles/
    ├── base/                 # System updates, timezone, user creation
    ├── firewall/             # UFW configuration
    ├── crowdsec/             # CrowdSec installation + collections
    ├── docker/               # Docker CE + daemon hardening
    ├── nginx/                # Nginx + Certbot
    ├── monitoring/           # AIDE, rkhunter, auditd, logwatch
    └── hardening/            # sysctl, shared memory, disable services, AppArmor
```

**Example usage:**
```bash
# First run (full setup)
ansible-playbook -i inventory/hosts.yml playbook.yml

# Re-run after changes (idempotent)
ansible-playbook -i inventory/hosts.yml playbook.yml

# Run only specific roles
ansible-playbook -i inventory/hosts.yml playbook.yml --tags firewall,crowdsec
```

**Secondary: Keep the current docs as-is** — they serve as an excellent learning resource and manual fallback. The Ansible playbook should reference the docs for context and explanations.

**Tertiary: Add a Lynis verification step** — after running the playbook, run Lynis and include the score in the output. This validates that the hardening was applied correctly.

---

## 7. Prioritized Recommendations

### Immediate (add to repo docs)

| # | Action | Impact | Effort | New Doc? |
|---|--------|--------|--------|----------|
| 1 | Add kernel hardening (sysctl) to doc 02 or new doc 05 | High | 5 min | Section in existing or new |
| 2 | Add shared memory hardening | High | 2 min | Section in new doc |
| 3 | Add "disable unnecessary services" guidance | Medium-High | 10 min | Section in new doc |
| 4 | Document CrowdSec as alternative/complement to Fail2Ban | High | 15 min | Section in doc 02 or new doc |
| 5 | Add Docker hardening to doc 03 | Medium | 10 min | Section in doc 03 |
| 6 | Add Lynis as a verification step | High | 5 min | Section in new doc |

### Short-term (new documentation)

| # | Action | Impact | Effort |
|---|--------|--------|--------|
| 7 | Add auditd setup guide | Medium | 15 min |
| 8 | Add AIDE setup guide | Medium | 10 min |
| 9 | Add AppArmor enforcement guide | Medium | 10 min |
| 10 | Add 2FA for SSH guide | Medium | 15 min |
| 11 | Add log management guide | Medium | 15 min |

### Medium-term (automation)

| # | Action | Impact | Effort |
|---|--------|--------|--------|
| 12 | Create Ansible playbook automating all steps | High | 2-4 hours |
| 13 | Integrate dev-sec Ansible collection | High | 1 hour |
| 14 | Add Lynis + OpenSCAP as automated verification | Medium | 1 hour |
| 15 | Add CI pipeline to test playbook against Vagrant/Docker | Medium | 2 hours |

### Suggested new document structure

```
docs/
├── 01-initial-setup-ssh-hardening.md     (existing)
├── 02-firewall-fail2ban.md               (existing — add CrowdSec section)
├── 03-software-installation.md           (existing — add Docker hardening)
├── 04-nginx-letsencrypt.md               (existing)
├── 05-os-hardening.md                    (NEW — sysctl, shared memory, services, AppArmor)
├── 06-monitoring-detection.md            (NEW — auditd, AIDE, rkhunter, log management)
├── 07-2fa-ssh.md                         (NEW — TOTP and FIDO2)
├── 08-verification.md                    (NEW — Lynis, OpenSCAP, manual checks)
└── quick-checklist.md                    (existing — extend with new sections)
```

---

## 8. Sources

### Tools
- [Lynis - CISOfy](https://cisofy.com/lynis/) | [GitHub](https://github.com/CISOfy/lynis)
- [OpenSCAP](https://www.open-scap.org/) | [Ubuntu 24.04 guide](https://www.server-world.info/en/note?os=Ubuntu_24.04&p=openscap)
- [dev-sec Ansible Collection](https://github.com/dev-sec/ansible-collection-hardening)
- [konstruktoid/hardening](https://github.com/konstruktoid/hardening)
- [JShielder](https://github.com/Jsitech/JShielder)
- [CrowdSec](https://www.crowdsec.net/) | [GitHub](https://github.com/crowdsecurity/crowdsec)
- [OSSEC](https://www.ossec.net/)
- [Wazuh](https://wazuh.com/)
- [Suricata](https://suricata.io/)
- [AIDE](https://aide.github.io/)
- [ansible-lockdown](https://github.com/ansible-lockdown)

### Comparisons & Guides
- [Fail2Ban vs CrowdSec on VPS in 2025](https://onidel.com/blog/fail2ban-vs-crowdsec-vps-2025)
- [CrowdSec – not your typical Fail2Ban clone](https://www.crowdsec.net/blog/crowdsec-not-your-typical-fail2ban-clone)
- [Beyond Fail2ban: CrowdSec with Collective Intelligence](https://medium.com/@sriranjankapilan/beyond-fail2ban-how-crowdsec-revolutionizes-vm-server-security-with-collective-intelligence-1a9f5fd25def)
- [CrowdSec vs Fail2Ban: Modern Intrusion Prevention](https://selfhostedguides.com/crowdsec-vs-fail2ban/)
- [A CrowdSec Primer - Daniel Miessler](https://danielmiessler.com/blog/crowdsec)
- [Automating CIS Compliance with OpenSCAP on Ubuntu](https://ericmorrish.com/blog/automating-cis-compliance-with-openscap-on-ubuntu-server/)
- [CIS Hardening Ubuntu 24.04 LTS VPS](https://onidel.com/blog/cis-hardening-ubuntu-ansible)
- [Automate Compliance Using OpenSCAP and Ubuntu Security Guide](https://greponsecurity.com/posts/automate-compliance-and-security-hardening-using-openscap-and-ubuntu-security-guide/)
- [How to Run OpenSCAP Compliance Scans on Ubuntu](https://oneuptime.com/blog/post/2026-01-15-run-openscap-compliance-scans-ubuntu/view)
- [CIS Benchmarks for Ubuntu](https://www.cisecurity.org/benchmark/ubuntu_linux)
