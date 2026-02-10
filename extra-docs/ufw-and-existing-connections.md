# UFW and Existing SSH Connections

## Does `ufw default deny incoming` kill my SSH session?

**No.** Setting the default policy does not affect existing connections.

UFW (via iptables/nftables) automatically includes rules for `ESTABLISHED` and `RELATED` traffic. Your current SSH session is an already-established TCP connection tracked by the kernel's conntrack module — it stays alive regardless of the default policy.

## The actual danger

The risk is not the `default deny` command — it's enabling UFW **without first adding an allow rule for your SSH port**:

```bash
# SAFE order:
sudo ufw default deny incoming     # no effect yet, firewall not active
sudo ufw default allow outgoing    # no effect yet
sudo ufw allow 2222/tcp            # allow SSH BEFORE enabling
sudo ufw enable                    # now active — SSH is allowed

# DANGEROUS order:
sudo ufw default deny incoming
sudo ufw enable                    # SSH is now blocked!
# Your session stays alive, but if it drops you can't reconnect
```

## What happens if you get locked out

Your current session survives, but:
- If your connection drops (network blip, timeout, reboot), you **cannot reconnect**
- Fix it via your VPS provider's web console (VNC/KVM)

Recovery from the web console:

```bash
sudo ufw allow 2222/tcp
sudo ufw status
```

Or disable UFW entirely to regain access:

```bash
sudo ufw disable
```

## Quick safety checklist

1. Add your SSH port rule **before** running `ufw enable`
2. Keep an existing session open while enabling
3. Test from a **new terminal** before closing the old one
4. Know where your VPS provider's web console is — just in case
