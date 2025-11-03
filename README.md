# Ubuntu From Scratch

Automated Ubuntu server setup script with security hardening and essential tooling.

## What It Does

This idempotent script configures a fresh Ubuntu instance with:

- **Security hardening**: SSH key-only auth, custom SSH port, UFW firewall, fail2ban
- **System configuration**: hostname, timezone, swap file, non-root user with sudo
- **Essential software**: curl, git, vim, htop, tmux, wireguard, and more
- **Monitoring tools**: sysstat, vnstat for system and network monitoring
- **Log management**: automated log rotation
- **Optional**: unattended security updates, email notifications via SMTP

The script validates all configuration before execution and can be safely run multiple times.

## Quick Start

1. **Copy the example configuration**:
    ```bash
    cp instance.conf.example instance.conf
    ```

2. **Edit `instance.conf` and set required values**:
    ```bash
    vim instance.conf
    ```

    **Required settings** (marked with `[*]` in config):
    - `HOSTNAME` - Your server hostname
    - `TIMEZONE` - e.g., "UTC", "America/New_York"
    - `NEW_USER` - Non-root username to create
    - `NEW_USER_PASSWORD` - Secure password
    - `SSH_PUBLIC_KEY` - Your SSH public key (get with `cat ~/.ssh/id_ed25519.pub`)
    - `SSH_PORT` - Non-standard SSH port (e.g., 22222)

3. **Run setup as root**:
    ```bash
    chmod +x setup.sh
    sudo ./setup.sh instance.conf
    ```

4. **Test SSH access** (in a NEW terminal, keep root session open!):
    ```bash
    ssh -p 22222 your-user@server-ip
    ```

## Example Configuration

### Minimal Setup
```bash
HOSTNAME="webserver"
TIMEZONE="UTC"
NEW_USER="admin"
NEW_USER_PASSWORD="ChangeMe123!"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFoo..."
SSH_PORT=22222
```

### Production Setup with Monitoring
```bash
HOSTNAME="prod-api"
TIMEZONE="America/New_York"
NEW_USER="deploy"
NEW_USER_PASSWORD="SecurePassword123!"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFoo..."
SSH_PORT=2222
SWAP_SIZE_MB=4096
SWAPPINESS=10
ADDITIONAL_PACKAGES="postgresql-client redis-tools"
ADDITIONAL_PORTS="80/tcp 443/tcp"
ENABLE_FAIL2BAN=true
ENABLE_UNATTENDED_UPDATES=true
ENABLE_EMAIL_NOTIFICATIONS=true
NOTIFICATION_EMAIL="ops@example.com"
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="alerts@example.com"
SMTP_PASSWORD="app_password_here"
```

## What Gets Installed

**Core packages** (always installed):
- System tools: curl, wget, git, vim, htop, net-tools, ncdu, jq, tmux, tree, unzip
- Security: ufw, fail2ban
- Monitoring: sysstat, vnstat
- Updates: unattended-upgrades, apt-listchanges
- Email: msmtp, msmtp-mta, mailutils
- Networking: wireguard

**Additional packages**: Configurable via `ADDITIONAL_PACKAGES`

## Configuration Options

### System Settings
- `HOSTNAME` - Server hostname
- `TIMEZONE` - System timezone (see `/usr/share/zoneinfo/`)
- `SWAP_SIZE_MB` - Swap file size in MB (0 to disable, default: 2048)
- `SWAPPINESS` - Kernel swappiness 0-100 (default: 10)
- `DISABLE_SNAPD` - Remove snapd (default: true)

### User Setup
- `NEW_USER` - Username for non-root account
- `NEW_USER_PASSWORD` - Password for the user
- `NEW_USER_GROUPS` - Additional groups, comma-separated (default: "sudo")
- `SSH_PUBLIC_KEY` - SSH public key for key-based authentication

### Security & Firewall
- `SSH_PORT` - Custom SSH port (default: 22222)
- `WIREGUARD_PORT` - WireGuard VPN port if used (default: 51820)
- `ADDITIONAL_PORTS` - Extra ports to open (e.g., "80 443 8080")
- `ENABLE_FAIL2BAN` - Enable brute-force protection (default: true)
- `FAIL2BAN_BANTIME` - Ban duration in seconds (default: 3600)
- `FAIL2BAN_MAXRETRY` - Max failed attempts (default: 5)

### Optional Features
- `ENABLE_UNATTENDED_UPDATES` - Auto security updates (default: false)
- `UNATTENDED_UPDATES_EMAIL` - Email for update notifications
- `ENABLE_EMAIL_NOTIFICATIONS` - Enable SMTP email (default: false)
- `NOTIFICATION_EMAIL` - Where to send notifications
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` - SMTP settings

## Security Features

### SSH Hardening (setup.sh:433-498)
- Root login disabled
- Password authentication disabled (keys only)
- Modern ciphers and key exchange algorithms
- Custom port (reduces automated attacks)
- Configuration validated before restart

### Firewall (setup.sh:500-539)
- Default deny incoming, allow outgoing
- SSH port automatically allowed
- Additional ports configurable
- UFW enabled automatically

### Fail2ban (setup.sh:562-626)
- Protects SSH from brute-force attacks
- Configurable ban time and retry limits
- DDoS protection for SSH connections
- Automatic IP banning

## Post-Setup Commands

### Check System Status
```bash
# Firewall status
sudo ufw status verbose

# Fail2ban status
sudo fail2ban-client status sshd

# System monitoring
sar          # CPU usage
vnstat       # Network traffic
htop         # Live system monitor
```

### Manage Services
```bash
# Check SSH configuration
sudo sshd -t

# View setup log
sudo tail -f /var/log/$HOSTNAME-setup.log

# Check unattended upgrades
sudo tail -f /var/log/unattended-upgrades/unattended-upgrades.log

# Unban an IP from fail2ban
sudo fail2ban-client set sshd unbanip 1.2.3.4
```

## Logs

- Setup log: `/var/log/$HOSTNAME-setup.log`
- Fail2ban: `/var/log/fail2ban.log`
- MSMTP email: `/var/log/msmtp.log`
- SSH auth: `/var/log/auth.log`

## Important Notes

⚠️ **Always test SSH access in a new terminal before closing your root session!**

⚠️ **Save your SSH private key securely - you cannot login without it**

⚠️ **Keep instance.conf secure - it contains passwords and keys**

## Requirements

- Fresh Ubuntu instance (tested on Ubuntu 22.04+)
- Root access
- Internet connectivity
- Valid SSH public key

## Troubleshooting

**Cannot connect after setup:**
0. Check if it's something obvious (try `ssh -vvv ...` with all params explicitly on command line)
1. Check provider's firewall, new $SSH_PORT might be closed by provider (this solved `connection timed out` ssh error)
2. Reset instance (this solved `route not found` ssh error)

**Script fails:**
- Check `/var/log/$HOSTNAME-setup.log` for errors
- Script is idempotent - fix the issue and run again
