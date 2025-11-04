#!/bin/sh
#
# Ubuntu Instance Setup Script
# Copyright (c) 2025 Branislav Anovic
# Licensed under the MIT License
#
# Configures a fresh Ubuntu instance with security hardening and common tools.
# Must be run as root.
# This script is idempotent and can be safely run multiple times (with same config file, or with gradually more specific configurations).
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${1:-${SCRIPT_DIR}/instance.conf}"  # Use first argument or default

# Logging functions. Logs in LOG_FILE (setup in config) and to stdout
log_info() {
    echo "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')][INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')][SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')][WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "${RED}[$(date '+%Y-%m-%d %H:%M:%S')][ERROR]${NC} $*" | tee -a "$LOG_FILE"
}


# Validate configuration
validate_config() {
    log_info "[validate_config] Validating configuration..."
    
    # Check required variables
    if [ -z "$HOSTNAME" ]; then
        log_error "[validate_config] HOSTNAME is not set in configuration"
        exit 1
    fi
    
    if [ -z "$TIMEZONE" ]; then
        log_error "[validate_config] TIMEZONE is not set in configuration"
        exit 1
    fi
    
    if [ -z "$NEW_USER" ]; then
        log_error "[validate_config] NEW_USER is not set in configuration"
        exit 1
    fi
    
    if [ -z "$NEW_USER_PASSWORD" ]; then
        log_error "[validate_config] NEW_USER_PASSWORD must be set to a secure password"
        exit 1
    fi
    
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        log_error "[validate_config] SSH_PUBLIC_KEY must not be empty"
        exit 1
    fi
      
    if ! echo "$SSH_PUBLIC_KEY" | ssh-keygen -lf - >/dev/null 2>&1; then
        log_error "[validate_config] Invalid SSH public key format"
        exit 1
    fi
    
    # SSH port validation
    if [ -z "$SSH_PORT" ]; then
        log_error "[validate_config] SSH_PORT is not set in configuration"
        exit 1
    fi

    log_success "[validate_config] Configuration validated"
}

# Pre-flight system checks
preflight_checks() {
    log_info "[preflight] Running pre-flight checks..."
    
    # Check internet connectivity
    log_info "[preflight] Checking internet connectivity..."
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
        log_success "[preflight] Internet connectivity OK"
    else
        log_error "[preflight] No internet connectivity detected"
        log_error "[preflight] Internet access is required for package installation"
        exit 1
    fi

    log_success "[preflight] Pre-flight checks completed"
}

################################################################################
# COMPONENT: Software Install (required)
################################################################################

install_software() {
    log_info "[install] === Starting Software Installation ==="

    # Core packages that are always installed
    CORE_PACKAGES="curl wget git vim htop net-tools ncdu jq tmux tree unzip ufw fail2ban sysstat vnstat unattended-upgrades apt-listchanges msmtp msmtp-mta mailutils wireguard"
    
    # Combine core and additional packages
    ALL_PACKAGES="$CORE_PACKAGES $ADDITIONAL_PACKAGES"
    
    log_info "[install] Packages to install: $ALL_PACKAGES"

    # Update package lists
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq $ALL_PACKAGES
    apt-get autoremove -y -qq
    apt-get autoclean -qq

    log_success "[install] Software installation completed"
}

################################################################################
# COMPONENT: System Setup (required)
################################################################################

setup_hostname() {
    log_info "[hostname] === Starting System Setup ==="
    
    # Set hostname using portable methods
    log_info "[hostname] Setting hostname to: $HOSTNAME"
    echo "$HOSTNAME" > /etc/hostname
    hostname "$HOSTNAME"
    
    # Update /etc/hosts
    sed -i "/^127.0.1.1/d" /etc/hosts
    echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

    log_success "[hostname] Hostname set to: $HOSTNAME"
}

setup_timezone() {
    # Set timezone
    log_info "[timezone] Setting timezone to: $TIMEZONE"

    # Portable method: create symlink to zoneinfo
    if [ -f "/usr/share/zoneinfo/$TIMEZONE" ]; then
        ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
        echo "$TIMEZONE" > /etc/timezone
        log_success "[timezone] Timezone set to: $TIMEZONE"
    else
        log_error "[timezone] Invalid timezone: $TIMEZONE not found in /usr/share/zoneinfo/"
        exit 1
    fi
}

setup_swap() {
    if [ "$SWAP_SIZE_MB" -le 0 ]; then
        log_info "[swap] Swap file creation disabled (SWAP_SIZE_MB=0)"
        return
    fi

    SWAP_FILE="/swapfile"
    log_info "[swap] Creating swap file: ${SWAP_SIZE_MB}MB"

    # Always recreate swap file
    swapoff "$SWAP_FILE" 2>/dev/null || true
    rm -f "$SWAP_FILE"
    
    fallocate -l "${SWAP_SIZE_MB}M" "$SWAP_FILE" || dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$SWAP_SIZE_MB"
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE"
    swapon "$SWAP_FILE"

    # Add to fstab if not present
    grep -q "$SWAP_FILE" /etc/fstab || echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    sysctl vm.swappiness=$SWAPPINESS
    grep -q "vm.swappiness" /etc/sysctl.conf || echo "vm.swappiness=$SWAPPINESS" >> /etc/sysctl.conf

    log_success "[swap] Swap file created: ${SWAP_SIZE_MB}MB"
}

setup_user() {
    # Create new user with sudo privileges
    if id "$NEW_USER" >/dev/null 2>&1; then
        log_info "[user] User already exists: $NEW_USER"
    else
        log_info "[user] Creating user: $NEW_USER"

        # Create user with home directory
        useradd -m -s /bin/bash "$NEW_USER"
        
        # Set password
        echo "$NEW_USER:$NEW_USER_PASSWORD" | chpasswd

        log_success "[user] User created: $NEW_USER"
    fi
    
    # Add user to groups
    if [ -n "$NEW_USER_GROUPS" ]; then
        log_info "[user] Adding user to groups: $NEW_USER_GROUPS"

        # Convert comma-separated to space-separated
        GROUPS="$(echo "$NEW_USER_GROUPS" | tr ',' ' ')"
        
        for group in $GROUPS; do
            if getent group "$group" >/dev/null; then
                usermod -aG "$group" "$NEW_USER"
                log_success "[user] Added to group: $group"
            else
                log_warning "[user] Group does not exist: $group"
            fi
        done
    fi
    
    # Setup SSH directory and authorized_keys
    USER_HOME="$(getent passwd "$NEW_USER" | cut -d: -f6)"
    [ -z "$USER_HOME" ] && {
        log_error "Could not determine home directory for $NEW_USER"
        exit 1
    }
    SSH_DIR="$USER_HOME/.ssh"
    
    if [ ! -d "$SSH_DIR" ]; then
        log_info "[user] Creating SSH directory for $NEW_USER"
        mkdir -p "$SSH_DIR"
    fi
    
    AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
    
    # Add SSH public key if provided
    if [ -n "$SSH_PUBLIC_KEY" ]; then
        if [ -f "$AUTHORIZED_KEYS" ]; then
            grep -Fxq "$SSH_PUBLIC_KEY" "$AUTHORIZED_KEYS" 2>/dev/null || echo "$SSH_PUBLIC_KEY" >> "$AUTHORIZED_KEYS"
            log_info "[user] SSH public key already present or added for $NEW_USER"
        else
            log_info "[user] Adding SSH public key for $NEW_USER"
            echo "$SSH_PUBLIC_KEY" > "$AUTHORIZED_KEYS"
            log_success "[user] SSH public key added"
        fi
    else
        log_warning "[user] No SSH public key provided in configuration"
    fi
    
    # Set correct permissions
    chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    if [ -f "$AUTHORIZED_KEYS" ]; then
        chmod 600 "$AUTHORIZED_KEYS"
    fi

    log_success "[user] SSH configuration completed for $NEW_USER"
}

disable_snapd() {
    if ! command -v snap >/dev/null 2>&1; then
        log_info "[snapd] snapd not installed, skipping"
        return
    fi
    
    log_info "[snapd] Disabling and removing snapd installation..."
    systemctl stop snapd
    systemctl disable snapd
    systemctl mask snapd
    apt-get purge -y snapd
    rm -rf /snap /var/snap /var/lib/snapd
    log_success "[snapd] snapd disabled and removed"
}

install_caddy() {
    if command -v caddy > /dev/null 2>&1; then
        log_info "[caddy] Caddy is already installed, skipping..."
        return 0
    fi

    log_info "[caddy] Installing Caddy web server..."
    apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list
    apt update -qq
    apt install -y -qq caddy
    log_success "[caddy] Caddy installed successfully"
}

setup_logrotate() {
    # Configure log rotation
    log_info "[logrotate] Configuring log rotation..."

    cat > "$LOG_ROTATE_CONFIG" << EOF
# Log rotation configuration for common system logs

/var/log/syslog
/var/log/auth.log
/var/log/kern.log
/var/log/mail.log
/var/log/daemon.log
/var/log/user.log
{
    rotate $LOG_ROTATE_COUNT
    daily
    maxage $LOG_ROTATE_DAYS
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

$LOG_FILE
{
    rotate $LOG_ROTATE_COUNT
    daily
    maxage $LOG_ROTATE_DAYS
    missingok
    notifempty
    compress
    delaycompress
}
EOF

    log_success "[logrotate] Log rotation configured: $LOG_ROTATE_DAYS days, $LOG_ROTATE_COUNT rotations"
}


################################################################################
# COMPONENT: Unattended Updates (optional)
################################################################################

setup_unattended_updates() {
    log_info "[unattended-upgrades] === Starting Unattended Updates Setup ==="

    cat > "$UNATTENDED_UPGRADES_CONFIG" << EOF
// Unattended-Upgrade configuration

Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    // "\${distro_id}:\${distro_codename}-updates";
    // "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    // "\${distro_id}ESM:\${distro_codename}-infra-security";
};

// List of packages to not update (regexp format)
Unattended-Upgrade::Package-Blacklist {
};

// Do automatic removal of unused dependencies
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically reboot *WITHOUT CONFIRMATION* if required
// DISABLED - manual control preferred
Unattended-Upgrade::Automatic-Reboot "false";

// If automatic reboot is enabled, reboot at specific time
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Send email on errors or when updates are available
Unattended-Upgrade::Mail "$UNATTENDED_UPDATES_EMAIL";
Unattended-Upgrade::MailReport "on-change";

// Enable logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Verbose logging
Unattended-Upgrade::Verbose "false";
Unattended-Upgrade::Debug "false";
EOF

    cat > "$APT_PERIODIC_CONFIG" << 'EOF'
// Enable automatic updates

APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    log_success "[unattended-upgrades] Unattended updates configured (security only, no auto-reboot)"
}

################################################################################
# COMPONENT: Notifications (optional)
################################################################################

setup_email_notifications() {
    log_info "[notifications] === Starting Email Notifications Setup ==="

    cat > "$MSMTP_CONFIG" << EOF
# MSMTP configuration

# Default settings
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        $MSMTP_LOG

# Account configuration
account        default
host           $SMTP_HOST
port           $SMTP_PORT
from           ${SMTP_FROM:-$SMTP_USER}
user           $SMTP_USER
password       $SMTP_PASSWORD

# Set default account
account default : default
EOF

    chmod 600 "$MSMTP_CONFIG"
    log_success "[notifications] msmtp configuration created"
    
    # Create log file with proper permissions
    touch "$MSMTP_LOG"
    chmod 666 "$MSMTP_LOG"

    # Test email configuration
    log_info "[notifications] Testing email configuration..."

    TEST_EMAIL_BODY="This is a test email from your $HOSTNAME server.

Server: $HOSTNAME
Date: $(date)

If you receive this email, notifications are configured correctly."
    
    if echo "$TEST_EMAIL_BODY" | mail -s "Test Email from $HOSTNAME" "$NOTIFICATION_EMAIL" 2>/dev/null; then
        log_success "[notifications] Test email sent to $NOTIFICATION_EMAIL"
        log_info "[notifications] Check your inbox to verify email delivery"
    else
        log_warning "[notifications] Failed to send test email (check $MSMTP_LOG for details)"
    fi

    log_success "[notifications] Email notifications setup completed"
}

setup_ssh() {
    log_info "[ssh] === Configuring SSH (no restart) ==="

    # Backup existing sshd_config
    if [ -f /etc/ssh/sshd_config ] && [ ! -f /etc/ssh/sshd_config.backup ]; then
        log_info "[ssh] Backing up original SSH configuration"
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        log_success "[ssh] Backup created: /etc/ssh/sshd_config.backup"
    fi

    log_info "[ssh] Configuring hardened SSH settings..."

    # Generate new sshd_config with hardened settings
    cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration

# Port and Protocol
Port $SSH_PORT
Protocol 2

# Ciphers and Keying
# Use modern, secure ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Authentication
PermitRootLogin no

# Public key authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Password authentication - DISABLED
PasswordAuthentication no

# PAM
UsePAM yes

# Allow specific users (add more as needed)
AllowUsers $NEW_USER
EOF

    log_success "[ssh] SSH configuration file updated"

    # Test SSH configuration
    log_info "[ssh] Testing SSH configuration..."
    if sshd -t; then
        log_success "[ssh] SSH configuration is valid"
    else
        log_error "[ssh] SSH configuration test failed!"
        log_error "[ssh] Restoring backup configuration..."
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        exit 1
    fi

    log_info "[ssh] Restarting SSH service..."
    systemctl restart sshd > /dev/null 2>&1 || systemctl restart ssh > /dev/null 2>&1

    if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
        log_success "[ssh] SSH service restarted successfully"
    else
        log_error "[ssh] Failed to restart SSH service!"
        exit 1
    fi
}

setup_firewall() {
    log_info "[ufw] === Configuring Firewall (not enabling) ==="

    # Reset to clean state
    log_info "[ufw] Resetting UFW to clean state..."
    ufw --force reset >/dev/null 2>&1

    # Set default policies
    log_info "[ufw] Setting default firewall policies..."
    ufw default deny incoming
    ufw default allow outgoing
    log_success "[ufw] Default policies set"

    # Allow SSH
    log_info "[ufw] Allowing SSH on port $SSH_PORT..."
    ufw allow "$SSH_PORT/tcp" comment "SSH"

    # Allow WireGuard if configured
    if [ -n "$WIREGUARD_PORT" ] && [ "$WIREGUARD_PORT" -gt 0 ]; then
        log_info "[ufw] Allowing WireGuard on port $WIREGUARD_PORT..."
        ufw allow "$WIREGUARD_PORT/udp" comment "WireGuard"
    fi

    # Allow additional ports
    if [ -n "$ADDITIONAL_PORTS" ]; then
        log_info "[ufw] Configuring additional ports: $ADDITIONAL_PORTS"

        for port in $ADDITIONAL_PORTS; do
            log_info "[ufw] Allowing port: $port"
            ufw allow "$port" comment "Additional service"
        done

        log_success "[ufw] Additional ports configured"
    fi

    log_info "[ufw] Enabling UFW firewall..."
    ufw --force enable
    log_info "[ufw] Rules preview: $(ufw status | grep -c 'ALLOW' || echo '0') rules"
    log_success "[ufw] Firewall enabled"
}

setup_monitoring() {
    log_info "[monitoring] === Configuring Monitoring (no start) ==="

    # Configure sysstat
    sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
    log_success "[monitoring] sysstat configured"

    # Initialize vnstat for all network interfaces
    for interface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'); do
        vnstat --add --iface "$interface" >/dev/null 2>&1 || true
    done

    # Start/restart monitoring
    log_info "[monitoring] Starting monitoring services..."
    systemctl enable sysstat >/dev/null 2>&1
    systemctl start sysstat >/dev/null 2>&1
    systemctl enable vnstat >/dev/null 2>&1
    systemctl start vnstat >/dev/null 2>&1
    log_success "[monitoring] Monitoring services started"
}

setup_fail2ban() {
    log_info "[fail2ban] === Configuring Fail2ban (no restart) ==="

    cat > "$FAIL2BAN_CONFIG" << EOF
# Fail2ban configuration

[DEFAULT]
# Ban settings
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME
maxretry = $FAIL2BAN_MAXRETRY

# Action to take when banning
banaction = iptables-multiport
banaction_allports = iptables-allports

# Email settings (if notifications enabled)
destemail = root@localhost
sender = root@localhost
mta = sendmail

# Log settings
logtarget = $FAIL2BAN_LOG

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME

# Additional protection for SSH
[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 600
findtime = 60
EOF

    cat > "$FAIL2BAN_FILTER_SSHD_DDOS" << 'EOF'
# Fail2ban filter to match SSH connection flood
[Definition]
failregex = ^.*sshd\[\d+\]: Connection from <HOST> port \d+$
ignoreregex =
EOF

    log_info "[fail2ban] Starting fail2ban..."
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        log_success "[fail2ban] fail2ban is active and running"
    else
        log_error "[fail2ban] fail2ban failed to start - check /var/log/fail2ban.log"
        exit 1
    fi

    log_success "[fail2ban] configuration ready (restart required to apply)"
}

################################################################################
main() {
    [ -f "$CONFIG_FILE" ] || {
        echo -e "${RED}[ERROR] Configuration file not found: $CONFIG_FILE${NC}"
        echo -e "${RED}[ERROR] Usage: $0 [config-file]${NC}"
        echo -e "${RED}[ERROR] Example: $0 /path/to/myserver.conf${NC}"
        echo -e "${RED}[ERROR] If no config file specified, will look for: ${SCRIPT_DIR}/instance.conf${NC}"
        exit 1
    }

    . "$CONFIG_FILE"

    log_info "=========================================="
    log_info "Instance Setup Script"
    log_info "Configuration file: $CONFIG_FILE"
    log_info "Started at: $(date)"
    log_info "=========================================="

    # Pre-flight checks
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi

    validate_config
    preflight_checks

    install_software
    setup_hostname
    setup_timezone
    setup_swap
    setup_user
    setup_logrotate
    setup_monitoring

    if [ "$DISABLE_SNAPD" = "true" ]; then
        disable_snapd
    fi


    if [ "$ENABLE_UNATTENDED_UPDATES" = "true" ]; then
        setup_unattended_updates
    fi

    if [ "$ENABLE_EMAIL_NOTIFICATIONS" = "true" ]; then
        setup_email_notifications
    fi

    setup_ssh

    if [ "$ENABLE_FAIL2BAN" = "true" ]; then
        setup_fail2ban
    fi

    setup_firewall

    if [ "$INSTALL_CADDY" = "true" ]; then
        install_caddy
    fi

    log_success "Instance configuration completed successfully!"
}

# Run main function
main "$@"
