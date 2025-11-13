#!/bin/bash
# =============================================================================
# GemiLab Tunnel Crafter -- WireGuard VPN Setup Script for Debian/Ubuntu
# Version: 3.0
# Description: WireGuard VPN + System Hardening + Netdata Monitoring
# =============================================================================
set -euo pipefail

# =============================================================================
# CONFIGURATION SECTION - CUSTOMIZE THESE VALUES
# =============================================================================

# Default user configuration
readonly DEFAULT_USERNAME="cew"

# SSH Public Key Configuration
# SAFE: SSH public keys are meant to be public - paste your public key here
# Find your public key with: cat ~/.ssh/id_ed25519.pub (or id_rsa.pub)
# Example: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@hostname"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLpsMrS7cda7HEeGVWV9ho6RWlSdyKnY3Q30F1A43t9wHjy1Jj1707I3p8LNqR6VlIesPdwCYcHNr7PvrvZcKS2ebaLZwFAyFJNAICrpVln1tEo+Dusi8G0HbRC3vVMOjVDXiCaSAFMMKBvqutDiYF/h0wAFaEcp9cnch2wQOHbRiv0nzjRsrJPK6P09esruX4Y57NWxTMU4Nwpsl7y02UIFeI2e8aac1kVA9G3x/e1Wob95rT2Hx75GoCMHhuL+EsYgdd86njcEtwYqpUsM7YYcnqjtAWr45sq6TB8TA3N0KELR4FRRtjL0xV/LQrPh8Ir15HRNr6yXBe3hXyaYYQ3yB5gQtrQLlNchm31S5piqARbUY/PCFlg07KXu+VjivrpMrK7/fwFzi6de9cvmVJRwDhCMAh6bSAc/9OJGybfaTX7JomSE/V/6pPeaOUSVA/6zAcNtW6+tAoR82hy3vWgsz6a3Hkw6RqzEJB6JSdOWNDtgNBTSBk4sEFNQPm2W4hoI9D2+7gG/Z+ijt1u/wfsVrezQwhpLkLHmFqpV++UJXGKpDUmUxYv1F6/G+UoqztPCl9eBY8PJeO0u8+a8J6DB1Yx+ClMypdTvgGajyOryG9q6/HsL0268l1Z29XkgueaCltIu1cOvwdOxWQwZJH/kV/rVWzxJAO3TAj9UPHTw==}"

# Network Configuration
readonly WG_PORT=51820
readonly WG_SERVER_IP="10.10.10.1/24"
readonly SSH_PORT=22
readonly PING_TEST_IP="4.2.2.1"

# Feature Flags
INSTALL_NETDATA="${INSTALL_NETDATA:-true}"
ENABLE_SSL="${ENABLE_SSL:-true}"
DRY_RUN="${DRY_RUN:-false}"

# Network Timeout Configuration
readonly CURL_TIMEOUT=10
readonly CURL_RETRIES=3
readonly DNS_TIMEOUT=5
readonly PING_TIMEOUT=5

# File Paths
readonly CONFIG_FILE="vpn_setup.conf"
readonly LOG_FILE="/var/log/secure_vpn_setup.log"

# Runtime Variables (do not modify)
USER_ACCOUNT_NAME=""
HOST_FQDN=""
PUBLIC_IP=""
SCRIPT_START_TIME=$(date +%s)

# =============================================================================
# TERMINAL COLORS
# =============================================================================
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# =============================================================================
# USAGE AND HELP
# =============================================================================
usage() {
    cat << EOF
${BLUE}GemiLab Tunnel Crafter WireGuard VPN Setup Script${NC}

${GREEN}Usage:${NC}
    $0 [OPTIONS]

${GREEN}Options:${NC}
    -h, --help              Show this help message
    -c, --config FILE       Load configuration from FILE
    -d, --dry-run          Show what would be done without executing
    --skip-netdata         Skip Netdata installation
    --skip-ssl             Skip SSL certificate setup
    -u, --username USER    Specify username (default: cew)

${GREEN}Environment Variables:${NC}
    HOST_FQDN              Fully qualified domain name
    SSH_PUBLIC_KEY         SSH public key to install
    PUBLIC_IP              Server's public IP address
    INSTALL_NETDATA        Install Netdata monitoring (true/false)
    ENABLE_SSL             Enable SSL certificates (true/false)
    DRY_RUN                Dry run mode (true/false)

${GREEN}Examples:${NC}
    # Interactive setup
    sudo $0

    # With custom username
    sudo $0 -u myuser

    # Skip Netdata installation
    sudo $0 --skip-netdata

    # Dry run to see what would happen
    sudo $0 --dry-run

${YELLOW}Note:${NC} This script must be run as root.

EOF
    exit 0
}

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

# Initialize logging
init_log() {
    if [[ "$DRY_RUN" == "false" ]]; then
        (umask 027 && touch "$LOG_FILE")
        chmod 640 "$LOG_FILE" 2>/dev/null || true
    fi
    log "Starting VPS hardening and WireGuard setup (v2.0)"
    log "Logging to $LOG_FILE"
    [[ "$DRY_RUN" == "true" ]] && warning "DRY RUN MODE - No changes will be made"
}

# Log informational message
log() {
    local msg="$1"
    echo -e "${GREEN}[+]${NC} $msg"
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Log error and exit
error() {
    local msg="$1"
    echo -e "${RED}[-] ERROR: $msg${NC}" >&2
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
    exit 1
}

# Log warning
warning() {
    local msg="$1"
    echo -e "${YELLOW}[!]${NC} WARNING: $msg"
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Log section header
section() {
    local msg="$1"
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}  $msg${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - SECTION: $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# Execute command with dry-run support
exec_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${CYAN}[DRY-RUN]${NC} Would execute: $*"
        return 0
    else
        "$@"
    fi
}

# =============================================================================
# ERROR HANDLING AND CLEANUP
# =============================================================================

# Cleanup handler
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        warning "Script failed with exit code $exit_code"
        # Add cleanup logic here if needed
    fi
}

# Set up traps
trap cleanup EXIT
trap 'error "Script interrupted by user"' INT TERM

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

# Validate IP address format
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Check each octet is <= 255
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate hostname format
validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# Validate SSH public key
validate_ssh_key() {
    local key="$1"
    if [[ -z "$key" ]]; then
        return 1
    fi
    # Check if key starts with known key types
    if [[ "$key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
        return 0
    fi
    return 1
}

# Validate username format
validate_username() {
    local username="$1"
    if [[ "$username" =~ ^[a-z][-a-z0-9_]{0,30}$ ]]; then
        return 0
    fi
    return 1
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[-] This script must be run as root${NC}" >&2
        echo "    Try: sudo $0" >&2
        exit 1
    fi
}

# Check OS compatibility
check_os() {
    section "Checking System Requirements"

    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS version - /etc/os-release not found"
    fi

    # shellcheck source=/dev/null
    source /etc/os-release

    log "Detected OS: $PRETTY_NAME"

    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        error "This script only supports Ubuntu and Debian. Detected: $ID"
    fi

    # Check version
    local version_id="${VERSION_ID:-0}"
    if [[ "$ID" == "ubuntu" ]] && [[ "${version_id%%.*}" -lt 20 ]]; then
        warning "Ubuntu version $VERSION_ID is quite old. Recommended: 20.04 or newer"
    elif [[ "$ID" == "debian" ]] && [[ "${version_id%%.*}" -lt 10 ]]; then
        warning "Debian version $VERSION_ID is quite old. Recommended: 10 or newer"
    fi

    log "OS compatibility check passed"
}

# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

# Load configuration file if it exists
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "Loading configuration from $CONFIG_FILE"
        # Safely source the config file
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

# =============================================================================
# NETWORK FUNCTIONS
# =============================================================================

# Get public IP address with timeout and retry
get_public_ip() {
    if [[ -n "$PUBLIC_IP" ]]; then
        log "Using configured public IP: $PUBLIC_IP"
        return 0
    fi

    section "Detecting Public IP Address"

    # Try multiple services with timeout
    local ip_services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )

    for service in "${ip_services[@]}"; do
        log "Trying to get public IP from $service..."
        PUBLIC_IP=$(curl -s --max-time "$CURL_TIMEOUT" --retry "$CURL_RETRIES" \
                    --retry-delay 2 --retry-all-errors "$service" 2>/dev/null | tr -d '[:space:]')

        if [[ -n "$PUBLIC_IP" ]] && validate_ip "$PUBLIC_IP"; then
            log "Successfully detected public IP: $PUBLIC_IP"
            return 0
        fi
    done

    warning "Could not automatically determine public IP"

    # Prompt user for manual entry
    while true; do
        read -rp "Please enter your server's public IP address: " PUBLIC_IP
        PUBLIC_IP="${PUBLIC_IP// /}" # Remove spaces

        if [[ -z "$PUBLIC_IP" ]]; then
            error "Public IP is required for VPN setup"
        fi

        if validate_ip "$PUBLIC_IP"; then
            log "Using public IP: $PUBLIC_IP"
            return 0
        else
            warning "Invalid IP address format: $PUBLIC_IP"
        fi
    done
}

# DNS lookup with timeout using dig (more reliable than nslookup)
reverse_dns_lookup() {
    local ip="$1"
    timeout "$DNS_TIMEOUT" dig +short -x "$ip" +time=2 +tries=2 2>/dev/null | sed 's/\.$//' | head -n1
}

forward_dns_lookup() {
    local hostname="$1"
    timeout "$DNS_TIMEOUT" dig +short "$hostname" +time=2 +tries=2 2>/dev/null | head -n1
}

# Check if IP matches hostname
ip_matches_hostname() {
    local ip="$1"
    local hostname="$2"
    local resolved_ip

    resolved_ip=$(forward_dns_lookup "$hostname")

    if [[ "$resolved_ip" == "$ip" ]]; then
        return 0
    fi
    return 1
}

# Get and validate FQDN
get_host_fqdn() {
    section "Configuring Hostname"

    if [[ -n "$HOST_FQDN" ]]; then
        log "Using configured hostname: $HOST_FQDN"
        local fqdn_ip
        fqdn_ip=$(forward_dns_lookup "$HOST_FQDN")

        if ip_matches_hostname "$PUBLIC_IP" "$HOST_FQDN"; then
            log "Hostname '$HOST_FQDN' resolves correctly to $PUBLIC_IP"
            return 0
        else
            error "Configured hostname '$HOST_FQDN' does not resolve to public IP '$PUBLIC_IP' (resolves to: ${fqdn_ip:-NXDOMAIN})"
        fi
    fi

    # Try reverse DNS lookup
    local detected_hostname
    detected_hostname=$(reverse_dns_lookup "$PUBLIC_IP")

    local prompt
    if [[ -n "$detected_hostname" ]]; then
        prompt="Auto-detected hostname is '$detected_hostname', press ENTER to use or enter alternative: "
        HOST_FQDN="$detected_hostname"
    else
        prompt="Enter fully qualified domain name (e.g., vpn.example.com): "
    fi

    while true; do
        local response
        read -rp "$prompt" response

        # If user provided input, use it; otherwise keep detected hostname
        if [[ -n "$response" ]]; then
            HOST_FQDN="$response"
        fi

        # Validate hostname format
        if ! validate_hostname "$HOST_FQDN"; then
            warning "Invalid hostname format: $HOST_FQDN"
            HOST_FQDN=""
            prompt="Enter valid FQDN (e.g., vpn.example.com): "
            continue
        fi

        # Check DNS resolution
        local fqdn_ip
        fqdn_ip=$(forward_dns_lookup "$HOST_FQDN")
        log "Hostname '$HOST_FQDN' resolves to: ${fqdn_ip:-NXDOMAIN}"

        if ip_matches_hostname "$PUBLIC_IP" "$HOST_FQDN"; then
            log "Hostname '$HOST_FQDN' verified successfully"
            break
        else
            warning "Hostname '$HOST_FQDN' does not resolve to public IP '$PUBLIC_IP'"
            warning "Expected: $PUBLIC_IP, Got: ${fqdn_ip:-NXDOMAIN}"

            read -rp "Continue anyway? (y/N): " continue_response
            if [[ "${continue_response,,}" == "y" ]]; then
                warning "Continuing with unverified hostname - SSL certificate may fail"
                break
            fi

            HOST_FQDN=""
            prompt="Enter correct FQDN: "
        fi
    done
}

# Test network connectivity
test_network() {
    section "Testing Network Connectivity"

    log "Testing connectivity to $PING_TEST_IP..."

    if ping -c3 -W"$PING_TIMEOUT" "$PING_TEST_IP" >/dev/null 2>&1; then
        log "Network connectivity: OK"
        return 0
    else
        warning "Ping test failed. Showing detailed output:"
        ping -c3 -W"$PING_TIMEOUT" "$PING_TEST_IP" || true
        error "Network connectivity test failed. Please check your network configuration."
    fi
}

# =============================================================================
# USER MANAGEMENT FUNCTIONS
# =============================================================================

# Get and validate username
select_user_name() {
    section "Configuring User Account"

    # Use default username
    local default_user="$DEFAULT_USERNAME"

    while true; do
        read -rp "Enter username for VPS account and Netdata login [$default_user]: " username_response

        # Use default if no input provided
        if [[ -z "$username_response" ]]; then
            username_response="$default_user"
        fi

        # Convert to lowercase
        username_response="${username_response,,}"

        # Validate format
        if ! validate_username "$username_response"; then
            warning "Invalid username format: $username_response"
            warning "Username must start with a letter, contain only lowercase letters, numbers, hyphens, and underscores"
            continue
        fi

        # Check if user already exists
        if getent passwd "$username_response" >/dev/null 2>&1; then
            warning "User '$username_response' already exists"

            read -rp "Use existing user? (Y/n): " use_existing
            if [[ "${use_existing,,}" != "n" ]]; then
                USER_ACCOUNT_NAME="$username_response"
                log "Using existing user: $USER_ACCOUNT_NAME"
                return 0
            fi
            continue
        fi

        break
    done

    USER_ACCOUNT_NAME="$username_response"
    log "Username will be: $USER_ACCOUNT_NAME"
}

# Get SSH public key
get_pubkey() {
    section "Configuring SSH Public Key"

    if [[ -n "$SSH_PUBLIC_KEY" ]]; then
        if validate_ssh_key "$SSH_PUBLIC_KEY"; then
            log "Using pre-configured SSH public key"
            return 0
        else
            warning "Pre-configured SSH key is invalid"
            SSH_PUBLIC_KEY=""
        fi
    fi

    echo "Paste your SSH public key (from ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub):"
    echo "Or press ENTER to generate a new key pair on this server"

    read -rp "> " SSH_PUBLIC_KEY

    if [[ -z "$SSH_PUBLIC_KEY" ]]; then
        warning "No SSH key provided - password authentication will be required initially"
        return 0
    fi

    if ! validate_ssh_key "$SSH_PUBLIC_KEY"; then
        error "Invalid SSH public key format"
    fi

    log "SSH public key validated successfully"
}

# Install SSH public key for user (idempotent)
install_user_ssh_pubkey() {
    local user="$1"
    local home="$2"
    local pubkey="$3"

    if [[ -z "$pubkey" ]]; then
        log "No SSH public key to install for $user"
        return 0
    fi

    log "Installing SSH public key for $user..."

    exec_cmd mkdir -p "${home}/.ssh"
    exec_cmd touch "${home}/.ssh/authorized_keys"

    # Check if key already exists (idempotent)
    if [[ "$DRY_RUN" == "false" ]] && grep -qF "$pubkey" "${home}/.ssh/authorized_keys" 2>/dev/null; then
        log "SSH public key already installed for $user"
    else
        if [[ "$DRY_RUN" == "false" ]]; then
            echo "$pubkey" >> "${home}/.ssh/authorized_keys"
        fi
        log "SSH public key added for $user"
    fi

    exec_cmd chown -R "${user}:${user}" "${home}/.ssh"
    exec_cmd chmod 700 "${home}/.ssh"
    exec_cmd chmod 600 "${home}/.ssh/authorized_keys"
}

# =============================================================================
# PACKAGE INSTALLATION FUNCTIONS
# =============================================================================

# Check if package is installed
is_package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Bootstrap critical tools for minimal installations
# This must run BEFORE any network operations or DNS lookups
bootstrap_critical_tools() {
    log "Checking for critical tools..."

    local tools_to_install=()
    local need_update=false

    # Check for curl (needed for get_public_ip)
    if ! command -v curl &>/dev/null; then
        log "curl not found - will install"
        tools_to_install+=("curl")
        need_update=true
    fi

    # Check for dig (needed for DNS lookups)
    if ! command -v dig &>/dev/null; then
        log "dig not found - will install dnsutils"
        tools_to_install+=("dnsutils")
        need_update=true
    fi

    # Check for ping (needed for network test)
    if ! command -v ping &>/dev/null; then
        log "ping not found - will install iputils-ping"
        tools_to_install+=("iputils-ping")
        need_update=true
    fi

    # Check for timeout command (part of coreutils, usually present)
    if ! command -v timeout &>/dev/null; then
        log "timeout not found - will install coreutils"
        tools_to_install+=("coreutils")
        need_update=true
    fi

    # Install missing tools if needed
    if [[ ${#tools_to_install[@]} -gt 0 ]]; then
        log "Installing critical tools for minimal installation: ${tools_to_install[*]}"

        if [[ "$DRY_RUN" == "false" ]]; then
            # Update package list first
            apt-get update -qq || error "Failed to update package database for bootstrap"

            # Install each tool
            for tool in "${tools_to_install[@]}"; do
                log "Installing $tool..."
                apt-get install -y -qq "$tool" || error "Failed to install critical tool: $tool"
            done
        fi

        log "Critical tools installed successfully"
    else
        log "All critical tools present"
    fi
}

# Install required packages
install_packages() {
    section "Installing Required Packages"

    log "Updating package database..."
    exec_cmd apt-get update || error "Failed to update package database"

    log "Upgrading existing packages..."
    exec_cmd apt-get upgrade -y || warning "Some packages could not be upgraded"

    log "Installing required packages (this may take a few minutes)..."

    # Core packages that must succeed
    local critical_packages=(
        "sudo" "curl" "wget" "gnupg2" "apt-transport-https"
        "ca-certificates" "wireguard" "ufw"
    )

    # Additional packages
    local additional_packages=(
        "software-properties-common" "lsb-release" "unattended-upgrades"
        "fail2ban" "git" "python3" "python3-pip" "python3-venv"
        "qrencode" "nginx" "apache2-utils" "certbot" "python3-certbot-nginx"
        "zlib1g-dev" "uuid-dev" "libuv1-dev" "liblz4-dev" "libssl-dev"
        "libmnl-dev" "rsyslog" "dnsutils"
    )

    # Install critical packages first
    for pkg in "${critical_packages[@]}"; do
        if ! is_package_installed "$pkg"; then
            log "Installing critical package: $pkg"
            exec_cmd apt-get install -y "$pkg" || error "Failed to install critical package: $pkg"
        else
            log "Already installed: $pkg"
        fi
    done

    # Install additional packages (best effort)
    exec_cmd apt-get install -y "${additional_packages[@]}" || warning "Some optional packages could not be installed"

    log "Package installation completed"
}

# =============================================================================
# SYSTEM CONFIGURATION FUNCTIONS
# =============================================================================

# Preseed postfix configuration to avoid interactive prompts
preseed_postfix_settings() {
    log "Pre-configuring Postfix to avoid prompts..."
    exec_cmd debconf-set-selections <<< "postfix postfix/main_mailer_type select No configuration"
    exec_cmd debconf-set-selections <<< "postfix postfix/mailname string $(hostname).localdomain"
}

# Configure unattended upgrades (idempotent)
setup_unattended_upgrades() {
    section "Configuring Automatic Security Updates"

    log "Configuring unattended-upgrades..."

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    fi

    log "Automatic security updates configured"
}

# Harden system with sysctl settings (idempotent)
harden_sysctl() {
    section "Hardening Network Security Settings"

    log "Applying secure sysctl parameters..."

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable IP forwarding (required for WireGuard)
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Protect Against TCP Time-Wait
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for connections
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

        # Apply sysctl settings
        sysctl -p /etc/sysctl.d/99-security.conf || warning "Some sysctl parameters might not have been applied"
    fi

    log "Network security hardening completed"
}

# =============================================================================
# SSH SECURITY FUNCTIONS
# =============================================================================

# Secure SSH configuration
secure_ssh() {
    section "Securing SSH Configuration"

    # Backup SSH config (only first time)
    if [[ "$DRY_RUN" == "false" ]] && [[ ! -f /etc/ssh/sshd_config.backup.orig ]]; then
        log "Creating backup of original SSH configuration"
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.orig
    fi

    # Generate strong SSH host keys if needed
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        log "Generating ED25519 SSH host key..."
        exec_cmd ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    else
        log "ED25519 SSH host key already exists"
    fi

    log "Applying secure SSH configuration..."

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/ssh/sshd_config << EOF
# SSH Configuration - Generated by VPN Setup Script
Port ${SSH_PORT}
AddressFamily inet
Protocol 2

# Host Keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin without-password
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# PAM and Subsystems
UsePAM yes
X11Forwarding no
PrintMotd no

# Session Management
ClientAliveInterval 300
ClientAliveCountMax 2

# SFTP Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Cryptography
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Allow specific user
AllowUsers ${USER_ACCOUNT_NAME}
EOF
    fi

    # Create user if doesn't exist
    if ! id "$USER_ACCOUNT_NAME" &>/dev/null; then
        log "Creating user: $USER_ACCOUNT_NAME"
        exec_cmd useradd -m -s /bin/bash "$USER_ACCOUNT_NAME"

        if [[ "$DRY_RUN" == "false" ]]; then
            # Generate strong random password
            local user_password
            user_password=$(tr -dc 'A-Za-z0-9!@#%^&*()_+-=' </dev/urandom | head -c 20)
            echo "$USER_ACCOUNT_NAME:$user_password" | chpasswd

            # Display password securely (not logged to file)
            echo ""
            echo -e "${YELLOW}========================================${NC}"
            echo -e "${YELLOW}IMPORTANT: Save this password securely!${NC}"
            echo -e "${YELLOW}========================================${NC}"
            echo -e "User: ${GREEN}$USER_ACCOUNT_NAME${NC}"
            echo -e "Password: ${GREEN}$user_password${NC}"
            echo -e "${YELLOW}Change this password after first login!${NC}"
            echo -e "${YELLOW}========================================${NC}"
            echo ""
            sleep 5
        fi

        # Add user to sudo group
        exec_cmd usermod -aG sudo "$USER_ACCOUNT_NAME"
        log "User '$USER_ACCOUNT_NAME' created and added to sudo group"
    else
        log "User '$USER_ACCOUNT_NAME' already exists"
    fi

    # Test SSH configuration before restarting
    if [[ "$DRY_RUN" == "false" ]]; then
        sshd -t || error "SSH configuration test failed"
    fi

    # Restart SSH service
    exec_cmd systemctl restart sshd || error "Failed to restart SSH service"

    log "SSH secured successfully"
}

# =============================================================================
# FIREWALL CONFIGURATION FUNCTIONS
# =============================================================================

# Configure UFW firewall
setup_firewall() {
    section "Configuring Firewall Rules"

    log "Configuring UFW firewall..."

    # Reset UFW to defaults (idempotent)
    if [[ "$DRY_RUN" == "false" ]]; then
        ufw --force reset >/dev/null 2>&1 || true
    fi

    exec_cmd ufw default deny incoming
    exec_cmd ufw default allow outgoing

    # Add firewall rules
    log "Adding firewall rules..."
    exec_cmd ufw allow "${SSH_PORT}/tcp" comment 'SSH'
    exec_cmd ufw allow "${WG_PORT}/udp" comment 'WireGuard VPN'
    exec_cmd ufw allow 80/tcp comment 'HTTP'
    exec_cmd ufw allow 443/tcp comment 'HTTPS'

    # Enable UFW
    log "Enabling firewall..."
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "y" | ufw enable >/dev/null 2>&1
    fi

    # Configure Fail2Ban
    log "Configuring Fail2Ban..."

    if [[ "$DRY_RUN" == "false" ]] && [[ ! -f /etc/fail2ban/jail.local.orig ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local.orig 2>/dev/null || true
    fi

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/fail2ban/jail.d/custom.conf << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    fi

    exec_cmd systemctl enable fail2ban
    exec_cmd systemctl restart fail2ban

    log "Firewall and intrusion prevention configured"
}

# =============================================================================
# WIREGUARD VPN FUNCTIONS
# =============================================================================

# Install and configure WireGuard
install_wireguard() {
    section "Installing WireGuard VPN"

    # Create WireGuard directory structure
    exec_cmd mkdir -p /etc/wireguard/clients
    exec_cmd chmod 700 /etc/wireguard

    # Check if already configured
    if [[ -f /etc/wireguard/server.key ]] && [[ -f /etc/wireguard/wg0.conf ]]; then
        log "WireGuard already configured, skipping key generation"
        return 0
    fi

    # Generate server keys
    log "Generating WireGuard server keys..."
    if [[ "$DRY_RUN" == "false" ]]; then
        wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
        chmod 600 /etc/wireguard/server.key
    fi

    local server_private_key=""
    local server_public_key=""

    if [[ "$DRY_RUN" == "false" ]]; then
        server_private_key=$(cat /etc/wireguard/server.key)
        server_public_key=$(cat /etc/wireguard/server.pub)

        # Validate keys
        if [[ -z "$server_private_key" ]] || [[ -z "$server_public_key" ]]; then
            error "Failed to generate WireGuard keys"
        fi
    fi

    # Determine default network interface
    local default_interface
    default_interface=$(ip -4 route ls | grep default | grep -oP '(?<=dev )\S+' | head -1)

    if [[ -z "$default_interface" ]]; then
        warning "Could not determine default network interface, using eth0"
        default_interface="eth0"
    fi

    log "Using $default_interface as external network interface"

    # Create WireGuard server configuration
    log "Creating WireGuard server configuration..."

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${server_private_key}
SaveConfig = true

# NAT forwarding rules
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE
EOF
    fi

    # Generate first client configuration
    log "Creating first client configuration..."

    if [[ "$DRY_RUN" == "false" ]]; then
        wg genkey | tee /etc/wireguard/clients/client1.key | wg pubkey > /etc/wireguard/clients/client1.pub
        chmod 600 /etc/wireguard/clients/client1.key

        local client1_private_key
        local client1_public_key
        client1_private_key=$(cat /etc/wireguard/clients/client1.key)
        client1_public_key=$(cat /etc/wireguard/clients/client1.pub)

        # Validate client keys
        if [[ -z "$client1_private_key" ]] || [[ -z "$client1_public_key" ]]; then
            error "Failed to generate client keys"
        fi

        local client1_ip="10.10.10.2/32"

        # Create client configuration file
        cat > /etc/wireguard/clients/client1.conf << EOF
[Interface]
PrivateKey = ${client1_private_key}
Address = ${client1_ip%/*}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

        # Add client peer to server configuration
        cat >> /etc/wireguard/wg0.conf << EOF

# Client 1
[Peer]
PublicKey = ${client1_public_key}
AllowedIPs = ${client1_ip}
EOF

        # Generate QR code for easy mobile setup
        if command -v qrencode &>/dev/null; then
            qrencode -t ansiutf8 < /etc/wireguard/clients/client1.conf > /etc/wireguard/clients/client1_qr.txt 2>/dev/null || true
        fi
    fi

    # Enable and start WireGuard service
    log "Enabling WireGuard service..."
    exec_cmd systemctl enable wg-quick@wg0
    exec_cmd systemctl start wg-quick@wg0

    # Wait a moment and verify it's running
    if [[ "$DRY_RUN" == "false" ]]; then
        sleep 2
        if systemctl is-active --quiet wg-quick@wg0; then
            log "WireGuard VPN is running"
        else
            error "WireGuard service failed to start"
        fi
    fi

    log "WireGuard VPN installation completed"
}

# =============================================================================
# WGDASHBOARD INSTALLATION FUNCTIONS
# =============================================================================

# Install WireGuard Dashboard (idempotent)
install_wgdashboard() {
    section "Installing WireGuard Dashboard"

    local wg_dash_dir="/opt/WGDashboard"

    # Check if already installed
    if [[ -d "$wg_dash_dir" ]] && [[ -f "$wg_dash_dir/src/wgd.sh" ]]; then
        log "WGDashboard already installed, skipping..."

        # Ensure service is enabled
        exec_cmd systemctl enable wgdashboard 2>/dev/null || true
        exec_cmd systemctl start wgdashboard 2>/dev/null || true

        return 0
    fi

    # Remove any partial installation
    if [[ -d "$wg_dash_dir" ]]; then
        log "Removing incomplete WGDashboard installation..."
        exec_cmd rm -rf "$wg_dash_dir"
    fi

    # Clone repository
    log "Downloading WGDashboard..."
    if [[ "$DRY_RUN" == "false" ]]; then
        cd /opt || error "Failed to change to /opt directory"
        git clone --depth 1 https://github.com/donaldzou/WGDashboard.git || error "Failed to clone WGDashboard repository"
        cd WGDashboard/src || error "Failed to change to WGDashboard/src directory"
    fi

    # Create required directories
    exec_cmd mkdir -p "$wg_dash_dir/src/log"
    exec_cmd mkdir -p "$wg_dash_dir/src/db"

    # Set permissions and install
    if [[ "$DRY_RUN" == "false" ]]; then
        chmod +x "$wg_dash_dir/src/wgd.sh"

        log "Installing WGDashboard dependencies (this may take a few minutes)..."
        cd "$wg_dash_dir/src" || error "Failed to change directory"
        ./wgd.sh install || error "WGDashboard installation failed"
    fi

    # Create systemd service
    log "Creating WGDashboard systemd service..."

    if [[ "$DRY_RUN" == "false" ]]; then
        cat > /etc/systemd/system/wgdashboard.service << 'EOF'
[Unit]
Description=WireGuard Dashboard
After=network.target
Wants=wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=/opt/WGDashboard/src
ExecStart=/bin/bash -c '/opt/WGDashboard/src/wgd.sh start && while true; do sleep 3600; done'
Restart=on-failure
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Enable and start service
    exec_cmd systemctl daemon-reload
    exec_cmd systemctl enable wgdashboard
    exec_cmd systemctl start wgdashboard

    # Verify service started
    if [[ "$DRY_RUN" == "false" ]]; then
        sleep 3
        if systemctl is-active --quiet wgdashboard; then
            log "WGDashboard is running"
        else
            warning "WGDashboard service may not have started correctly"
        fi
    fi

    log "WGDashboard installation completed"
}

# =============================================================================
# NETDATA MONITORING FUNCTIONS
# =============================================================================

# Install Netdata monitoring system
install_netdata() {
    section "Installing Netdata Monitoring"

    if [[ "$INSTALL_NETDATA" != "true" ]]; then
        log "Skipping Netdata installation (disabled)"
        return 0
    fi

    # Check if already installed
    if systemctl is-active --quiet netdata 2>/dev/null; then
        log "Netdata already installed and running"
        return 0
    fi

    log "Installing Netdata dependencies..."
    exec_cmd apt-get install -y zlib1g-dev uuid-dev libuv1-dev liblz4-dev libssl-dev libmnl-dev || warning "Some Netdata dependencies may be missing"

    log "Installing Netdata (this may take several minutes)..."

    if [[ "$DRY_RUN" == "false" ]]; then
        # Download and execute installer
        bash <(curl -Ss --max-time 30 https://get.netdata.cloud/kickstart.sh) \
            --stable-channel \
            --disable-telemetry \
            --dont-wait \
            --no-updates || error "Netdata installation failed"
    fi

    # Configure Netdata for local-only access
    log "Configuring Netdata for secure access..."

    if [[ "$DRY_RUN" == "false" ]] && [[ -f "/etc/netdata/netdata.conf" ]]; then
        # Backup original config
        if [[ ! -f "/etc/netdata/netdata.conf.orig" ]]; then
            cp /etc/netdata/netdata.conf /etc/netdata/netdata.conf.orig
        fi

        cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    run as user = netdata
    web files owner = root
    web files group = root

[web]
    default port = 19999
    bind to = localhost
EOF
    fi

    # Disable cloud connection
    if [[ "$DRY_RUN" == "false" ]] && [[ -f "/etc/netdata/cloud.conf" ]]; then
        if [[ ! -f "/etc/netdata/cloud.conf.orig" ]]; then
            cp /etc/netdata/cloud.conf /etc/netdata/cloud.conf.orig
        fi

        cat > /etc/netdata/cloud.conf << 'EOF'
[global]
    enabled = no
    cloud base url =
EOF
    fi

    # Restart Netdata
    exec_cmd systemctl restart netdata

    # Verify service
    if [[ "$DRY_RUN" == "false" ]]; then
        sleep 2
        if systemctl is-active --quiet netdata; then
            log "Netdata monitoring is running"
        else
            warning "Netdata service may not have started correctly"
        fi
    fi

    log "Netdata installation completed"
}

# =============================================================================
# NGINX REVERSE PROXY CONFIGURATION
# =============================================================================

# Configure Nginx as reverse proxy
configure_nginx() {
    section "Configuring Nginx Reverse Proxy"

    log "Setting up Netdata authentication..."

    # Create htpasswd for Netdata access
    if [[ "$DRY_RUN" == "false" ]]; then
        htpasswd -c /etc/nginx/.htpasswd "$USER_ACCOUNT_NAME" || error "Failed to create htpasswd file"
    fi

    log "Creating Nginx configuration..."

    if [[ "$DRY_RUN" == "false" ]]; then
        # Backup original config
        if [[ ! -f /etc/nginx/sites-available/default.orig ]]; then
            cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.orig
        fi

        cat > /etc/nginx/sites-available/default << 'EOF'
# Netdata backend
upstream netdatabackend {
    server 127.0.0.1:19999;
    keepalive 1024;
}

# WGDashboard backend
upstream wgdashboard {
    server 127.0.0.1:10086;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options SAMEORIGIN;
    add_header Referrer-Policy strict-origin-when-cross-origin;

    # Netdata monitoring endpoint
    location = /netdata {
        return 301 $scheme://$host:$server_port/netdata/;
    }

    location ^~ /netdata/ {
        auth_basic "Authentication Required";
        auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Server $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_pass_request_headers on;
        proxy_set_header Connection "keep-alive";
        proxy_store off;
        proxy_pass http://netdatabackend/;

        gzip on;
        gzip_proxied any;
        gzip_types *;

        # Timeout settings
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;

        access_log /var/log/nginx/netdata.access.log;
        error_log /var/log/nginx/netdata.error.log;
    }

    # WGDashboard endpoint (root)
    location / {
        proxy_pass http://wgdashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        access_log /var/log/nginx/wgdashboard.access.log;
        error_log /var/log/nginx/wgdashboard.error.log;
    }
}
EOF
    fi

    # Test Nginx configuration
    if [[ "$DRY_RUN" == "false" ]]; then
        nginx -t || error "Nginx configuration test failed"
    fi

    # Restart Nginx
    exec_cmd systemctl restart nginx

    # Get SSL certificate if enabled
    if [[ "$ENABLE_SSL" == "true" ]]; then
        log "Requesting SSL certificate from Let's Encrypt..."

        if [[ "$DRY_RUN" == "false" ]]; then
            if certbot --nginx -d "$HOST_FQDN" --non-interactive --agree-tos --email "root@$HOST_FQDN" 2>&1; then
                log "SSL certificate obtained successfully"

                # Add additional SSL hardening
                if ! grep -q "ssl_stapling" /etc/nginx/sites-available/default; then
                    sed -i '/server_name/a \    # SSL hardening\n    ssl_stapling on;\n    ssl_stapling_verify on;\n    resolver 1.1.1.1 8.8.8.8 valid=300s;\n    resolver_timeout 5s;\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' /etc/nginx/sites-available/default

                    # Test and restart again
                    nginx -t || error "Nginx SSL configuration test failed"
                    systemctl restart nginx
                fi

                log "SSL/TLS configuration completed"
            else
                warning "Let's Encrypt certificate request failed"
                warning "This usually means DNS is not properly configured for $HOST_FQDN"

                read -rp "Continue without SSL/TLS? Enter 'INSECURE' to proceed: " no_tls_response
                if [[ "$no_tls_response" != "INSECURE" ]]; then
                    error "Aborted due to SSL certificate failure"
                fi

                warning "Continuing without SSL/TLS - connections will NOT be encrypted!"
            fi
        fi
    else
        log "SSL/TLS disabled - skipping certificate request"
    fi

    log "Nginx configuration completed"
}

# =============================================================================
# CREDENTIALS AND DOCUMENTATION
# =============================================================================

# Create credentials file
create_credentials() {
    section "Saving Configuration and Credentials"

    log "Creating credentials file..."

    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p /root/vpn_credentials

        local server_public_key=""
        local client1_public_key=""

        if [[ -f /etc/wireguard/server.pub ]]; then
            server_public_key=$(cat /etc/wireguard/server.pub)
        fi

        if [[ -f /etc/wireguard/clients/client1.pub ]]; then
            client1_public_key=$(cat /etc/wireguard/clients/client1.pub)
        fi

        local protocol="http"
        if [[ "$ENABLE_SSL" == "true" ]]; then
            protocol="https"
        fi

        cat > /root/vpn_credentials/vpn_info.txt << EOF
========================================================
VPS SECURITY & WIREGUARD SETUP INFORMATION
========================================================
Setup Date: $(date)
Script Version: 2.0
Host FQDN: ${HOST_FQDN}
Public IP: ${PUBLIC_IP}

--------------------------------------------------------
SSH ACCESS
--------------------------------------------------------
SSH Port: ${SSH_PORT}
Username: ${USER_ACCOUNT_NAME}
SSH Key: ${SSH_PUBLIC_KEY:+Installed}${SSH_PUBLIC_KEY:-Not configured}

IMPORTANT: Only SSH key authentication is allowed.
Password authentication is DISABLED for security.

--------------------------------------------------------
WIREGUARD VPN SERVER
--------------------------------------------------------
Server Public Key: ${server_public_key}
Server IP: ${WG_SERVER_IP%/*}
Server Port: ${WG_PORT}
Interface: wg0

--------------------------------------------------------
WIREGUARD CLIENT 1
--------------------------------------------------------
Client Public Key: ${client1_public_key}
Client IP: 10.10.10.2
Configuration: /etc/wireguard/clients/client1.conf
QR Code: /etc/wireguard/clients/client1_qr.txt

To display QR code for mobile setup:
    cat /etc/wireguard/clients/client1_qr.txt

--------------------------------------------------------
WGDASHBOARD WEB INTERFACE
--------------------------------------------------------
URL: ${protocol}://${HOST_FQDN}/
Default Username: admin
Default Password: admin
** CHANGE THE DEFAULT PASSWORD IMMEDIATELY **

--------------------------------------------------------
NETDATA MONITORING
--------------------------------------------------------
$(if [[ "$INSTALL_NETDATA" == "true" ]]; then
    echo "URL: ${protocol}://${HOST_FQDN}/netdata/"
    echo "Username: ${USER_ACCOUNT_NAME}"
    echo "Password: (as configured during setup)"
else
    echo "Not installed"
fi)

--------------------------------------------------------
SECURITY INFORMATION
--------------------------------------------------------
Firewall: UFW enabled
Intrusion Prevention: Fail2Ban active
SSH Root Login: Key-only (no password)
Password Auth: Disabled
Auto Updates: Enabled (daily security patches)
Auto Reboot: Enabled (02:00 if needed for updates)

--------------------------------------------------------
IMPORTANT SECURITY REMINDERS
--------------------------------------------------------
1. Change WGDashboard default password immediately
2. Keep your SSH private key secure
3. Review firewall rules: ufw status
4. Monitor fail2ban: fail2ban-client status
5. Check WireGuard status: wg show
6. View logs: tail -f ${LOG_FILE}

========================================================
STORE THIS FILE SECURELY - IT CONTAINS SENSITIVE INFO
========================================================
EOF

        # Secure the credentials file
        chmod 600 /root/vpn_credentials/vpn_info.txt
    fi

    log "Credentials saved to /root/vpn_credentials/vpn_info.txt"
}

# =============================================================================
# COMPLETION AND SUMMARY
# =============================================================================

# Display completion message
show_completion() {
    local duration=$(($(date +%s) - SCRIPT_START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SETUP COMPLETED SUCCESSFULLY! ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Your VPS has been configured with:"
    echo -e "  ${GREEN}✓${NC} System hardening and security updates"
    echo -e "  ${GREEN}✓${NC} WireGuard VPN server"
    echo -e "  ${GREEN}✓${NC} WGDashboard web interface"
    if [[ "$INSTALL_NETDATA" == "true" ]]; then
        echo -e "  ${GREEN}✓${NC} Netdata system monitoring"
    fi
    echo -e "  ${GREEN}✓${NC} Firewall and intrusion prevention"
    echo ""

    local protocol="http"
    [[ "$ENABLE_SSL" == "true" ]] && protocol="https"

    echo -e "${BLUE}Access Points:${NC}"
    echo -e "  WGDashboard: ${CYAN}${protocol}://${HOST_FQDN}/${NC}"
    if [[ "$INSTALL_NETDATA" == "true" ]]; then
        echo -e "  Netdata:     ${CYAN}${protocol}://${HOST_FQDN}/netdata/${NC}"
    fi
    echo ""

    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Change WGDashboard password (default: admin/admin)"
    echo "  2. Download client config: /etc/wireguard/clients/client1.conf"
    echo "  3. Or scan QR code: cat /etc/wireguard/clients/client1_qr.txt"
    echo "  4. View full info: cat /root/vpn_credentials/vpn_info.txt"
    echo ""

    echo -e "${YELLOW}Security Reminders:${NC}"
    echo "  • Change default WGDashboard password NOW"
    echo "  • Keep your SSH private key secure"
    echo "  • Store client VPN configs safely"
    echo ""

    echo -e "Setup completed in ${minutes}m ${seconds}s"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-netdata)
                INSTALL_NETDATA=false
                shift
                ;;
            --skip-ssl)
                ENABLE_SSL=false
                shift
                ;;
            -u|--username)
                USER_ACCOUNT_NAME="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"

    # Initial checks
    check_root
    check_os
    init_log

    # Bootstrap critical tools for minimal installations
    # This MUST run before any network operations
    bootstrap_critical_tools

    # Load configuration if exists
    load_config

    # Network setup (now safe to use curl, dig, ping, timeout)
    test_network
    get_public_ip
    get_host_fqdn

    # Package installation
    preseed_postfix_settings
    install_packages

    # System hardening
    setup_unattended_upgrades
    harden_sysctl

    # User and SSH configuration
    select_user_name
    get_pubkey
    secure_ssh
    install_user_ssh_pubkey root /root "$SSH_PUBLIC_KEY"
    install_user_ssh_pubkey "$USER_ACCOUNT_NAME" "/home/$USER_ACCOUNT_NAME" "$SSH_PUBLIC_KEY"

    # Security
    setup_firewall

    # VPN installation
    install_wireguard
    install_wgdashboard

    # Optional: Netdata monitoring
    if [[ "$INSTALL_NETDATA" == "true" ]]; then
        install_netdata
    fi

    # Web interface configuration
    configure_nginx

    # Documentation
    create_credentials
    show_completion

    log "Installation completed successfully"
}

# Run the script
main "$@"
