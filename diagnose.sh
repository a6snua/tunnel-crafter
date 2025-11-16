#!/bin/bash
# =============================================================================
# GemiLab Tunnel Crafter - WireGuard Diagnostic Script
# Version: 1.1
# Description: Comprehensive diagnostics for WireGuard VPN connectivity issues
# Features: Auto-detects WireGuard interfaces, supports custom interface names,
#           checks NAT/masquerading, validates iptables rules positioning
# =============================================================================

set -uo pipefail

# =============================================================================
# TERMINAL COLORS
# =============================================================================
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0
CRITICAL_ISSUES=()
WARNINGS=()

# WireGuard interface configuration
WG_INTERFACE=""           # Will be auto-detected or specified via command-line
WG_INTERFACES=()          # Array of all detected WireGuard interfaces
WG_CONFIG_FILE=""         # Will be set based on interface name

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

pass() {
    local msg="$1"
    echo -e "${GREEN}[PASS]${NC} $msg"
    ((PASSED_CHECKS++))
    ((TOTAL_CHECKS++))
}

fail() {
    local msg="$1"
    local detail="${2:-}"
    echo -e "${RED}[FAIL]${NC} $msg"
    if [[ -n "$detail" ]]; then
        echo -e "       ${RED}↳${NC} $detail"
        CRITICAL_ISSUES+=("$msg: $detail")
    else
        CRITICAL_ISSUES+=("$msg")
    fi
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

warn() {
    local msg="$1"
    local detail="${2:-}"
    echo -e "${YELLOW}[WARN]${NC} $msg"
    if [[ -n "$detail" ]]; then
        echo -e "       ${YELLOW}↳${NC} $detail"
        WARNINGS+=("$msg: $detail")
    else
        WARNINGS+=("$msg")
    fi
    ((WARNING_CHECKS++))
    ((TOTAL_CHECKS++))
}

info() {
    local msg="$1"
    echo -e "${BLUE}[INFO]${NC} $msg"
}

section() {
    local msg="$1"
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}  $msg${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                            ║${NC}"
    echo -e "${CYAN}║     ${BOLD}GemiLab Tunnel Crafter - VPN Diagnostics${NC}${CYAN}           ║${NC}"
    echo -e "${CYAN}║                    Version 1.1                             ║${NC}"
    echo -e "${CYAN}║                                                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    if [[ -n "$WG_INTERFACE" ]]; then
        info "Checking WireGuard interface: ${BOLD}${WG_INTERFACE}${NC}"
        echo ""
    fi
}

# =============================================================================
# WIREGUARD INTERFACE DETECTION
# =============================================================================

# Detect all WireGuard interfaces on the system
detect_wireguard_interfaces() {
    local detected_interfaces=()

    # Method 1: Check for interfaces using 'ip link' (most reliable)
    while IFS= read -r iface; do
        detected_interfaces+=("$iface")
    done < <(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}')

    # Method 2: Check for running wg interfaces via 'wg show interfaces'
    if command -v wg &>/dev/null; then
        local wg_interfaces
        wg_interfaces=$(wg show interfaces 2>/dev/null)
        if [[ -n "$wg_interfaces" ]]; then
            for iface in $wg_interfaces; do
                # Add if not already in array
                if [[ ! " ${detected_interfaces[*]} " =~ " ${iface} " ]]; then
                    detected_interfaces+=("$iface")
                fi
            done
        fi
    fi

    # Method 3: Check for config files in /etc/wireguard/
    if [[ -d /etc/wireguard ]]; then
        for conf_file in /etc/wireguard/*.conf; do
            if [[ -f "$conf_file" ]]; then
                local iface_name=$(basename "$conf_file" .conf)
                # Add if not already in array and if interface exists
                if [[ ! " ${detected_interfaces[*]} " =~ " ${iface_name} " ]]; then
                    # Only add if interface actually exists or config exists
                    if ip link show "$iface_name" &>/dev/null || [[ -f "/etc/wireguard/${iface_name}.conf" ]]; then
                        detected_interfaces+=("$iface_name")
                    fi
                fi
            fi
        done
    fi

    WG_INTERFACES=("${detected_interfaces[@]}")
}

# Select WireGuard interface to check
select_wireguard_interface() {
    # If interface specified via command-line, use it
    if [[ -n "$WG_INTERFACE" ]]; then
        info "Using specified WireGuard interface: $WG_INTERFACE"
        WG_CONFIG_FILE="/etc/wireguard/${WG_INTERFACE}.conf"
        return 0
    fi

    # Detect all interfaces
    detect_wireguard_interfaces

    # If no interfaces found
    if [[ ${#WG_INTERFACES[@]} -eq 0 ]]; then
        warn "No WireGuard interfaces detected"
        info "Defaulting to 'wg0' for config file checks"
        WG_INTERFACE="wg0"
        WG_CONFIG_FILE="$WG_CONFIG_FILE"
        return 1
    fi

    # If only one interface found, use it
    if [[ ${#WG_INTERFACES[@]} -eq 1 ]]; then
        WG_INTERFACE="${WG_INTERFACES[0]}"
        WG_CONFIG_FILE="/etc/wireguard/${WG_INTERFACE}.conf"
        info "Auto-detected WireGuard interface: $WG_INTERFACE"
        return 0
    fi

    # Multiple interfaces found - use the first one, but notify user
    WG_INTERFACE="${WG_INTERFACES[0]}"
    WG_CONFIG_FILE="/etc/wireguard/${WG_INTERFACE}.conf"
    info "Multiple WireGuard interfaces detected: ${WG_INTERFACES[*]}"
    info "Checking primary interface: $WG_INTERFACE"
    info "To check a specific interface, run: $0 -i <interface>"
    return 0
}

# =============================================================================
# COMMAND-LINE ARGUMENT PARSING
# =============================================================================

usage() {
    cat << EOF
${BOLD}GemiLab Tunnel Crafter - WireGuard VPN Diagnostics${NC}

${GREEN}Usage:${NC}
    $0 [OPTIONS]

${GREEN}Options:${NC}
    -h, --help              Show this help message
    -i, --interface NAME    Check specific WireGuard interface (default: auto-detect)
    -a, --all              Check all detected WireGuard interfaces

${GREEN}Examples:${NC}
    # Auto-detect and check WireGuard interface
    sudo $0

    # Check specific interface
    sudo $0 -i wg0
    sudo $0 -i wg-vpn

    # Check all interfaces
    sudo $0 --all

${YELLOW}Note:${NC} This script must be run as root.

EOF
    exit 0
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                ;;
            -i|--interface)
                if [[ -z "${2:-}" ]]; then
                    echo -e "${RED}Error: --interface requires an argument${NC}" >&2
                    exit 1
                fi
                WG_INTERFACE="$2"
                shift 2
                ;;
            -a|--all)
                echo -e "${YELLOW}Checking all WireGuard interfaces is not yet implemented${NC}"
                echo -e "${YELLOW}Defaulting to primary interface${NC}"
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                usage
                ;;
        esac
    done
}

# =============================================================================
# ROOT CHECK
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}" >&2
        echo "Try: sudo $0" >&2
        exit 1
    fi
}

# =============================================================================
# SYSTEM INFORMATION
# =============================================================================
check_system_info() {
    section "System Information"

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        info "OS: $PRETTY_NAME"
        info "Kernel: $(uname -r)"
        info "Architecture: $(uname -m)"
    else
        warn "Cannot determine OS version"
    fi

    info "Hostname: $(hostname)"
    info "Uptime: $(uptime -p 2>/dev/null || uptime)"
}

# =============================================================================
# PACKAGE CHECKS
# =============================================================================
check_packages() {
    section "Required Packages"

    local packages=("wireguard" "wireguard-tools" "ufw" "nginx" "iptables")

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            pass "Package installed: $pkg"
        else
            fail "Package missing: $pkg"
        fi
    done
}

# =============================================================================
# WIREGUARD CHECKS
# =============================================================================
check_wireguard_installation() {
    section "WireGuard Installation"

    # Check if WireGuard kernel module is available
    if lsmod | grep -q wireguard || modprobe -n wireguard &>/dev/null; then
        pass "WireGuard kernel module available"
    else
        fail "WireGuard kernel module not available"
    fi

    # Check wg command
    if command -v wg &>/dev/null; then
        pass "WireGuard tools (wg) installed"
        info "Version: $(wg --version 2>&1 | head -n1)"
    else
        fail "WireGuard tools (wg) not found"
    fi

    # Check wg-quick
    if command -v wg-quick &>/dev/null; then
        pass "WireGuard quick (wg-quick) installed"
    else
        fail "WireGuard quick (wg-quick) not found"
    fi
}

check_wireguard_configuration() {
    section "WireGuard Configuration Files"

    # Check WireGuard directory
    if [[ -d /etc/wireguard ]]; then
        pass "WireGuard directory exists: /etc/wireguard"

        # Check permissions
        local perms=$(stat -c "%a" /etc/wireguard)
        if [[ "$perms" == "700" ]]; then
            pass "WireGuard directory permissions correct (700)"
        else
            warn "WireGuard directory permissions: $perms (should be 700)"
        fi
    else
        fail "WireGuard directory missing: /etc/wireguard"
        return
    fi

    # Check for wg0.conf
    if [[ -f $WG_CONFIG_FILE ]]; then
        pass "WireGuard config exists: $WG_CONFIG_FILE"

        # Check permissions
        local perms=$(stat -c "%a" $WG_CONFIG_FILE)
        if [[ "$perms" == "600" ]]; then
            pass "WireGuard config permissions correct (600)"
        else
            warn "WireGuard config permissions: $perms (should be 600)"
        fi

        # Check for required fields
        if grep -q "^PrivateKey" $WG_CONFIG_FILE; then
            pass "PrivateKey present in config"
        else
            fail "PrivateKey missing in config"
        fi

        if grep -q "^ListenPort" $WG_CONFIG_FILE; then
            pass "ListenPort present in config"
            local port=$(grep "^ListenPort" $WG_CONFIG_FILE | awk '{print $3}')
            info "WireGuard listening on port: $port"
        else
            warn "ListenPort not specified in config"
        fi

        if grep -q "^Address" $WG_CONFIG_FILE; then
            pass "Address present in config"
            local addr=$(grep "^Address" $WG_CONFIG_FILE | awk '{print $3}')
            info "WireGuard server address: $addr"
        else
            fail "Address missing in config"
        fi

        # CRITICAL: Check for PostUp/PostDown rules (NAT configuration)
        if grep -q "^PostUp" $WG_CONFIG_FILE; then
            pass "PostUp rules present in config"
            grep "^PostUp" $WG_CONFIG_FILE | while read -r line; do
                info "  $line"
            done
        else
            fail "PostUp rules MISSING in config" "NAT/masquerading not configured - this is why traffic doesn't work!"
        fi

        if grep -q "^PostDown" $WG_CONFIG_FILE; then
            pass "PostDown rules present in config"
        else
            fail "PostDown rules MISSING in config" "Cleanup rules not configured"
        fi

        # Check for SaveConfig (critical issue!)
        if grep -q "^SaveConfig.*true" $WG_CONFIG_FILE; then
            fail "SaveConfig is enabled" "Will ERASE PostUp/PostDown rules on shutdown! Set to 'false' or remove this line"
        fi

        # Count peers
        local peer_count=$(grep -c "^\[Peer\]" $WG_CONFIG_FILE)
        if [[ $peer_count -gt 0 ]]; then
            pass "Peer configurations found: $peer_count peer(s)"
        else
            warn "No peers configured"
        fi

    else
        fail "WireGuard config missing: $WG_CONFIG_FILE"
    fi

    # Check for keys
    if [[ -f /etc/wireguard/server.key ]]; then
        pass "Server private key exists"
        local perms=$(stat -c "%a" /etc/wireguard/server.key)
        if [[ "$perms" == "600" ]]; then
            pass "Server private key permissions correct (600)"
        else
            warn "Server private key permissions: $perms (should be 600)"
        fi
    else
        fail "Server private key missing: /etc/wireguard/server.key"
    fi

    if [[ -f /etc/wireguard/server.pub ]]; then
        pass "Server public key exists"
    else
        warn "Server public key missing: /etc/wireguard/server.pub"
    fi
}

check_wireguard_service() {
    section "WireGuard Service Status"

    # Check if service exists
    if systemctl list-unit-files | grep -q "wg-quick@$WG_INTERFACE"; then
        pass "WireGuard service unit exists: wg-quick@$WG_INTERFACE"
    else
        info "WireGuard service unit not found (may be started manually)"

        # Check if interface exists anyway
        if ip link show $WG_INTERFACE &>/dev/null; then
            info "WireGuard interface exists (started manually, not via systemd)"
            info "To manage via systemd: wg-quick down $WG_INTERFACE && systemctl enable --now wg-quick@$WG_INTERFACE"
        fi
        return
    fi

    # Check if enabled
    if systemctl is-enabled wg-quick@$WG_INTERFACE &>/dev/null; then
        pass "WireGuard service enabled (will start on boot)"
    else
        warn "WireGuard service not enabled" "Enable with: systemctl enable wg-quick@$WG_INTERFACE"
    fi

    # Check if active
    if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        pass "WireGuard service is running"
    else
        # Check if interface exists (manually started)
        if ip link show $WG_INTERFACE &>/dev/null; then
            info "WireGuard interface is up (started manually, not via systemd)"
        else
            fail "WireGuard service is NOT running" "Run: systemctl start wg-quick@$WG_INTERFACE"
        fi
        return
    fi

    # Check service logs for errors
    if journalctl -u wg-quick@$WG_INTERFACE --since "10 minutes ago" 2>/dev/null | grep -qi "error\|fail"; then
        warn "Errors found in service logs (last 10 minutes)"
        info "Check with: journalctl -u wg-quick@$WG_INTERFACE -n 50"
    else
        pass "No recent errors in service logs"
    fi
}

check_wireguard_interface() {
    section "WireGuard Interface Status"

    # Check if wg0 interface exists
    if ip link show $WG_INTERFACE &>/dev/null; then
        pass "WireGuard interface '$WG_INTERFACE' exists"

        # Check if interface is up
        if ip link show $WG_INTERFACE | grep -q "state UP"; then
            pass "WireGuard interface is UP"
        else
            fail "WireGuard interface is DOWN" "Run: wg-quick up $WG_INTERFACE"
        fi

        # Check interface IP address
        local wg_ip=$(ip -4 addr show $WG_INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1)
        if [[ -n "$wg_ip" ]]; then
            pass "WireGuard interface has IP: $wg_ip"
        else
            fail "WireGuard interface has no IP address"
        fi

    else
        fail "WireGuard interface '$WG_INTERFACE' does NOT exist" "WireGuard is not running"
        return
    fi

    # Check WireGuard status with wg command
    if wg show $WG_INTERFACE &>/dev/null; then
        pass "WireGuard interface status available"

        # Get listening port
        local listen_port=$(wg show $WG_INTERFACE listen-port 2>/dev/null)
        if [[ -n "$listen_port" ]]; then
            info "Listening port: $listen_port"
        fi

        # Get peer count
        local peer_count=$(wg show $WG_INTERFACE peers 2>/dev/null | wc -l)
        info "Connected peers: $peer_count"

        # Check each peer
        if [[ $peer_count -gt 0 ]]; then
            echo ""
            info "Peer Details:"
            wg show $WG_INTERFACE peers | while read -r peer_pubkey; do
                echo -e "${CYAN}    Peer: ${peer_pubkey:0:20}...${NC}"

                # Get peer endpoint
                local endpoint=$(wg show $WG_INTERFACE endpoints | grep "$peer_pubkey" | awk '{print $2}')
                if [[ -n "$endpoint" ]]; then
                    echo -e "      Endpoint: $endpoint"
                else
                    echo -e "      ${YELLOW}Endpoint: Not connected yet${NC}"
                fi

                # Get latest handshake
                local handshake=$(wg show $WG_INTERFACE latest-handshakes | grep "$peer_pubkey" | awk '{print $2}')
                if [[ -n "$handshake" ]] && [[ "$handshake" != "0" ]]; then
                    local now=$(date +%s)
                    local age=$((now - handshake))

                    if [[ $age -lt 180 ]]; then
                        echo -e "      ${GREEN}Last handshake: ${age}s ago (active)${NC}"
                    else
                        echo -e "      ${YELLOW}Last handshake: ${age}s ago (stale)${NC}"
                    fi
                else
                    echo -e "      ${RED}Last handshake: Never${NC}"
                fi

                # Get transfer
                local transfer=$(wg show $WG_INTERFACE transfer | grep "$peer_pubkey")
                local rx=$(echo "$transfer" | awk '{print $2}')
                local tx=$(echo "$transfer" | awk '{print $3}')

                if [[ -n "$rx" ]] && [[ -n "$tx" ]]; then
                    local rx_mb=$((rx / 1048576))
                    local tx_mb=$((tx / 1048576))

                    if [[ $rx -gt 1000 ]] && [[ $tx -gt 1000 ]]; then
                        echo -e "      ${GREEN}Transfer: ↓ ${rx_mb}MB / ↑ ${tx_mb}MB${NC}"
                    else
                        echo -e "      ${RED}Transfer: ↓ ${rx}B / ↑ ${tx}B (NO TRAFFIC!)${NC}"
                    fi
                fi

                # Get allowed IPs
                local allowed=$(wg show $WG_INTERFACE allowed-ips | grep "$peer_pubkey" | cut -d$'\t' -f2-)
                if [[ -n "$allowed" ]]; then
                    echo -e "      Allowed IPs: $allowed"
                fi

                echo ""
            done
        fi
    else
        fail "Cannot get WireGuard interface status"
    fi
}

# =============================================================================
# NETWORK CONFIGURATION CHECKS
# =============================================================================
check_ip_forwarding() {
    section "IP Forwarding (Required for VPN)"

    # Check current runtime status
    local ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$ipv4_forward" == "1" ]]; then
        pass "IPv4 forwarding is ENABLED (runtime)"
    else
        fail "IPv4 forwarding is DISABLED (runtime)" "Traffic cannot be routed! Enable with: sysctl -w net.ipv4.ip_forward=1"
    fi

    # Check if it's persistent in sysctl.conf
    if grep -q "^net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        pass "IPv4 forwarding is configured to persist across reboots"
    else
        warn "IPv4 forwarding may not persist after reboot" "Add to /etc/sysctl.d/99-security.conf: net.ipv4.ip_forward = 1"
    fi
}

check_nat_masquerading() {
    section "NAT/Masquerading (Critical for VPN)"

    # Determine default network interface
    local default_iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')
    if [[ -n "$default_iface" ]]; then
        info "Default network interface: $default_iface"
    else
        warn "Could not determine default network interface"
        default_iface="UNKNOWN"
    fi

    # Check if UFW is active
    local ufw_active=false
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw_active=true
        info "UFW firewall detected and active"
    fi

    # Check iptables for NAT rules
    local nat_rules_found=false
    local forward_rules_found=false
    local forward_rules_properly_positioned=false

    # Check for MASQUERADE rule
    if iptables -t nat -L POSTROUTING -v -n 2>/dev/null | grep -q "MASQUERADE.*$default_iface"; then
        pass "iptables MASQUERADE rule found for $default_iface"
        nat_rules_found=true
    else
        fail "iptables MASQUERADE rule NOT found for $default_iface" "VPN traffic cannot reach the internet!"
    fi

    # Show current NAT table
    info "Current NAT table (POSTROUTING chain):"
    if command -v iptables &>/dev/null; then
        iptables -t nat -L POSTROUTING -v -n --line-numbers 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -q "MASQUERADE.*$default_iface"; then
                echo -e "      ${GREEN}$line${NC}"
            else
                echo -e "      $line"
            fi
        done
    fi

    # Check for FORWARD chain rules
    echo ""
    info "Checking FORWARD chain rules..."

    # Get full FORWARD chain
    local forward_output=$(iptables -L FORWARD -v -n --line-numbers 2>/dev/null)

    if echo "$forward_output" | grep -q "$WG_INTERFACE"; then
        forward_rules_found=true

        # Check POSITION of wg0 rules relative to UFW chains
        local wg0_line=$(echo "$forward_output" | grep -n "wg0" | head -1 | cut -d: -f1)
        local ufw_line=$(echo "$forward_output" | grep -n "ufw-" | head -1 | cut -d: -f1)

        if [[ -n "$wg0_line" ]] && [[ -n "$ufw_line" ]]; then
            if [[ $wg0_line -lt $ufw_line ]]; then
                pass "FORWARD chain rules for wg0 are BEFORE UFW chains (correct position)"
                forward_rules_properly_positioned=true
            else
                fail "FORWARD chain rules for wg0 are AFTER UFW chains" "Rules will never be reached! Use -I instead of -A"
            fi
        elif [[ -n "$wg0_line" ]]; then
            pass "FORWARD chain rules found for wg0"
            forward_rules_properly_positioned=true
        fi

        # Show packet counts
        local wg0_rules=$(echo "$forward_output" | grep "$WG_INTERFACE")
        if echo "$wg0_rules" | grep -q "^\s*[1-9]"; then
            pass "FORWARD rules are processing packets (good sign!)"
            echo "$wg0_rules" | while IFS= read -r line; do
                echo -e "      ${GREEN}$line${NC}"
            done
        else
            warn "FORWARD rules exist but show 0 packets" "No traffic has been forwarded yet (no clients connected?)"
            echo "$wg0_rules" | while IFS= read -r line; do
                echo -e "      ${YELLOW}$line${NC}"
            done
        fi
    else
        fail "No specific FORWARD chain rules for wg0" "Packets will be blocked by firewall"
        forward_rules_found=false
    fi

    # Check FORWARD chain default policy
    local forward_policy=$(iptables -L FORWARD -n 2>/dev/null | grep "^Chain FORWARD" | awk '{print $4}' | tr -d '()')
    if [[ "$forward_policy" == "ACCEPT" ]]; then
        info "FORWARD chain default policy: ACCEPT"
    elif [[ "$forward_policy" == "DROP" ]]; then
        if [[ "$forward_rules_properly_positioned" == "true" ]]; then
            info "FORWARD chain default policy: DROP (OK - wg0 rules come first)"
        else
            warn "FORWARD chain default policy: DROP" "Will block VPN traffic!"
        fi
    else
        warn "FORWARD chain default policy: $forward_policy"
    fi

    # Provide fix if NAT not configured
    if [[ "$nat_rules_found" == "false" ]] || [[ "$forward_rules_found" == "false" ]] || [[ "$forward_rules_properly_positioned" == "false" ]]; then
        echo ""
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  CRITICAL: NAT/MASQUERADING NOT CONFIGURED PROPERLY!     ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}This is the most likely cause of your connectivity issue!${NC}"
        echo ""

        if [[ "$ufw_active" == "true" ]]; then
            echo -e "${CYAN}UFW is active - you MUST use -I (insert) instead of -A (append)${NC}"
            echo -e "${CYAN}This places wg0 rules BEFORE UFW's DROP policy.${NC}"
            echo ""
        fi

        echo -e "${CYAN}To fix, add these lines to $WG_CONFIG_FILE:${NC}"
        echo ""

        if [[ "$ufw_active" == "true" ]]; then
            echo -e "${BOLD}PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT${NC}"
            echo -e "${BOLD}PostUp = iptables -I FORWARD 1 -o wg0 -j ACCEPT${NC}"
        else
            echo -e "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT"
            echo -e "PostUp = iptables -A FORWARD -o wg0 -j ACCEPT"
        fi

        echo -e "PostUp = iptables -t nat -A POSTROUTING -o $default_iface -j MASQUERADE"
        echo -e "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT"
        echo -e "PostDown = iptables -D FORWARD -o wg0 -j ACCEPT"
        echo -e "PostDown = iptables -t nat -D POSTROUTING -o $default_iface -j MASQUERADE"
        echo ""
        echo -e "${CYAN}Then restart WireGuard:${NC}"

        if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
            echo -e "  systemctl restart wg-quick@$WG_INTERFACE"
        else
            echo -e "  wg-quick down $WG_INTERFACE (if running manually)"
            echo -e "  wg-quick up $WG_INTERFACE"
        fi
        echo ""
    fi
}

# =============================================================================
# FIREWALL CHECKS
# =============================================================================
check_firewall() {
    section "Firewall Configuration (UFW)"

    # Check if UFW is installed
    if ! command -v ufw &>/dev/null; then
        warn "UFW not installed"
        return
    fi

    # Check UFW status
    if ufw status | grep -q "Status: active"; then
        pass "UFW firewall is active"
    else
        warn "UFW firewall is inactive"
    fi

    # Check WireGuard port
    local wg_port=$(grep "^ListenPort" $WG_CONFIG_FILE 2>/dev/null | awk '{print $3}')
    if [[ -n "$wg_port" ]]; then
        if ufw status | grep -q "${wg_port}/udp.*ALLOW"; then
            pass "UFW allows WireGuard port ${wg_port}/udp"
        else
            fail "UFW does NOT allow WireGuard port ${wg_port}/udp" "Add rule: ufw allow ${wg_port}/udp"
        fi
    fi

    # Check SSH port
    if ufw status | grep -q "22/tcp.*ALLOW\|OpenSSH.*ALLOW"; then
        pass "UFW allows SSH"
    else
        warn "UFW may not allow SSH" "Verify SSH access before enabling UFW"
    fi

    # Check HTTP/HTTPS for dashboard
    if ufw status | grep -q "80/tcp.*ALLOW\|'Nginx Full'.*ALLOW\|'WWW Full'.*ALLOW"; then
        pass "UFW allows HTTP (port 80)"
    else
        warn "UFW may not allow HTTP access to dashboard"
    fi

    if ufw status | grep -q "443/tcp.*ALLOW\|'Nginx Full'.*ALLOW\|'WWW Full'.*ALLOW"; then
        pass "UFW allows HTTPS (port 443)"
    else
        warn "UFW may not allow HTTPS access to dashboard"
    fi
}

# =============================================================================
# ROUTING CHECKS
# =============================================================================
check_routing() {
    section "Routing Configuration"

    # Check default route
    local default_route=$(ip -4 route show default 2>/dev/null | head -n1)
    if [[ -n "$default_route" ]]; then
        pass "Default route exists"
        info "$default_route"
    else
        fail "No default route found" "Server cannot reach internet"
    fi

    # Check WireGuard routes
    if ip -4 route | grep -q "$WG_INTERFACE"; then
        pass "Routes exist for wg0 interface"
        ip -4 route | grep "$WG_INTERFACE" | while IFS= read -r line; do
            info "  $line"
        done
    else
        warn "No routes configured for wg0 interface"
    fi
}

# =============================================================================
# DNS CHECKS
# =============================================================================
check_dns() {
    section "DNS Configuration"

    # Check system DNS
    if [[ -f /etc/resolv.conf ]]; then
        pass "/etc/resolv.conf exists"

        local nameservers=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}' | paste -sd "," -)
        if [[ -n "$nameservers" ]]; then
            info "System DNS servers: $nameservers"
        else
            warn "No nameservers configured in /etc/resolv.conf"
        fi
    else
        warn "/etc/resolv.conf not found"
    fi

    # Test DNS resolution
    if host google.com &>/dev/null || nslookup google.com &>/dev/null || dig google.com &>/dev/null; then
        pass "DNS resolution working"
    else
        warn "DNS resolution test failed" "May affect VPN client connectivity"
    fi
}

# =============================================================================
# CONNECTIVITY TESTS
# =============================================================================
check_connectivity() {
    section "Network Connectivity Tests"

    # Check internet connectivity
    if ping -c 2 -W 3 8.8.8.8 &>/dev/null; then
        pass "Can ping 8.8.8.8 (internet connectivity OK)"
    else
        fail "Cannot ping 8.8.8.8" "No internet connectivity"
    fi

    # Check DNS connectivity
    if ping -c 2 -W 3 google.com &>/dev/null; then
        pass "Can ping google.com (DNS working)"
    else
        warn "Cannot ping google.com" "DNS may not be working"
    fi

    # Check WireGuard can reach internet (if interface is up)
    if ip link show $WG_INTERFACE &>/dev/null && ip link show $WG_INTERFACE | grep -q "state UP"; then
        local wg_ip=$(ip -4 addr show $WG_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        if [[ -n "$wg_ip" ]]; then
            echo ""
            info "Testing server-originated traffic from wg0 interface..."
            info "(Note: This tests OUTPUT chain, not FORWARD chain used by clients)"

            # Try to ping from wg0 interface
            if ping -I $WG_INTERFACE -c 2 -W 3 8.8.8.8 &>/dev/null; then
                pass "Server can ping from wg0 interface"
            else
                warn "Server cannot ping from wg0 interface (not critical)"
                info "Server-originated traffic uses OUTPUT chain, which may be restricted by UFW"
                info "CLIENT traffic uses FORWARD chain and may still work fine"
                info "Test with an actual VPN client to verify client routing"
            fi
        fi
    fi

    # Check for active client connections
    echo ""
    info "Checking for active client connections..."

    if command -v wg &>/dev/null && ip link show $WG_INTERFACE &>/dev/null; then
        local peer_count=$(wg show $WG_INTERFACE peers 2>/dev/null | wc -l)

        if [[ $peer_count -gt 0 ]]; then
            info "Found $peer_count configured peer(s)"

            # Check if any peers have recent handshakes
            local active_peers=0
            wg show $WG_INTERFACE peers | while read -r peer_pubkey; do
                local handshake=$(wg show $WG_INTERFACE latest-handshakes | grep "$peer_pubkey" | awk '{print $2}')
                if [[ -n "$handshake" ]] && [[ "$handshake" != "0" ]]; then
                    local now=$(date +%s)
                    local age=$((now - handshake))

                    if [[ $age -lt 180 ]]; then
                        ((active_peers++)) || true
                    fi
                fi
            done

            if [[ $active_peers -gt 0 ]]; then
                pass "Active client connections detected ($active_peers peer(s))"
                info "Check FORWARD rule packet counts to verify client traffic routing"
            else
                info "No active client connections (no recent handshakes)"
                info "Connect a client device and check 'wg show $WG_INTERFACE' for traffic stats"
            fi
        else
            info "No peers configured yet"
        fi
    fi
}

# =============================================================================
# WGDASHBOARD CHECKS
# =============================================================================
check_wgdashboard() {
    section "WGDashboard Web Interface"

    # Check if installed
    if [[ -d /opt/WGDashboard ]]; then
        pass "WGDashboard directory exists"
    else
        warn "WGDashboard not installed at /opt/WGDashboard"
        return
    fi

    # Check service
    if systemctl is-active --quiet wgdashboard; then
        pass "WGDashboard service is running"
    else
        warn "WGDashboard service is not running" "Start with: systemctl start wgdashboard"
    fi

    # Check if enabled
    if systemctl is-enabled wgdashboard &>/dev/null; then
        pass "WGDashboard service enabled (will start on boot)"
    else
        warn "WGDashboard service not enabled"
    fi

    # Check if listening on port 10086
    if netstat -tlnp 2>/dev/null | grep -q ":10086" || ss -tlnp 2>/dev/null | grep -q ":10086"; then
        pass "WGDashboard listening on port 10086"
    else
        warn "WGDashboard not listening on port 10086"
    fi
}

# =============================================================================
# NGINX CHECKS
# =============================================================================
check_nginx() {
    section "Nginx Reverse Proxy"

    # Check if installed
    if ! command -v nginx &>/dev/null; then
        warn "Nginx not installed"
        return
    fi

    pass "Nginx installed"

    # Check if running
    if systemctl is-active --quiet nginx; then
        pass "Nginx service is running"
    else
        fail "Nginx service is not running" "Start with: systemctl start nginx"
        return
    fi

    # Check if enabled
    if systemctl is-enabled nginx &>/dev/null; then
        pass "Nginx service enabled (will start on boot)"
    else
        warn "Nginx service not enabled"
    fi

    # Check configuration
    if nginx -t &>/dev/null; then
        pass "Nginx configuration is valid"
    else
        fail "Nginx configuration has errors" "Check with: nginx -t"
    fi

    # Check if listening on 80
    if netstat -tlnp 2>/dev/null | grep -q ":80.*nginx" || ss -tlnp 2>/dev/null | grep -q ":80.*nginx"; then
        pass "Nginx listening on port 80 (HTTP)"
    else
        warn "Nginx not listening on port 80"
    fi

    # Check if listening on 443
    if netstat -tlnp 2>/dev/null | grep -q ":443.*nginx" || ss -tlnp 2>/dev/null | grep -q ":443.*nginx"; then
        pass "Nginx listening on port 443 (HTTPS)"
    else
        info "Nginx not listening on port 443 (SSL may not be configured)"
    fi
}

# =============================================================================
# SSL/TLS CHECKS
# =============================================================================
check_ssl() {
    section "SSL/TLS Certificates"

    # Check if certbot is installed
    if ! command -v certbot &>/dev/null; then
        info "Certbot not installed (SSL not configured)"
        return
    fi

    pass "Certbot installed"

    # Check for certificates
    if [[ -d /etc/letsencrypt/live ]]; then
        local cert_count=$(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
        if [[ $cert_count -gt 0 ]]; then
            pass "SSL certificates found: $cert_count domain(s)"

            # Check certificate expiration
            find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read -r certdir; do
                local domain=$(basename "$certdir")
                if [[ -f "$certdir/cert.pem" ]]; then
                    local expiry=$(openssl x509 -enddate -noout -in "$certdir/cert.pem" 2>/dev/null | cut -d= -f2)
                    local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
                    local now_epoch=$(date +%s)
                    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

                    if [[ $days_left -gt 30 ]]; then
                        info "  $domain: ${days_left} days until expiry"
                    elif [[ $days_left -gt 0 ]]; then
                        warn "  $domain: ${days_left} days until expiry (renewal recommended)"
                    else
                        fail "  $domain: EXPIRED!"
                    fi
                fi
            done
        else
            info "No SSL certificates found"
        fi
    else
        info "No SSL certificates configured"
    fi
}

# =============================================================================
# CLIENT CONFIGURATION CHECKS
# =============================================================================
check_client_configs() {
    section "WireGuard Client Configurations"

    if [[ -d /etc/wireguard/clients ]]; then
        pass "Client configurations directory exists"

        local conf_count=$(find /etc/wireguard/clients -name "*.conf" 2>/dev/null | wc -l)
        if [[ $conf_count -gt 0 ]]; then
            pass "Client configuration files found: $conf_count"

            find /etc/wireguard/clients -name "*.conf" 2>/dev/null | while read -r conf_file; do
                local filename=$(basename "$conf_file")
                info "  $filename"

                # Check for QR code
                local qr_file="${conf_file%.conf}_qr.txt"
                if [[ -f "$qr_file" ]]; then
                    info "    QR code: ${filename%.conf}_qr.txt"
                fi
            done
        else
            warn "No client configuration files found"
        fi
    else
        warn "Client configurations directory missing: /etc/wireguard/clients"
    fi
}

# =============================================================================
# SYSTEM RESOURCE CHECKS
# =============================================================================
check_system_resources() {
    section "System Resources"

    # Check memory
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local mem_used=$(free -m | awk '/^Mem:/{print $3}')
    local mem_percent=$((mem_used * 100 / mem_total))

    info "Memory: ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"

    if [[ $mem_percent -gt 90 ]]; then
        warn "High memory usage: ${mem_percent}%"
    elif [[ $mem_percent -gt 80 ]]; then
        info "Memory usage OK (${mem_percent}%)"
    fi

    # Check disk space
    local disk_percent=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')

    info "Disk space: ${disk_used} / ${disk_total} (${disk_percent}%)"

    if [[ $disk_percent -gt 90 ]]; then
        warn "Low disk space: ${disk_percent}% used"
    fi

    # Check CPU load
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    info "Load average (1min): $load_avg"
}

# =============================================================================
# SECURITY CHECKS
# =============================================================================
check_security() {
    section "Security Configuration"

    # Check fail2ban
    if systemctl is-active --quiet fail2ban; then
        pass "Fail2Ban is running"

        # Check SSH jail
        if fail2ban-client status sshd &>/dev/null; then
            local banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
            info "Fail2Ban SSH jail: $banned IP(s) currently banned"
        fi
    else
        warn "Fail2Ban is not running"
    fi

    # Check for automatic updates
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        pass "Automatic security updates configured"
    else
        warn "Automatic security updates not configured"
    fi
}

# =============================================================================
# LOG ANALYSIS
# =============================================================================
check_logs() {
    section "Recent Log Analysis"

    info "Checking for errors in system logs (last 1 hour)..."

    # WireGuard errors
    local wg_errors=$(journalctl -u wg-quick@$WG_INTERFACE --since "1 hour ago" 2>/dev/null | grep -i "error\|fail" | wc -l)
    if [[ $wg_errors -gt 0 ]]; then
        warn "Found $wg_errors error(s) in WireGuard logs"
        info "View with: journalctl -u wg-quick@$WG_INTERFACE -n 50"
    else
        pass "No errors in WireGuard logs"
    fi

    # Nginx errors
    if [[ -f /var/log/nginx/error.log ]]; then
        local nginx_errors=$(tail -100 /var/log/nginx/error.log 2>/dev/null | grep -c "error")
        if [[ $nginx_errors -gt 5 ]]; then
            warn "Multiple errors in Nginx error log"
            info "View with: tail -50 /var/log/nginx/error.log"
        else
            pass "No significant errors in Nginx logs"
        fi
    fi

    # Kernel errors
    local kern_errors=$(dmesg -T 2>/dev/null | tail -100 | grep -i "wireguard.*error" | wc -l)
    if [[ $kern_errors -gt 0 ]]; then
        warn "WireGuard errors in kernel log"
        info "View with: dmesg -T | grep -i wireguard"
    fi
}

# =============================================================================
# SUMMARY AND RECOMMENDATIONS
# =============================================================================
show_summary() {
    section "Diagnostic Summary"

    echo ""
    echo -e "${BOLD}Test Results:${NC}"
    echo -e "  ${GREEN}Passed:${NC}  $PASSED_CHECKS"
    echo -e "  ${RED}Failed:${NC}  $FAILED_CHECKS"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNING_CHECKS"
    echo -e "  ─────────────"
    echo -e "  Total:   $TOTAL_CHECKS"
    echo ""

    if [[ $FAILED_CHECKS -eq 0 ]] && [[ $WARNING_CHECKS -eq 0 ]]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ✓ ALL CHECKS PASSED - System appears healthy!            ║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    else
        if [[ $FAILED_CHECKS -gt 0 ]]; then
            echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║  CRITICAL ISSUES FOUND (${FAILED_CHECKS})                                   ║${NC}"
            echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""

            for issue in "${CRITICAL_ISSUES[@]}"; do
                echo -e "${RED}  ✗${NC} $issue"
            done
            echo ""
        fi

        if [[ $WARNING_CHECKS -gt 0 ]]; then
            echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${YELLOW}║  WARNINGS (${WARNING_CHECKS})                                             ║${NC}"
            echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""

            for warning in "${WARNINGS[@]}"; do
                echo -e "${YELLOW}  !${NC} $warning"
            done
            echo ""
        fi
    fi

    # Specific recommendations
    echo -e "${BOLD}${BLUE}Recommendations:${NC}"
    echo ""

    # Check for the most common issue
    if ! grep -q "^PostUp" $WG_CONFIG_FILE 2>/dev/null; then
        echo -e "${RED}1. FIX NAT/MASQUERADING (CRITICAL):${NC}"
        echo -e "   Your WireGuard config is missing NAT rules. This is why clients"
        echo -e "   can connect but have no traffic. Add these lines to $WG_CONFIG_FILE:"
        echo ""

        local default_iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')
        [[ -z "$default_iface" ]] && default_iface="eth0"

        # Check if UFW is active to determine which iptables command to use
        local use_insert=false
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            use_insert=true
            echo -e "   ${YELLOW}NOTE: UFW is active - using -I (insert) instead of -A (append)${NC}"
            echo ""
        fi

        if [[ "$use_insert" == "true" ]]; then
            echo -e "   ${CYAN}PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT${NC}"
            echo -e "   ${CYAN}PostUp = iptables -I FORWARD 1 -o wg0 -j ACCEPT${NC}"
        else
            echo -e "   ${CYAN}PostUp = iptables -A FORWARD -i wg0 -j ACCEPT${NC}"
            echo -e "   ${CYAN}PostUp = iptables -A FORWARD -o wg0 -j ACCEPT${NC}"
        fi

        echo -e "   ${CYAN}PostUp = iptables -t nat -A POSTROUTING -o $default_iface -j MASQUERADE${NC}"
        echo -e "   ${CYAN}PostDown = iptables -D FORWARD -i wg0 -j ACCEPT${NC}"
        echo -e "   ${CYAN}PostDown = iptables -D FORWARD -o wg0 -j ACCEPT${NC}"
        echo -e "   ${CYAN}PostDown = iptables -t nat -D POSTROUTING -o $default_iface -j MASQUERADE${NC}"
        echo ""
        echo -e "   Then restart WireGuard: ${CYAN}systemctl restart wg-quick@$WG_INTERFACE${NC}"
        echo ""
    fi

    if [[ $FAILED_CHECKS -gt 0 ]] || [[ $WARNING_CHECKS -gt 0 ]]; then
        echo -e "2. Review all failed checks and warnings above"
        echo -e "3. Check service logs: ${CYAN}journalctl -u wg-quick@$WG_INTERFACE -n 100${NC}"
        echo -e "4. Test connectivity after fixes: ${CYAN}ping -I $WG_INTERFACE 8.8.8.8${NC}"
        echo ""
    fi

    # Useful commands
    echo -e "${BOLD}${BLUE}Useful Commands:${NC}"
    echo -e "  Show WireGuard status:       ${CYAN}wg show $WG_INTERFACE${NC}"
    echo -e "  Monitor clients (real-time): ${CYAN}watch -n 1 wg show $WG_INTERFACE${NC}"
    echo -e "  Show WireGuard config:       ${CYAN}cat $WG_CONFIG_FILE${NC}"
    echo -e "  Restart WireGuard:           ${CYAN}systemctl restart wg-quick@$WG_INTERFACE${NC}"
    echo -e "  View WireGuard logs:         ${CYAN}journalctl -u wg-quick@$WG_INTERFACE -f${NC}"
    echo -e "  Show FORWARD chain:          ${CYAN}iptables -L FORWARD -v -n${NC}"
    echo -e "  Show NAT rules:              ${CYAN}iptables -t nat -L -v -n${NC}"
    echo -e "  Show firewall rules:         ${CYAN}ufw status verbose${NC}"
    echo -e "  Show routing table:          ${CYAN}ip route${NC}"
    echo ""

    if [[ $FAILED_CHECKS -eq 0 ]] && [[ $WARNING_CHECKS -gt 0 ]]; then
        echo -e "${BOLD}${YELLOW}Note:${NC} Warnings are not critical but should be reviewed."
        echo ""
    fi

    echo -e "${BOLD}Report generated: $(date)${NC}"
    echo ""
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    # Parse command-line arguments first
    parse_arguments "$@"

    # Must be root
    check_root

    # Detect and select WireGuard interface
    select_wireguard_interface

    # Show header
    header

    # Run all diagnostic checks
    check_system_info
    check_packages
    check_wireguard_installation
    check_wireguard_configuration
    check_wireguard_service
    check_wireguard_interface
    check_ip_forwarding
    check_nat_masquerading
    check_firewall
    check_routing
    check_dns
    check_connectivity
    check_wgdashboard
    check_nginx
    check_ssl
    check_client_configs
    check_system_resources
    check_security
    check_logs

    # Show summary
    show_summary

    # Exit code based on results
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        exit 1
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

# Run the diagnostic script
main "$@"
