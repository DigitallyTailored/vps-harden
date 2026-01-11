#!/bin/bash
#===============================================================================
# VPS Hardening Script for Ubuntu 24.04 LTS+
# https://github.com/DigitallyTailored/vps-harden
#===============================================================================

set -uo pipefail

#===============================================================================
# CONFIGURATION DEFAULTS
#===============================================================================
readonly DEFAULT_SSH_PORT=22222
readonly LOGFILE='/var/log/server_hardening.log'
readonly SSHDFILE='/etc/ssh/sshd_config'
readonly SCRIPT_VERSION="1.0.1"
readonly MIN_UBUNTU_VERSION="20.04"

#===============================================================================
# COLORS & FORMATTING
#===============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

#===============================================================================
# GLOBAL VARIABLES
#===============================================================================
TOTAL_STEPS=10
CURRENT_STEP=0
SSHPORT=""
UNAME=""
BTIME=""
START_TIME=""
ERRORS_OCCURRED=0
CURRENT_USER=""

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" >> "$LOGFILE"
}

print_header() {
    echo -e "\n${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}\n"
}

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo -e "\n${BLUE}${BOLD}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${BOLD}$1${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────${NC}"
    log "INFO" "Step ${CURRENT_STEP}: $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    log "SUCCESS" "$1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    log "WARNING" "$1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    log "ERROR" "$1"
    ERRORS_OCCURRED=$((ERRORS_OCCURRED + 1))
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

print_action() {
    echo -e "  ${DIM}→${NC} $1"
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local response
    
    if [[ "$default" == "y" ]]; then
        prompt="${prompt} [Y/n]: "
    else
        prompt="${prompt} [y/N]: "
    fi
    
    echo -e -n "${YELLOW}?${NC} ${prompt}"
    read -r response
    response="${response:-$default}"
    
    [[ "${response,,}" == "y" ]]
}

format_duration() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local remaining_seconds=$((seconds % 60))
    if [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${remaining_seconds}s"
    else
        echo "${seconds}s"
    fi
}

get_current_user() {
    # Get the user who invoked sudo, or current user if not using sudo
    if [[ -n "${SUDO_USER:-}" ]]; then
        CURRENT_USER="$SUDO_USER"
    else
        CURRENT_USER="$(whoami)"
    fi
}

#===============================================================================
# VALIDATION FUNCTIONS
#===============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo -e "  Run with: ${BOLD}sudo $0${NC}"
        exit 1
    fi
    print_success "Running as root"
}

check_ubuntu_version() {
    if [[ ! -r /etc/os-release ]]; then
        print_error "Cannot detect OS version"
        exit 1
    fi
    
    # shellcheck source=/dev/null
    source /etc/os-release
    
    if [[ "$ID" != "ubuntu" ]]; then
        print_error "This script is designed for Ubuntu only (detected: $ID)"
        exit 1
    fi
    
    local version_num="${VERSION_ID//./}"
    local min_version_num="${MIN_UBUNTU_VERSION//./}"
    
    if [[ $version_num -lt $min_version_num ]]; then
        print_error "Ubuntu ${MIN_UBUNTU_VERSION}+ required (detected: ${VERSION_ID})"
        exit 1
    fi
    
    print_success "Ubuntu ${VERSION_ID} detected"
}

check_network() {
    if ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
        print_success "Network connectivity verified"
    else
        print_warning "Network connectivity may be limited"
    fi
}

check_ssh_keys() {
    if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
        print_success "SSH authorized_keys found"
    else
        print_warning "No SSH keys found - ensure you have key access before continuing!"
        echo -e "  ${YELLOW}This script will disable password authentication.${NC}"
        echo -e "  ${YELLOW}Without SSH keys, you may be locked out!${NC}"
        echo ""
        if ! confirm "I confirm I have SSH key access configured" "n"; then
            echo -e "\n${YELLOW}Aborted. Please configure SSH keys first.${NC}"
            exit 0
        fi
    fi
}

#===============================================================================
# MAIN FUNCTIONS
#===============================================================================

show_welcome() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ╦  ╦╔═╗╔═╗  ╦ ╦╔═╗╦═╗╔╦╗╔═╗╔╗╔╦╔╗╔╔═╗
    ╚╗╔╝╠═╝╚═╗  ╠═╣╠═╣╠╦╝ ║║║╣ ║║║║║║║║ ╦
     ╚╝ ╩  ╚═╝  ╩ ╩╩ ╩╩╚══╩╝╚═╝╝╚╝╩╝╚╝╚═╝
EOF
    echo -e "${NC}"
    echo -e "${DIM}    Version ${SCRIPT_VERSION} | Ubuntu 24.04 LTS+${NC}\n"
    
    echo -e "${BOLD}This script will:${NC}"
    echo -e "  ${GREEN}•${NC} Create swap space if needed"
    echo -e "  ${GREEN}•${NC} Update and upgrade system packages"
    echo -e "  ${GREEN}•${NC} Install essential security tools"
    echo -e "  ${GREEN}•${NC} Create a non-root sudo user (optional)"
    echo -e "  ${GREEN}•${NC} Configure SSH on port ${BOLD}${DEFAULT_SSH_PORT}${NC}"
    echo -e "  ${GREEN}•${NC} Disable SSH password authentication"
    echo -e "  ${GREEN}•${NC} Configure UFW firewall (SSH, HTTP, HTTPS)"
    echo -e "  ${GREEN}•${NC} Harden system security settings"
    echo -e "  ${GREEN}•${NC} Enable automatic security updates"
    echo -e "  ${GREEN}•${NC} Install enhanced MOTD"
    echo ""
    
    log "INFO" "Script started - Version ${SCRIPT_VERSION}"
}

show_pre_flight_check() {
    print_header "Pre-Flight Checks"
    
    check_root
    get_current_user
    check_ubuntu_version
    check_network
    check_ssh_keys
    
    echo ""
    if ! confirm "Ready to proceed with hardening?"; then
        echo -e "\n${YELLOW}Aborted by user${NC}"
        exit 0
    fi
    
    START_TIME=$(date +%s)
}

create_swap() {
    print_step "Configuring Swap Space"
    
    # Check if swap exists
    local swap_total
    swap_total=$(free | awk '/^Swap:/ {print $2}')
    
    if [[ "$swap_total" -gt 0 ]]; then
        local current_swap
        current_swap=$(free -h | awk '/^Swap:/ {print $2}')
        print_info "Swap already exists (${current_swap})"
        print_success "Skipping swap creation"
        return 0
    fi
    
    print_action "Calculating optimal swap size..."
    
    local phys_ram_gb
    phys_ram_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    local swap_size=$((phys_ram_gb * 2))
    
    # Clamp between 2GB and 32GB
    [[ $swap_size -lt 2 ]] && swap_size=2
    [[ $swap_size -gt 32 ]] && swap_size=32
    
    print_action "Creating ${swap_size}GB swap file..."
    
    if fallocate -l "${swap_size}G" /swapfile 2>/dev/null || \
       dd if=/dev/zero of=/swapfile bs=1G count="$swap_size" status=none 2>/dev/null; then
        chmod 600 /swapfile
        mkswap /swapfile >> "$LOGFILE" 2>&1
        swapon /swapfile
        
        # Add to fstab if not already present
        if ! grep -q '/swapfile' /etc/fstab; then
            cp /etc/fstab /etc/fstab.bak
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        
        print_success "Created ${swap_size}GB swap file"
    else
        print_error "Failed to create swap file"
    fi
}

update_system() {
    print_step "Updating System Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    
    print_action "Updating package lists..."
    if apt-get update -qq >> "$LOGFILE" 2>&1; then
        print_success "Package lists updated"
    else
        print_error "Failed to update package lists"
    fi
    
    print_action "Upgrading installed packages (this may take a while)..."
    if apt-get -o Dpkg::Options::="--force-confold" \
               -o Dpkg::Options::="--force-confdef" \
               upgrade -y -qq >> "$LOGFILE" 2>&1; then
        print_success "System packages upgraded"
    else
        print_warning "Some packages may not have upgraded cleanly"
    fi
    
    print_action "Removing unnecessary packages..."
    apt-get autoremove -y -qq >> "$LOGFILE" 2>&1 || true
    print_success "Cleanup complete"
}

install_packages() {
    print_step "Installing Essential Packages"
    
    local packages=(
        # System monitoring
        htop
        glances
        nethogs
        iotop
        
        # Security
        ufw
        fail2ban
        unattended-upgrades
        apt-listchanges
        
        # Networking
        curl
        wget
        net-tools
        dnsutils
        
        # Utilities
        vim
        tmux
        git
        zip
        unzip
        jq
        tree
        ncdu
        
        # Required for MOTD
        lsb-release
        update-motd
    )
    
    print_action "Installing ${#packages[@]} packages..."
    
    if apt-get install -y -qq "${packages[@]}" >> "$LOGFILE" 2>&1; then
        print_success "All packages installed"
    else
        print_warning "Some packages may have failed to install"
    fi
    
    # Display installed packages
    echo -e "\n  ${DIM}Installed:${NC}"
    echo -e "  ${DIM}├─ Security:${NC} ufw, fail2ban, unattended-upgrades"
    echo -e "  ${DIM}├─ Monitoring:${NC} htop, glances, nethogs, iotop"
    echo -e "  ${DIM}├─ Network:${NC} curl, wget, net-tools, dnsutils"
    echo -e "  ${DIM}└─ Utilities:${NC} vim, tmux, git, jq, ncdu"
}

setup_user() {
    print_step "User Account Setup"
    
    if ! confirm "Create a non-root sudo user?" "y"; then
        print_info "Skipping user creation"
        return 0
    fi
    
    local input_user=""
    echo -e -n "${YELLOW}?${NC} Enter username: "
    read -r input_user
    
    # Validate username
    while [[ ! "$input_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || [[ -z "$input_user" ]]; do
        print_warning "Username must start with a letter and contain only lowercase letters, numbers, underscores, or hyphens"
        echo -e -n "${YELLOW}?${NC} Enter username: "
        read -r input_user
    done
    
    UNAME="${input_user,,}"  # Lowercase
    
    if id "$UNAME" &>/dev/null; then
        print_warning "User '$UNAME' already exists"
        if confirm "Add to sudo group anyway?" "y"; then
            usermod -aG sudo "$UNAME"
            print_success "User '$UNAME' added to sudo group"
        fi
    else
        print_action "Creating user '$UNAME'..."
        adduser --gecos "" "$UNAME"
        usermod -aG sudo "$UNAME"
        print_success "User '$UNAME' created with sudo privileges"
        
        # Copy SSH keys if they exist
        if [[ -f /root/.ssh/authorized_keys ]]; then
            print_action "Copying SSH authorized keys..."
            mkdir -p "/home/${UNAME}/.ssh"
            cp /root/.ssh/authorized_keys "/home/${UNAME}/.ssh/"
            chmod 700 "/home/${UNAME}/.ssh"
            chmod 600 "/home/${UNAME}/.ssh/authorized_keys"
            chown -R "${UNAME}:${UNAME}" "/home/${UNAME}/.ssh"
            print_success "SSH keys copied to user '$UNAME'"
        else
            print_warning "No SSH keys found in /root/.ssh/authorized_keys"
            print_info "Remember to add SSH keys for the new user!"
        fi
    fi
}

configure_ssh() {
    print_step "Configuring SSH Security"
    
    # Backup original config
    BTIME=$(date +%Y%m%d_%H%M%S)
    cp "$SSHDFILE" "${SSHDFILE}.${BTIME}.bak"
    print_action "Backed up sshd_config to ${SSHDFILE}.${BTIME}.bak"
    
    # Set SSH port
    SSHPORT=$DEFAULT_SSH_PORT
    local input_port=""
    echo -e -n "${YELLOW}?${NC} SSH port [${DEFAULT_SSH_PORT}]: "
    read -r input_port
    
    if [[ -n "$input_port" ]]; then
        if [[ "$input_port" =~ ^[0-9]+$ ]] && [[ "$input_port" -ge 1 ]] && [[ "$input_port" -le 65535 ]]; then
            SSHPORT=$input_port
        else
            print_warning "Invalid port, using default: ${DEFAULT_SSH_PORT}"
        fi
    fi
    
    print_action "Configuring SSH on port ${SSHPORT}..."
    
    # Create new sshd_config with hardened settings
    cat > "$SSHDFILE" << EOF
# SSH Server Configuration - Hardened
# Generated by VPS Hardening Script v${SCRIPT_VERSION}
# Original backup: ${SSHDFILE}.${BTIME}.bak

# Network
Port ${SSHPORT}
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes

# Security
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
DebianBanner no

# Session
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    # If user was created, offer to disable root login
    if [[ -n "$UNAME" ]]; then
        if confirm "Disable root SSH login completely?" "n"; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHDFILE"
            print_action "Root SSH login disabled"
        fi
    fi
    
    print_success "SSH configured on port ${SSHPORT}"
    print_success "Password authentication disabled"
    
    # Configure fail2ban for new SSH port
    print_action "Configuring fail2ban for SSH..."
    
    mkdir -p /etc/fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ${SSHPORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
EOF
    
    systemctl enable fail2ban >> "$LOGFILE" 2>&1 || true
    systemctl restart fail2ban >> "$LOGFILE" 2>&1 || true
    print_success "Fail2ban configured"
}

configure_firewall() {
    print_step "Configuring UFW Firewall"
    
    print_action "Resetting firewall to defaults..."
    ufw --force reset >> "$LOGFILE" 2>&1 || true
    
    print_action "Setting default policies..."
    ufw default deny incoming >> "$LOGFILE" 2>&1
    ufw default allow outgoing >> "$LOGFILE" 2>&1
    
    print_action "Adding firewall rules..."
    
    # SSH
    ufw allow "${SSHPORT}/tcp" comment 'SSH' >> "$LOGFILE" 2>&1
    echo -e "  ${GREEN}✓${NC} Port ${SSHPORT}/tcp (SSH)"
    
    # HTTP
    ufw allow 80/tcp comment 'HTTP' >> "$LOGFILE" 2>&1
    echo -e "  ${GREEN}✓${NC} Port 80/tcp (HTTP)"
    
    # HTTPS
    ufw allow 443/tcp comment 'HTTPS' >> "$LOGFILE" 2>&1
    echo -e "  ${GREEN}✓${NC} Port 443/tcp (HTTPS)"
    
    # Rate limiting on SSH
    print_action "Enabling rate limiting on SSH..."
    ufw limit "${SSHPORT}/tcp" >> "$LOGFILE" 2>&1 || true
    
    print_success "Firewall rules configured"
    print_info "Firewall will be enabled after SSH restart"
}

harden_system() {
    print_step "Applying System Hardening"
    
    # Secure shared memory
    print_action "Securing shared memory..."
    if ! grep -q 'tmpfs /run/shm' /etc/fstab; then
        echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
        print_success "Shared memory secured"
    else
        print_info "Shared memory already secured"
    fi
    
    # Harden sysctl settings
    print_action "Applying kernel security parameters..."
    
    cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Allow for more PIDs
kernel.pid_max = 65536

# Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000

# RFC 1337 fix
net.ipv4.tcp_rfc1337 = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-hardening.conf >> "$LOGFILE" 2>&1 || true
    print_success "Kernel parameters hardened"
    
    # Configure automatic security updates
    print_action "Configuring automatic security updates..."
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
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
Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    systemctl enable unattended-upgrades >> "$LOGFILE" 2>&1 || true
    print_success "Automatic security updates enabled"
}

install_motd() {
    print_step "Installing Enhanced MOTD"
    
    print_action "Configuring MOTD components..."
    
    # Disable default MOTD components
    chmod -x /etc/update-motd.d/* 2>/dev/null || true
    
    # Create system info MOTD
    cat > /etc/update-motd.d/00-header << 'MOTDEOF'
#!/bin/bash
#===============================================================================
# System Status Report
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# Source OS info
. /etc/os-release 2>/dev/null || true

#===============================================================================
# SYSTEM OVERVIEW
#===============================================================================
echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}  SYSTEM STATUS REPORT${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════════════${NC}"

# Basic system info
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
KERNEL=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || echo "unknown")
LOAD=$(cut -d' ' -f1-3 /proc/loadavg)
IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
LAST_BOOT=$(who -b 2>/dev/null | awk '{print $3, $4}' || echo "unknown")

echo -e "\n${BOLD}System${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
printf "  ${CYAN}%-16s${NC} %s\n" "Hostname:" "$HOSTNAME"
printf "  ${CYAN}%-16s${NC} %s\n" "OS:" "${PRETTY_NAME:-Ubuntu}"
printf "  ${CYAN}%-16s${NC} %s\n" "Kernel:" "$KERNEL"
printf "  ${CYAN}%-16s${NC} %s\n" "IP Address:" "$IP_ADDR"
printf "  ${CYAN}%-16s${NC} %s\n" "Uptime:" "$UPTIME"
printf "  ${CYAN}%-16s${NC} %s\n" "Last Boot:" "$LAST_BOOT"
printf "  ${CYAN}%-16s${NC} %s\n" "Load Average:" "$LOAD"

#===============================================================================
# RESOURCE USAGE
#===============================================================================
MEMORY_USED=$(free -m | awk 'NR==2{printf "%.1f", $3*100/$2}')
MEMORY_TOTAL=$(free -h | awk 'NR==2{print $2}')
SWAP_USED=$(free -m | awk 'NR==3{if($2>0) printf "%.1f", $3*100/$2; else print "0"}')
DISK_USED=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
DISK_TOTAL=$(df -h / | awk 'NR==2{print $2}')

echo -e "\n${BOLD}Resources${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

# Memory bar
if (( $(echo "$MEMORY_USED > 80" | bc -l 2>/dev/null || echo 0) )); then
    MEM_COLOR=$RED
elif (( $(echo "$MEMORY_USED > 60" | bc -l 2>/dev/null || echo 0) )); then
    MEM_COLOR=$YELLOW
else
    MEM_COLOR=$GREEN
fi
printf "  ${CYAN}%-16s${NC} ${MEM_COLOR}%5.1f%%${NC} of %s\n" "Memory:" "$MEMORY_USED" "$MEMORY_TOTAL"

# Swap
printf "  ${CYAN}%-16s${NC} %5.1f%%\n" "Swap:" "$SWAP_USED"

# Disk bar
if [[ $DISK_USED -gt 80 ]]; then
    DISK_COLOR=$RED
elif [[ $DISK_USED -gt 60 ]]; then
    DISK_COLOR=$YELLOW
else
    DISK_COLOR=$GREEN
fi
printf "  ${CYAN}%-16s${NC} ${DISK_COLOR}%5d%%${NC} of %s\n" "Disk (/):" "$DISK_USED" "$DISK_TOTAL"

#===============================================================================
# SECURITY STATUS
#===============================================================================
echo -e "\n${BOLD}Security${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

# Users and groups
TOTAL_USERS=$(cat /etc/passwd | wc -l)
HUMAN_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | wc -l)
SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -c . || echo "0")
ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)

printf "  ${CYAN}%-16s${NC} %d total, %d human, ${YELLOW}%d sudo${NC}, ${RED}%d root${NC}\n" "Users:" "$TOTAL_USERS" "$HUMAN_USERS" "$SUDO_USERS" "$ROOT_USERS"

# Failed login attempts (last 24h)
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date +%b\ %d)" | wc -l || echo "0")
if [[ $FAILED_LOGINS -gt 10 ]]; then
    FAILED_COLOR=$RED
elif [[ $FAILED_LOGINS -gt 0 ]]; then
    FAILED_COLOR=$YELLOW
else
    FAILED_COLOR=$GREEN
fi
printf "  ${CYAN}%-16s${NC} ${FAILED_COLOR}%d${NC} (last 24h)\n" "Failed Logins:" "$FAILED_LOGINS"

# Currently logged in users
LOGGED_IN=$(who | wc -l)
printf "  ${CYAN}%-16s${NC} %d\n" "Logged In:" "$LOGGED_IN"

# Fail2ban status
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban; then
    BANNED_IPS=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
    printf "  ${CYAN}%-16s${NC} ${GREEN}Active${NC}, %s IPs banned\n" "Fail2ban:" "$BANNED_IPS"
else
    printf "  ${CYAN}%-16s${NC} ${RED}Inactive${NC}\n" "Fail2ban:"
fi

# Firewall status
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
    if [[ "$UFW_STATUS" == "active" ]]; then
        printf "  ${CYAN}%-16s${NC} ${GREEN}Active${NC}\n" "Firewall:"
    else
        printf "  ${CYAN}%-16s${NC} ${RED}Inactive${NC}\n" "Firewall:"
    fi
fi

#===============================================================================
# NETWORK - LISTENING PORTS
#===============================================================================
echo -e "\n${BOLD}Listening Ports${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

# Get listening ports with services
ss -tlnp 2>/dev/null | awk 'NR>1 {
    split($4, a, ":");
    port = a[length(a)];
    proc = $6;
    gsub(/.*"/, "", proc);
    gsub(/".*/, "", proc);
    if (port != "" && port ~ /^[0-9]+$/) {
        printf "  %-8s %s\n", port, proc
    }
}' | sort -t' ' -k1 -n | uniq | head -10

#===============================================================================
# TOP PROCESSES
#===============================================================================
echo -e "\n${BOLD}Top Processes (by CPU)${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
printf "  ${DIM}%-6s %-10s %-6s %-6s %s${NC}\n" "PID" "USER" "CPU%" "MEM%" "COMMAND"
ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && NR<=6 {printf "  %-6s %-10s %-6s %-6s %s\n", $2, $1, $3, $4, $11}' | head -5

#===============================================================================
# RECENT LOGINS
#===============================================================================
echo -e "\n${BOLD}Recent Logins${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
last -n 5 -a 2>/dev/null | head -5 | while read line; do
    if [[ -n "$line" ]] && [[ ! "$line" =~ ^$ ]] && [[ ! "$line" =~ ^wtmp ]]; then
        echo "  $line"
    fi
done

#===============================================================================
# UPDATES
#===============================================================================
echo -e "\n${BOLD}Updates${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
if [[ -f /var/lib/update-notifier/updates-available ]]; then
    UPDATES=$(grep -oP '^\d+(?= updates)' /var/lib/update-notifier/updates-available 2>/dev/null || echo "0")
    SECURITY=$(grep -oP '^\d+(?= .* security)' /var/lib/update-notifier/updates-available 2>/dev/null || echo "0")
else
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1 || echo "?")
    SECURITY="?"
fi

if [[ "$UPDATES" != "0" ]] && [[ "$UPDATES" != "?" ]]; then
    printf "  ${CYAN}%-16s${NC} ${YELLOW}%s available${NC}\n" "Packages:" "$UPDATES"
else
    printf "  ${CYAN}%-16s${NC} ${GREEN}System up to date${NC}\n" "Packages:"
fi

if [[ "$SECURITY" != "0" ]] && [[ "$SECURITY" != "?" ]]; then
    printf "  ${CYAN}%-16s${NC} ${RED}%s security updates!${NC}\n" "Security:" "$SECURITY"
fi

# Last update check
if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
    LAST_UPDATE=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null)
    NOW=$(date +%s)
    DAYS_AGO=$(( (NOW - LAST_UPDATE) / 86400 ))
    printf "  ${CYAN}%-16s${NC} %d days ago\n" "Last Check:" "$DAYS_AGO"
fi

#===============================================================================
# FOOTER
#===============================================================================
echo -e "\n${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "${RED}${BOLD}  ⚠  UNAUTHORIZED ACCESS IS PROHIBITED${NC}"
echo -e "${DIM}  All activity on this system may be monitored and recorded.${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}\n"
MOTDEOF
    
    # Make script executable
    chmod +x /etc/update-motd.d/00-header
    
    # Update issue.net for pre-login banner
    cat > /etc/issue.net << 'EOF'
******************************************************************
                    AUTHORIZED ACCESS ONLY
  Unauthorized access is prohibited and may be prosecuted.
******************************************************************

EOF
    
    # Enable banner in SSH config if not already done
    if ! grep -q "^Banner /etc/issue.net" "$SSHDFILE"; then
        echo "Banner /etc/issue.net" >> "$SSHDFILE"
    fi
    
    print_success "Enhanced MOTD installed"
}

restart_ssh_service() {
    print_step "Restarting SSH Service"
    
    # Determine which user to show in the connection command
    local ssh_user="${UNAME:-$CURRENT_USER}"
    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    echo ""
    echo -e "  ${YELLOW}${BOLD}⚠  IMPORTANT: Keep this terminal open!${NC}"
    echo -e "  ${YELLOW}Open a NEW terminal and test SSH access before closing this one.${NC}"
    echo ""
    echo -e "  Test command: ${BOLD}ssh -p ${SSHPORT} ${ssh_user}@${server_ip}${NC}"
    echo ""
    
    if ! confirm "Restart SSH and enable firewall now?" "y"; then
        print_warning "SSH not restarted - changes will apply on next restart"
        print_warning "Firewall not enabled"
        print_info "To apply changes manually, run:"
        echo -e "    sudo systemctl daemon-reload"
        echo -e "    sudo systemctl stop ssh.socket ssh"
        echo -e "    sudo systemctl start ssh"
        echo -e "    sudo ufw --force enable"
        return 0
    fi
    
    print_action "Validating SSH configuration..."
    if ! sshd -t 2>> "$LOGFILE"; then
        print_error "SSH configuration is invalid! Restoring backup..."
        cp "${SSHDFILE}.${BTIME}.bak" "$SSHDFILE"
        print_warning "Original configuration restored"
        return 1
    fi
    print_success "SSH configuration valid"
    
    print_action "Restarting SSH service (Ubuntu 20.04+ method)..."
    
    # Ubuntu 20.04+ SSH restart procedure
    systemctl daemon-reload >> "$LOGFILE" 2>&1 || true
    systemctl stop ssh.socket >> "$LOGFILE" 2>&1 || true
    systemctl stop ssh >> "$LOGFILE" 2>&1 || true
    sleep 1
    systemctl start ssh >> "$LOGFILE" 2>&1
    
    # Verify SSH is running
    sleep 2
    if systemctl is-active --quiet ssh; then
        print_success "SSH service restarted successfully"
    else
        print_error "SSH service may not have started correctly"
        print_info "Check status with: systemctl status ssh"
    fi
    
    # Enable firewall
    print_action "Enabling firewall..."
    if ufw --force enable >> "$LOGFILE" 2>&1; then
        print_success "UFW firewall enabled"
    else
        print_error "Failed to enable UFW firewall"
    fi
    
    # Show firewall status
    echo ""
    echo -e "  ${DIM}Firewall status:${NC}"
    ufw status numbered 2>/dev/null | head -15 | sed 's/^/  /' || true
}

show_summary() {
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    # Determine which user to show
    local ssh_user="${UNAME:-$CURRENT_USER}"
    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    clear
    print_header "Installation Complete"
    
    if [[ $ERRORS_OCCURRED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ✓ Server hardening completed successfully${NC}"
    else
        echo -e "${YELLOW}${BOLD}  ⚠ Server hardening completed with ${ERRORS_OCCURRED} warning(s)${NC}"
    fi
    echo -e "  ${DIM}Duration: $(format_duration "$duration")${NC}"
    
    echo ""
    echo -e "${CYAN}${BOLD}  Connection Details${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    printf "  %-20s %s\n" "SSH Port:" "${BOLD}${SSHPORT}${NC}"
    printf "  %-20s %s\n" "SSH User:" "${BOLD}${ssh_user}${NC}"
    printf "  %-20s %s\n" "Password Auth:" "${RED}Disabled${NC}"
    printf "  %-20s %s\n" "Root Login:" "Key only"
    
    echo ""
    echo -e "${CYAN}${BOLD}  Firewall Rules${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN}✓${NC} ${SSHPORT}/tcp (SSH - rate limited)"
    echo -e "  ${GREEN}✓${NC} 80/tcp (HTTP)"
    echo -e "  ${GREEN}✓${NC} 443/tcp (HTTPS)"
    
    echo ""
    echo -e "${CYAN}${BOLD}  Files${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    printf "  %-20s %s\n" "Log:" "${LOGFILE}"
    printf "  %-20s %s\n" "SSH Backup:" "${SSHDFILE}.${BTIME}.bak"
    
    echo ""
    echo -e "${RED}${BOLD}  ⚠  TEST BEFORE CLOSING THIS SESSION${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    echo -e "  1. Open a ${BOLD}new terminal window${NC}"
    echo -e "  2. Run: ${BOLD}ssh -p ${SSHPORT} ${ssh_user}@${server_ip}${NC}"
    echo -e "  3. Confirm you can login successfully"
    echo -e "  4. ${GREEN}Only then${NC} close this session"
    
    echo ""
    echo -e "${CYAN}${BOLD}  Useful Commands${NC}"
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}Firewall status:${NC}  sudo ufw status"
    echo -e "  ${DIM}Fail2ban status:${NC}  sudo fail2ban-client status sshd"
    echo -e "  ${DIM}Auth logs:${NC}        sudo tail -f /var/log/auth.log"
    echo -e "  ${DIM}Unban IP:${NC}         sudo fail2ban-client set sshd unbanip IP"
    echo ""
    
    log "INFO" "Script completed in $(format_duration "$duration") with ${ERRORS_OCCURRED} error(s)"
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================

main() {
    # Initialize log file
    mkdir -p "$(dirname "$LOGFILE")"
    cat > "$LOGFILE" << EOF
========================================
VPS Hardening Script v${SCRIPT_VERSION}
Started: $(date)
========================================
EOF
    
    show_welcome
    show_pre_flight_check
    
    create_swap
    update_system
    install_packages
    setup_user
    configure_ssh
    configure_firewall
    harden_system
    install_motd
    restart_ssh_service
    show_summary
}

# Handle interruption
trap 'echo -e "\n${RED}Script interrupted by user${NC}"; exit 130' INT
trap 'echo -e "\n${RED}Script terminated${NC}"; exit 143' TERM

# Run main
main "$@"
