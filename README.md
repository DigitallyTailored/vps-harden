# VPS Hardening Script

A comprehensive security hardening script for Ubuntu 24.04 LTS+ servers. Automates essential security configurations with sensible defaults and an intuitive interface.

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%2B-E95420?logo=ubuntu&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?logo=gnu-bash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

---

## Quick Start

```bash
# Download and run
curl -fsSL https://raw.githubusercontent.com/DigitallyTailored/vps-harden/main/harden.sh -o harden.sh
chmod +x harden.sh
sudo ./harden.sh
```

Or clone the repository:

```bash
git clone https://github.com/DigitallyTailored/vps-harden.git
cd vps-harden
sudo ./harden.sh
```

---

## What It Does (Summary)

| Category | Actions |
|----------|---------|
| **System** | Creates swap, updates packages, installs security tools |
| **SSH** | Changes port to 22222, disables password auth, hardens config |
| **Firewall** | Configures UFW with SSH, HTTP, HTTPS rules |
| **Security** | Kernel hardening, fail2ban, automatic security updates |
| **User** | Optional non-root sudo user creation with SSH key copy |

---

## Requirements

- **OS:** Ubuntu 20.04 LTS or newer (optimized for 24.04 LTS)
- **Access:** Root or sudo privileges
- **SSH Keys:** Must have SSH key authentication configured before running
- **Network:** Active internet connection

> ⚠️ **Warning:** This script disables password authentication. Ensure you have SSH key access configured before running.

---

## Default Configuration

| Setting | Default Value |
|---------|---------------|
| SSH Port | `22222` |
| Password Authentication | `Disabled` |
| Root Login | `Key-only` |
| Firewall Ports | `22222 (SSH)`, `80 (HTTP)`, `443 (HTTPS)` |
| Fail2ban SSH Ban | `24 hours` |
| Auto Security Updates | `Enabled` |

---

## Detailed Breakdown

### 1. Swap Configuration

- Checks for existing swap space
- Creates swap file if none exists (2× RAM, min 2GB, max 32GB)
- Configures swap to persist across reboots via `/etc/fstab`

### 2. System Updates

- Updates all package lists
- Upgrades installed packages (preserves existing configs)
- Removes unnecessary packages
- Sets non-interactive mode to prevent prompts

### 3. Essential Packages

Installs the following packages:

| Category | Packages |
|----------|----------|
| **Security** | `ufw`, `fail2ban`, `unattended-upgrades`, `apt-listchanges` |
| **Monitoring** | `htop`, `glances`, `nethogs`, `iotop` |
| **Networking** | `curl`, `wget`, `net-tools`, `dnsutils`, `ntp` |
| **Utilities** | `vim`, `tmux`, `git`, `zip`, `unzip`, `jq`, `tree`, `ncdu` |
| **MOTD** | `figlet`, `lsb-release`, `update-motd`, `landscape-common` |

### 4. User Setup (Optional)

- Creates a non-root user with sudo privileges
- Copies SSH authorized keys from root
- Sets correct permissions on `.ssh` directory

### 5. SSH Hardening

Applies the following security configurations to `/etc/ssh/sshd_config`:

```
Port 22222                          # Non-standard port
PermitRootLogin prohibit-password   # Root via key only
PasswordAuthentication no           # Keys only
PermitEmptyPasswords no             # No empty passwords
MaxAuthTries 3                      # Limit auth attempts
MaxSessions 3                       # Limit concurrent sessions
LoginGraceTime 30                   # 30 second login timeout
ClientAliveInterval 300             # 5 minute keepalive
ClientAliveCountMax 2               # Disconnect after 2 missed
X11Forwarding no                    # Disable X11
AllowTcpForwarding no               # Disable TCP forwarding
AllowAgentForwarding no             # Disable agent forwarding
```

### 6. Firewall Configuration

UFW (Uncomplicated Firewall) rules:

| Rule | Port | Description |
|------|------|-------------|
| Allow | `22222/tcp` | SSH (rate limited) |
| Allow | `80/tcp` | HTTP |
| Allow | `443/tcp` | HTTPS |
| Default | Incoming | Deny |
| Default | Outgoing | Allow |

### 7. Fail2ban Configuration

- Monitors SSH login attempts
- Bans IPs after 3 failed attempts
- 24-hour ban duration
- Uses UFW for ban actions

### 8. Kernel Hardening

Applies security parameters via `/etc/sysctl.d/99-hardening.conf`:

| Protection | Setting |
|------------|---------|
| IP Spoofing | `rp_filter = 1` |
| ICMP Broadcast | `icmp_echo_ignore_broadcasts = 1` |
| Source Routing | Disabled |
| SYN Flood | `tcp_syncookies = 1` |
| ICMP Redirects | Ignored |
| Martian Logging | Enabled |

### 9. Automatic Security Updates

Configures unattended-upgrades:

- Daily security update checks
- Automatic installation of security patches
- Weekly cleanup of old packages
- Removes unused dependencies

### 10. Enhanced MOTD

Installs a custom Message of the Day displaying:

- Hostname (ASCII art)
- OS and kernel version
- System uptime
- IP address
- Load, memory, and disk usage
- Available updates count
- Security warning banner

---

## Post-Installation

After the script completes:

1. **Keep your current terminal open**
2. Open a new terminal window
3. Test SSH connection:
   ```bash
   ssh -p 22222 username@your-server-ip
   ```
4. Verify successful login
5. Only then close the original session

### Useful Commands

```bash
# Check firewall status
sudo ufw status

# View fail2ban status
sudo fail2ban-client status sshd

# Check SSH service
sudo systemctl status ssh

# View auth logs
sudo tail -f /var/log/auth.log

# Unban an IP from fail2ban
sudo fail2ban-client set sshd unbanip <IP_ADDRESS>
```

---

## Files Modified

| File | Purpose |
|------|---------|
| `/etc/ssh/sshd_config` | SSH server configuration |
| `/etc/fstab` | Swap and shared memory mounts |
| `/etc/ufw/before.rules` | DDoS protection rules |
| `/etc/sysctl.d/99-hardening.conf` | Kernel security parameters |
| `/etc/fail2ban/jail.local` | Fail2ban configuration |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Auto-update settings |
| `/etc/apt/apt.conf.d/50unattended-upgrades` | Unattended upgrade config |
| `/etc/update-motd.d/*` | Custom MOTD scripts |
| `/etc/issue.net` | Pre-login banner |

### Backup Files

The script creates backups before modifying:

- `/etc/ssh/sshd_config.[timestamp].bak`
- `/etc/fstab.bak`
- `/etc/ufw/before.rules.bak`

---

## Logs

All script actions are logged to:

```
/var/log/server_hardening.log
```

---

## Troubleshooting

### Locked out of SSH?

If you lose SSH access, use your VPS provider's console/VNC access to:

```bash
# Restore SSH config backup
sudo cp /etc/ssh/sshd_config.*.bak /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh

# Or disable firewall temporarily
sudo ufw disable
```

### SSH connection refused?

Check the correct port:
```bash
ssh -p 22222 user@server
```

### Fail2ban banned your IP?

From the server console:
```bash
sudo fail2ban-client set sshd unbanip YOUR_IP
```

---

## Customization

### Change SSH Port

Edit the script before running and modify:
```bash
readonly DEFAULT_SSH_PORT=22222
```

### Add Additional Firewall Ports

After running the script:
```bash
sudo ufw allow 8080/tcp comment 'Custom App'
```

### Disable Root Login Completely

When prompted during user creation, select "Yes" to disable root login.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Inspired by various VPS hardening guides and best practices
- Built for the Ubuntu Server community
```

---

## Optional: LICENSE file

If you want to include an MIT license:

```
MIT License

Copyright (c) 2025 DigitallyTailored

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
