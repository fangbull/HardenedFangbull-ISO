# 🛡️ Hardened Fangbull Linux Distribution

**Hardened Security-Focused Linux Distribution with Proactive Threat Detection**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 Installation](#-installation-guide) • [🛡️ Security](#-security-features) • [🎯 Usage](#-usage-guide)

</div>

---

## 📋 Table of Contents

- [🌟 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🎯 Target Users](#-target-users)
- [⚡ Quick Start](#-quick-start)
- [📦 System Requirements](#-system-requirements)
- [🔧 Installation Guide](#-installation-guide)
- [🛡️ Security Features](#-security-features)
- [🎛️ Management Tools](#-management-tools)
- [📊 Performance Optimization](#-performance-optimization)
- [🔍 Monitoring & Logging](#-monitoring--logging)
- [🚨 Troubleshooting](#-troubleshooting)
- [📚 Advanced Configuration](#-advanced-configuration)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🌟 Overview

**Hardened Fangbull** is an ultra-hardened, security-focused Linux distribution based on Arch Linux. It features **10 custom Intrusion Detection System (IDS) scripts**, advanced threat detection, comprehensive system hardening, and user-friendly management tools.

### 🎯 Mission
To provide a production-ready, security-hardened Linux distribution that offers **proactive threat detection** and **defense-in-depth** security architecture without sacrificing usability.

### 🏗️ Architecture
- **Base**: Arch Linux (Rolling Release)
- **Desktop**: XFCE4 (Hardened Configuration)
- **Firewall**: nftables with Advanced DDoS Protection
- **IDS**: 10 Custom Real-time Detection Scripts
- **MAC**: AppArmor with 15+ Custom Profiles
- **Kernel**: Hardened Linux Kernel

---

## ✨ Key Features

### 🛡️ **Security Features**
- **10 Custom IDS Scripts** for real-time threat detection
- **Ultra-hardened kernel** with 243-line sysctl configuration
- **Advanced nftables firewall** with DDoS protection and geo-blocking
- **AppArmor Mandatory Access Control** with 15+ custom profiles
- **Supply chain attack protection** via AUR helper blocking
- **Comprehensive system hardening** from kernel to application layer
- **Kernel** Hardened Linux kernel default

### 🎛️ **Management Tools**
- **fangbull-sys**: 19-option system administration tool
- **fangbull-usbguard**: 23-option USB device management
- **fangbull-jails**: 27-option Firejail sandbox management
- **fangbull-crypt**: Age-based encryption tool
- **Menu-driven interfaces** for all security tools

### ⚡ **Performance Optimization**
- **Optimized logging system** with automatic rotation
- **Hash-based caching** for 80%+ cache hit rates
- **Concurrent operation limiting** to prevent system overload
- **Adaptive timing** based on system load and threat detection
- **Emergency disk space management** with automated cleanup

---

## 🎯 Target Users

### ✅ **Ideal Users**
- **Security Professionals**: SOC analysts, penetration testers, security researchers
- **System Administrators**: Enterprise security teams, IT security managers
- **Threat Hunters**: Malware analysts, incident response teams
- **Advanced Linux Users**: Users with Arch Linux experience
- **Security Enthusiasts**: Technical hobbyists interested in security

### 📚 **Required Knowledge Level**
- **Linux Command Line**: Intermediate to Advanced
- **Network Security**: Basic understanding of firewalls, IDS/IPS
- **System Administration**: Systemd service management
- **Log Analysis**: Ability to read and interpret security logs

### ❌ **Not Suitable For**
- **Beginners**: Users new to Linux
- **Casual Users**: Basic web browsing and office work
- **Gaming**: Performance-critical gaming setups
- **Multimedia Editing**: Video/audio editing workstations
- **Legacy Hardware**: Systems with <4GB RAM or old CPUs

---

## ⚡ Quick Start

### 🚀 **5-Minute Setup**

```bash
# 1. Download ISO
download from Sourceforge

# 2. Create bootable USB
sudo dd if=hardened-fangbull.iso of=/dev/sdX bs=4M status=progress

# 3. Boot from USB and run installer
sudo hardened-fangbull-installer

# 4. Post-installation: Check system status
sudo fangbull-sys
```

### 🔍 **First Boot Checklist**
- [ ] Verify all IDS services are running
- [ ] Check firewall status
- [ ] Review initial security logs
- [ ] Configure network settings
- [ ] Set up user accounts

---

## 📦 System Requirements

### 🖥️ **Minimum Requirements**
| Component | Requirement |
|-----------|-------------|
| **CPU** | x86_64, 2 cores, 2.0 GHz |
| **RAM** | 4 GB (8 GB recommended) |
| **Storage** | 20 GB free space |
| **Network** | Internet connection for installation |
| **Boot** | UEFI or Legacy BIOS support |

### 🚀 **Recommended Specifications**
| Component | Recommendation |
|-----------|----------------|
| **CPU** | x86_64, 4+ cores, 3.0+ GHz |
| **RAM** | 8 GB or more |
| **Storage** | 50 GB+ SSD |
| **Network** | Gigabit Ethernet |
| **Graphics** | Any modern GPU |

### 💾 **Performance Impact**
- **Base System**: ~800 MB RAM
- **IDS Scripts**: ~200 MB RAM
- **Desktop Environment**: ~300 MB RAM
- **Total Runtime**: ~1.3 GB RAM usage

---

## 🔧 Installation Guide

### 📀 **Creating Installation Media**

#### **Method 1: Using dd (Linux)**
```bash
# Download the latest ISO
download from Sourceforge

# Verify checksum (recommended)
sha256sum hardened-fangbull.iso

# Create bootable USB (replace /dev/sdX with your USB device)
sudo dd if=hardened-fangbull.iso of=/dev/sdX bs=4M status=progress oflag=sync

# Verify the write
sudo sync
```

#### **Method 2: Using Rufus (Windows)**
1. Download [Rufus](https://rufus.ie/)
2. Select your USB device
3. Choose the Hardened Fangbull ISO
4. Select "DD Image" mode
5. Click "START"

#### **Method 3: Using Etcher (Cross-platform)**
1. Download [Balena Etcher](https://www.balena.io/etcher/)
2. Select the ISO file
3. Select your USB device
4. Click "Flash!"

#### **Method 4: Ventoy (Cross-platform)**
1. Download [Ventoy](https://www.ventoy.net/)
2. Select the ISO file


### 🚀 **Live Boot Process**

#### **Step 1: Boot Configuration**
```bash
# Boot parameters (if needed)
# For NVIDIA graphics:
hardened-fangbull.iso nomodeset

# For older hardware:
hardened-fangbull.iso acpi=off

```

#### **Step 2: Live Environment**
```bash
# Check system status
systemctl status

# Verify network connectivity
ping -c 3 google.com

# Check available disks
lsblk

# Test IDS functionality
sudo systemctl status ghost-service-killer
```

### 💾 **Installation Process**

#### **Automated Installation (Recommended)**
```bash
# Run the installer
sudo hardened-fangbull-installer

# Follow the interactive prompts:
# 1. Disk selection and partitioning
# 2. User account creation
# 3. Network configuration
# 4. Security settings confirmation
# 5. Package installation
```

### ⚙️ **Post-Installation Configuration**

#### **Step 1: User Setup**
```bash
# Create user account
sudo useradd -m -G wheel,audio,video,storage securonis
sudo passwd securonis

# Configure sudo
sudo visudo
# Uncomment: %wheel ALL=(ALL) ALL
```

#### **Step 2: Network Configuration**
```bash
# Enable NetworkManager
sudo systemctl enable NetworkManager
sudo systemctl start NetworkManager

# Connect to WiFi
nmcli device wifi connect "SSID" password "password"

# Configure firewall for your network
sudo fangbull-sys
# Select: Network Management > Firewall Configuration
```

#### **Step 3: Security Verification**
```bash
# Check all IDS services
sudo systemctl status ghost-service-killer
sudo systemctl status suspicious-cron-dropper-killer
sudo systemctl status hidden-binary-execution-catcher

# Verify AppArmor profiles
sudo aa-status

# Check firewall rules
sudo nft list ruleset

# Review security logs
sudo tail -f /var/log/fangbull-ids/*.log
```

---

## 🛡️ Security Features

### 🔍 **Intrusion Detection System (IDS)**

Hardened Fangbull includes **10 custom IDS scripts** that provide real-time threat detection:

#### **1. Ghost Service Killer**
```bash
# Purpose: Detect and eliminate suspicious hidden services
# Location: /usr/local/bin/ghost_service_killer
# Log: /var/log/fangbull-ids/ghost_service.log

# Manual execution
sudo ghost_service_killer

# Check status
sudo systemctl status ghost-service-killer

# View logs
sudo tail -f /var/log/fangbull-ids/ghost_service.log
```

#### **2. Suspicious Cron Dropper Killer**
```bash
# Purpose: Detect malicious cron jobs and scheduled tasks
# Features: YARA rule matching, behavioral analysis
# Scan interval: 60 seconds (optimized)

# Check detected threats
sudo cat /var/log/fangbull-ids/cron_dropper.log

# View performance stats
sudo cat /var/log/fangbull-ids/cron_performance.stats
```

#### **3. Hidden Binary Execution Catcher**
```bash
# Purpose: Detect processes running from deleted binaries
# Features: Memory analysis, forensic data collection

# Check for hidden binaries
sudo hidden_binary_execution_catcher --scan-once

# View forensic samples
sudo ls -la /var/log/fangbull-ids/hidden_samples/
```

#### **4. Malicious Script Exterminator**
```bash
# Purpose: Detect and eliminate malicious scripts
# Supported: Shell, Python, Perl, PHP scripts
# Features: Static analysis, dynamic behavior monitoring

# Manual scan
sudo malscript_exterminator --deep-scan

# Check quarantined scripts
sudo ls -la /var/log/fangbull-ids/malscript_samples/
```

#### **5. Memory Resident Process Checker**
```bash
# Purpose: Detect memory-resident malware
# Features: Process hollowing detection, injection analysis

# Check memory anomalies
sudo memory_resident_process_checker --analyze

# View memory dumps
sudo ls -la /var/log/fangbull-ids/memory_dumps/
```

### 🔥 **Advanced Firewall Configuration**

#### **nftables Rules Overview**
```bash
# View current ruleset
sudo nft list ruleset

# Key features:
# - Default deny policy
# - DDoS protection with rate limiting
# - Port scan detection and blocking
# - Geo-blocking for suspicious countries
# - Connection state tracking
# - ICMP flood protection
```

#### **Firewall Management**
```bash
# Start/stop firewall
sudo systemctl start great-fangbull-firewall
sudo systemctl stop great-fangbull-firewall

# Add custom rules
sudo nft add rule inet filter input tcp dport 22 accept

# Block specific IP
sudo nft add rule inet filter input ip saddr 192.168.1.100 drop

# Allow VPN traffic
sudo nft add rule inet filter output oif tun0 accept
```

### 🛡️ **AppArmor Mandatory Access Control**

#### **Profile Management**
```bash
# List all profiles
sudo aa-status

# Enforce a profile
sudo aa-enforce /etc/apparmor.d/usr.local.bin.fangbull-sys

# Set profile to complain mode
sudo aa-complain /etc/apparmor.d/usr.local.bin.fangbull-sys

# Disable a profile
sudo aa-disable /etc/apparmor.d/usr.local.bin.fangbull-sys

# Reload all profiles
sudo systemctl reload apparmor
```

#### **Custom Profiles**
Hardened Fangbull includes custom AppArmor profiles for:
- All IDS scripts
- System management tools
- AUR helper blocking (security feature)
- Firefox sandboxing
- USB device management

### 🔒 **Kernel Hardening**

#### **Sysctl Configuration**
```bash
# View current kernel parameters
sudo sysctl -a | grep -E "(kernel|net|fs)"

# Key hardening features:
# - ASLR: kernel.randomize_va_space = 2
# - Ptrace restrictions: kernel.yama.ptrace_scope = 3
# - Kernel pointer hiding: kernel.kptr_restrict = 2
# - Core dump restrictions: fs.suid_dumpable = 0
# - Network hardening: Multiple TCP/IP protections
```

---

## 🎛️ Management Tools

### 🖥️ **fangbull-sys - System Administration Tool**

The primary system management interface with 19 comprehensive options:

```bash
# Launch system manager
sudo fangbull-sys

# Available categories:
# 1. System Information & Monitoring
# 2. Security & Threat Management  
# 3. Network & Connectivity
# 4. Performance & Maintenance
```

#### **System Information & Monitoring**
```bash
# Option 1: System Overview
# - Hardware information
# - CPU, memory, disk usage
# - Running services status
# - Security service health

# Option 2: Process Monitor
# - Real-time process monitoring
# - Resource usage tracking
# - Suspicious process detection

# Option 3: Disk Analysis
# - Disk usage breakdown
# - Large file detection
# - Cleanup recommendations
```

#### **Security & Threat Management**
```bash
# Option 5: IDS Status
# - All 10 IDS service status
# - Threat detection summary
# - Recent security events

# Option 6: Threat Intelligence
# - Threat database statistics
# - IOC (Indicators of Compromise)
# - Risk assessment reports

# Option 7: File Integrity Monitor
# - Critical file monitoring
# - Hash verification
# - Change detection alerts
```

### 🔌 **fangbull-usbguard - USB Device Management**

Comprehensive USB security management with 23 options:

```bash
# Launch USB manager
sudo fangbull-usbguard

# Key features:
# - Device whitelisting/blacklisting
# - Real-time USB monitoring
# - Policy management
# - Forensic logging
```

#### **Device Management**
```bash
# Option 1: List Connected Devices
# Shows all currently connected USB devices with details

# Option 2: Device Allow/Block
# Temporarily or permanently allow/block devices

# Option 3: Generate Device Policy
# Create rules based on current devices

# Option 4: Import/Export Policies
# Backup and restore USB policies
```

### 🏰 **fangbull-jails - Firejail Sandbox Management**

Advanced application sandboxing with 27 options:

```bash
# Launch sandbox manager
sudo fangbull-jails

# Key features:
# - Application isolation
# - Custom security profiles
# - Resource limiting
# - Network isolation
```

#### **Quick Launch Options**
```bash
# Option 1: Sandboxed Firefox
firejail --profile=firefox firefox

# Option 2: Sandboxed Terminal
firejail --profile=terminal xfce4-terminal

# Option 3: Sandboxed File Manager
firejail --profile=filemanager thunar

# Option 4: Sandboxed Text Editor
firejail --profile=editor mousepad
```

### 🔐 **fangbull-crypt - Encryption Tool**

Age-based encryption with menu interface:

```bash
# Launch encryption tool
fangbull-crypt

# Features:
# - File/directory encryption
# - Secure key management
# - Batch operations
# - Secure deletion
```

---

## 📊 Performance Optimization

### ⚡ **System Performance Tuning**

#### **IDS Optimization**
```bash
# Performance improvements implemented:
# - Scan intervals increased from 30-45s to 60s (40-50% CPU reduction)
# - Severity thresholds raised from 70 to 75 (30% false positive reduction)
# - Hash-based caching with 80%+ hit rates
# - Concurrent operation limiting (max 2-3 parallel scans)
# - Adaptive timing based on system load

# Check IDS performance
sudo cat /var/log/fangbull-ids/*/performance.stats

# Adjust scan intervals (if needed)
sudo systemctl edit ghost-service-killer
# Add:
# [Service]
# Environment="SCAN_INTERVAL=120"
```

#### **Memory Optimization**
```bash
# Current memory usage:
# - Base system: ~800MB
# - IDS scripts: ~200MB  
# - Desktop: ~300MB
# - Total: ~1.3GB

# Reduce memory usage:
# 1. Disable unnecessary IDS scripts
sudo systemctl disable zombie-process-hunter  # If not needed

# 2. Adjust cache sizes
sudo nano /usr/local/bin/fangbull-log-manager
# Modify: MAX_CACHE_SIZE=512000  # Reduce from 1MB to 512KB

# 3. Limit concurrent operations
sudo nano /usr/local/bin/ghost_service_killer
# Modify: MAX_CONCURRENT_SCANS=1  # Reduce from 2
```

#### **Disk I/O Optimization**
```bash
# Log management optimizations:
# - Automatic log rotation every 6 hours
# - Compression of rotated logs
# - Emergency cleanup at 85% disk usage
# - Intelligent cache management

# Manual optimization
sudo fangbull-log-manager optimize

# Emergency cleanup (if disk full)
sudo fangbull-log-manager emergency

# Monitor disk usage
sudo fangbull-disk-monitor check
```

---

## 🔍 Monitoring & Logging

### 📊 **Log Management System**

#### **Centralized Logging**
```bash
# All logs are centralized in:
/var/log/fangbull-ids/

# Log structure:
├── ghost_service.log          # Ghost service detection
├── cron_dropper.log          # Cron job analysis
├── hidden_binary.log         # Hidden binary detection
├── malscript.log            # Malicious script detection
├── memory_resident.log      # Memory analysis
├── netlink_monitor.log      # Network monitoring
├── rootshell_injection.log  # Injection detection
├── shell_fork_bomb.log      # Fork bomb detection
├── tty_hijack.log          # TTY hijacking
├── zombie_process.log       # Zombie process cleanup
└── *.cache                  # Cache files
└── */samples/              # Forensic samples
└── */performance.stats     # Performance metrics
```

#### **Log Levels and Filtering**
```bash
# Log levels (in order of priority):
# 1. CRITICAL - Immediate threats and system issues
# 2. ERROR - Errors that need attention
# 3. WARNING - Potential issues
# 4. INFO - General information

# Set log level
sudo fangbull-log-manager set-level WARNING

# View only critical logs
sudo grep "CRITICAL" /var/log/fangbull-ids/*.log

# Real-time log monitoring
sudo tail -f /var/log/fangbull-ids/*.log
```

#### **Automated Log Rotation**
```bash
# Logrotate configuration:
# - Daily rotation for main logs (7 days retention)
# - Weekly rotation for cache files (1 day retention)
# - Monthly rotation for intelligence databases (3 months retention)
# - Size limits: 5-10MB per log file

# Manual log rotation
sudo logrotate -f /etc/logrotate.d/fangbull-ids

# Check rotation status
sudo logrotate -d /etc/logrotate.d/fangbull-ids
```

---

## 🚨 Troubleshooting

### 🔧 **Common Issues and Solutions**

#### **Issue 1: IDS Service Fails to Start**
```bash
# Symptoms:
# - Service shows "failed" status
# - No logs being generated
# - Error messages in systemctl status

# Diagnosis:
sudo systemctl status ghost-service-killer
sudo journalctl -u ghost-service-killer -n 50

# Common solutions:

# 1. Check log manager
sudo ls -la /usr/local/bin/fangbull-log-manager

# 2. Fix permissions
sudo chown root:root /usr/local/bin/ghost_service_killer
sudo chmod +x /usr/local/bin/ghost_service_killer

# 3. Create missing directories
sudo mkdir -p /var/log/fangbull-ids
sudo chown root:root /var/log/fangbull-ids
sudo chmod 750 /var/log/fangbull-ids

# 4. Restart service
sudo systemctl restart ghost-service-killer
```

#### **Issue 2: High CPU Usage**
```bash
# Symptoms:
# - System slowdown
# - High load averages
# - IDS scripts consuming too much CPU

# Solutions:

# 1. Increase scan intervals
sudo systemctl edit ghost-service-killer
# Add: Environment="SCAN_INTERVAL=120"

# 2. Reduce concurrent operations
sudo nano /usr/local/bin/ghost_service_killer
# Modify: MAX_CONCURRENT_SCANS=1

# 3. Disable non-essential IDS scripts
sudo systemctl disable zombie-process-hunter
```

#### **Issue 3: Network Connectivity Problems**
```bash
# Symptoms:
# - Cannot access internet
# - VPN connections fail
# - Some applications blocked

# Solutions:

# 1. Check firewall rules
sudo nft list ruleset

# 2. Allow VPN traffic
sudo nft add rule inet filter output oif tun0 accept

# 3. Temporarily disable firewall
sudo systemctl stop great-fangbull-firewall

# 4. Check AppArmor blocks
sudo aa-status
sudo aa-complain /etc/apparmor.d/problematic-profile
```

#### **Issue 4: Disk Space Full**
```bash
# Symptoms:
# - System becomes unresponsive
# - Cannot write files
# - Log rotation fails

# Emergency solutions:

# 1. Emergency cleanup
sudo fangbull-log-manager emergency

# 2. Manual cleanup
sudo find /var/log/fangbull-ids -name "*.log.*" -delete
sudo find /tmp -type f -mtime +1 -delete

# 3. Increase disk space
# Add more storage or remove unnecessary files
```

---

## 📚 Advanced Configuration

### 🔧 **Custom IDS Configuration**

#### **Adjusting Detection Thresholds**
```bash
# Edit IDS script configuration
sudo nano /usr/local/bin/ghost_service_killer

# Key parameters to adjust:
# SEVERITY_THRESHOLD=75    # Increase to reduce false positives
# SCAN_INTERVAL=60        # Increase to reduce CPU usage
# MAX_CONCURRENT_SCANS=2  # Reduce for lower resource usage
```

#### **Creating Custom YARA Rules**
```bash
# Create custom YARA rules for malware detection
sudo nano /var/log/fangbull-ids/custom_rules/my_rules.yar

# Example rule:
rule Custom_Malware_Detection {
    strings:
        $suspicious1 = "eval(base64_decode"
        $suspicious2 = "system($_GET"
        $suspicious3 = "exec($_POST"
    condition:
        any of them
}
```

### 🛡️ **Advanced AppArmor Configuration**

#### **Creating Custom Profiles**
```bash
# Generate profile for new application
sudo aa-genprof /path/to/application

# Edit existing profile
sudo nano /etc/apparmor.d/usr.local.bin.my-app

# Test profile in complain mode
sudo aa-complain /etc/apparmor.d/usr.local.bin.my-app

# Enforce profile
sudo aa-enforce /etc/apparmor.d/usr.local.bin.my-app
```

### 🔥 **Advanced Firewall Configuration**

#### **Custom nftables Rules**
```bash
# Edit firewall script
sudo nano /usr/local/bin/great-fangbull-firewall

# Add custom rules:
# Allow specific application
nft add rule inet filter input tcp dport 8080 accept

# Rate limit specific service
nft add rule inet filter input tcp dport 22 limit rate 5/minute accept

# Geo-blocking (example for blocking specific countries)
nft add rule inet filter input ip saddr @country_blocklist drop
```

---

## 🤝 Contributing


### 📋 **Contribution Guidelines**

1. **Security First**: All contributions must maintain or improve security
2. **Testing Required**: Test all changes in isolated environment
3. **Documentation**: Update documentation for any new features
4. **Code Quality**: Follow existing code style and patterns
5. **Performance**: Consider performance impact of changes

### 🐛 **Bug Reports**

Please include:
- System information (`uname -a`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant log files
- Screenshots if applicable

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

### 🔒 **Security Disclaimer**

Hardened Fangbull is provided "as is" without warranty. Users are responsible for:
- Proper configuration and maintenance
- Compliance with local laws and regulations
- Regular security updates
- Backup and disaster recovery

### ⚠️ **Important Notes**

- This is a security-focused distribution intended for advanced users
- Some features may break compatibility with certain applications
- Regular updates and monitoring are essential
- Always test in non-production environments first

---

<div align="center">

**Made with ❤️ by the Root0emir**

[🌟 Star  on GitHub](https://github.com/root0emir/HardenedSecuronis) • [📧 Report Issues](https://github.com/root0emir/HardenedSecuronis/issues) • [💬 Join Discussion](https://github.com/root0emir/HardenedSecuronis/discussions)

</div>
