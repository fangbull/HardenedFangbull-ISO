#!/bin/bash


#!/usr/bin/env bash

## Script to perform several important tasks before `mkarchcraftiso` create filesystem image.

set -e -u

## -------------------------------------------------------------- ##

## -------------------------------------------------------------- ##

systemctl enable great-fangbull-firewall.service

systemctl enable permissionhardening.service

systemctl enable apparmor.service

systemctl enable haveged

systemctl enable firstboot.service

# Enable log management and optimization
systemctl enable fangbull-log-optimizer.timer
systemctl enable logrotate.timer

# Enable Fangbull Attack Detection Systems
systemctl enable ghost-service-killer.service
systemctl enable hidden-binary-execution-catcher.service
systemctl enable malscript-exterminator.service
systemctl enable memory-resident-process-checker.service
systemctl enable netlink-monitor-watchdog.service
systemctl enable rootshell-injection-mitigator.service
systemctl enable shell-fork-bomb-terminator.service
systemctl enable suspicious-cron-dropper-killer.service
systemctl enable tty-hijack-detector.service
systemctl enable zombie-process-hunter.service

############################################
# AppArmor AUR Helper Security Enforcement
############################################
# echo "[INFO] Loading AppArmor profiles to block AUR helpers for security..."

# Load AUR helper denial profiles
# apparmor_parser -r /etc/apparmor.d/usr.bin.yay 2>/dev/null || true
# apparmor_parser -r /etc/apparmor.d/usr.bin.paru 2>/dev/null || true
# apparmor_parser -r /etc/apparmor.d/usr.bin.trizen 2>/dev/null || true
# apparmor_parser -r /etc/apparmor.d/usr.bin.pikaur 2>/dev/null || true
# apparmor_parser -r /etc/apparmor.d/usr.bin.chaotic-aur 2>/dev/null || true
# apparmor_parser -r /etc/apparmor.d/aur-helpers-deny 2>/dev/null || true

# Ensure AppArmor profiles are enforced
# aa-enforce /etc/apparmor.d/usr.bin.yay 2>/dev/null || true
# aa-enforce /etc/apparmor.d/usr.bin.paru 2>/dev/null || true
# aa-enforce /etc/apparmor.d/usr.bin.trizen 2>/dev/null || true
# aa-enforce /etc/apparmor.d/usr.bin.pikaur 2>/dev/null || true
# aa-enforce /etc/apparmor.d/usr.bin.chaotic-aur 2>/dev/null || true

# echo "[INFO] AUR helper blocking profiles loaded and enforced"

############################################
# Critical File Protection with chattr +i
############################################
echo "[INFO] Protecting critical system files with immutable attribute..."

# Protect network configuration
chattr +i /etc/resolv.conf

# Protect security limits and sysctl
chattr +i /etc/security/limits.d/hardened.conf
chattr +i /etc/sysctl.d/sysctl.conf

# Protect IDS scripts from modification
echo "[INFO] Protecting Fangbull IDS scripts..."
chattr +i /usr/local/bin/ghost_service_killer
chattr +i /usr/local/bin/hidden_binary_execution_catcher
chattr +i /usr/local/bin/malscript_exterminator
chattr +i /usr/local/bin/memory_resident_process_checker
chattr +i /usr/local/bin/netlink_monitor_watchdog
chattr +i /usr/local/bin/rootshell_injection_mitigator
chattr +i /usr/local/bin/shell_fork_bomb_terminator
chattr +i /usr/local/bin/suspicious_cron_dropper_killer
chattr +i /usr/local/bin/tty_hijack_detector
chattr +i /usr/local/bin/zombie_process_hunter
chattr +i /usr/local/bin/common_functions

# Protect firewall and system management scripts
chattr +i /usr/local/bin/great-fangbull-firewall
chattr +i /usr/local/bin/fangbull-sys
chattr +i /usr/local/bin/fangbull-crypt
chattr +i /usr/local/bin/permissionhardening

# Protect systemd service files
echo "[INFO] Protecting systemd service files..."
chattr +i /etc/systemd/system/great-fangbull-firewall.service
chattr +i /etc/systemd/system/permissionhardening.service
chattr +i /etc/systemd/system/ghost-service-killer.service
chattr +i /etc/systemd/system/hidden-binary-execution-catcher.service
chattr +i /etc/systemd/system/malscript-exterminator.service
chattr +i /etc/systemd/system/memory-resident-process-checker.service
chattr +i /etc/systemd/system/netlink-monitor-watchdog.service
chattr +i /etc/systemd/system/rootshell-injection-mitigator.service
chattr +i /etc/systemd/system/shell-fork-bomb-terminator.service
chattr +i /etc/systemd/system/suspicious-cron-dropper-killer.service
chattr +i /etc/systemd/system/tty-hijack-detector.service
chattr +i /etc/systemd/system/zombie-process-hunter.service

echo "[INFO] Critical file protection completed successfully"