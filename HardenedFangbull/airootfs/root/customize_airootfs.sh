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

# IDS SERVICES REMOVED: Temporarily removed to prevent boot RAM overflow
# IDS system will be re-implemented with better resource management later"

# Protect firewall and system management scripts
chattr +i /usr/local/bin/great-fangbull-firewall
chattr +i /usr/local/bin/fangbull-sys
chattr +i /usr/local/bin/fangbull-crypt
chattr +i /usr/bin/permissionhardening

# Protect systemd service files
echo "[INFO] Protecting systemd service files..."
chattr +i /etc/systemd/system/great-fangbull-firewall.service
chattr +i /etc/systemd/system/permissionhardening.service

echo "[INFO] Critical file protection completed successfully"