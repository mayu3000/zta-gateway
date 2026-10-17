"""Deployment network constants.

Every value can be overridden with an environment variable, so the same code
runs on all three deployment targets without edits:

  Option A, wired    : ZTA_INTERNAL_IFACE=eth1  (default)
  Option A, Wi-Fi AP : ZTA_INTERNAL_IFACE=wlan0 (hostapd on a USB adapter)
  Windows / Option B : values are ignored, the sniffer picks the adapter by subnet

These drive discovery, sniffing, and the captive portal. The sniffer defaults
to INTERNAL_IFACE, so the argless `start_sniffing()` in run.py automatically
binds the right interface on either deployment target.

Kali VM layout:
  UPLINK_IFACE   = path to the internet/WAN (home router)
  INTERNAL_IFACE = the side clients connect to (Ethernet port or Wi-Fi AP)
"""
import os

# Internal subnet served by dnsmasq on INTERNAL_IFACE
INTERNAL_SUBNET = os.environ.get("ZTA_INTERNAL_SUBNET", "192.168.50.0/24")

# Gateway's own address on the internal interface
GATEWAY_INTERNAL_IP = os.environ.get("ZTA_GATEWAY_IP", "192.168.50.1")

# Interface names (Linux); resolved by Scapy on Windows via _pick_interface
INTERNAL_IFACE = os.environ.get("ZTA_INTERNAL_IFACE", "eth1")
UPLINK_IFACE = os.environ.get("ZTA_UPLINK_IFACE", "eth0")

# A device counts as "connected" if the discovery sensor saw it within this many
# seconds. The sensor runs every 30s (run.py), so 90s tolerates two missed scans.
CONNECTED_TTL_SECONDS = int(os.environ.get("ZTA_CONNECTED_TTL", "90"))

# --- Portal gate (Phase 9) ---------------------------------------------------
# Master switch for the network-level captive portal. Off by default; off on
# Windows and during the existing 95 tests. Set ZTA_PORTAL_GATE=1 on Linux.
PORTAL_GATE = bool(int(os.environ.get("ZTA_PORTAL_GATE", "0")))

# Comma-separated list of internal interfaces the gate enforces on.
# Default falls back to the single INTERNAL_IFACE.
_internal_ifaces = os.environ.get(
    "ZTA_INTERNAL_IFACES", INTERNAL_IFACE)
INTERNAL_IFACES = tuple(
    s.strip() for s in _internal_ifaces.split(",") if s.strip()
)

# Whether admin approval is required before portal access is granted.
# 0 = email verification alone is sufficient.
PORTAL_REQUIRE_APPROVAL = bool(int(os.environ.get(
    "ZTA_PORTAL_REQUIRE_APPROVAL", "1")))

# Idle session timeout in minutes.
SESSION_TTL_MINUTES = int(os.environ.get("ZTA_SESSION_TTL_MINUTES", "30"))

# The URL the port-80 redirect listener sends unauthenticated devices to.
PORTAL_URL = os.environ.get(
    "ZTA_PORTAL_URL", "http://192.168.50.1:5000/login")

# --- Email warnings (Phase 10) ----------------------------------------------
# Master switch: when 0 no notification code runs (keeps the 95 tests unchanged).
NOTIFY = bool(int(os.environ.get("ZTA_NOTIFY", "1")))

# Minimum gap between warnings for the same device (minutes).
NOTIFY_COOLDOWN_MINUTES = int(os.environ.get(
    "ZTA_NOTIFY_COOLDOWN_MINUTES", "10"))

# Consecutive MEDIUM scoring windows (30s each) required before warning.
# 1 = warn on the first MEDIUM window.
NOTIFY_MIN_WINDOWS = int(os.environ.get("ZTA_NOTIFY_MIN_WINDOWS", "1"))

# Also email the owner when the device is banned.
NOTIFY_BAN_NOTICE = bool(int(os.environ.get("ZTA_NOTIFY_BAN_NOTICE", "1")))

# Optional admin address copied on every notice (empty = no copy).
NOTIFY_ADMIN_COPY = os.environ.get("ZTA_NOTIFY_ADMIN_COPY", "")

# --- DNS interception (live-gateway fix F1) ----------------------------------
# When on, all outbound DNS (udp/tcp 53) from internal clients is DNAT'd to the
# gateway's own dnsmasq. Names therefore resolve before sign-in without any
# hand-added FORWARD rule, and outside resolvers are unreachable -- which also
# closes DNS tunnelling. Granted clients are redirected too, so their lookups
# still appear in the activity monitor.
DNS_INTERCEPT = bool(int(os.environ.get("ZTA_DNS_INTERCEPT", "1")))

# --- Sign-in / approval hardening (live-gateway fix F4) ---------------------
# Infra MACs are never gated and never auto-banned: the access point, the
# admin's own laptop, printers. Comma-separated, matched case-insensitively.
INFRA_MACS = tuple(
    s.strip().lower() for s in
    os.environ.get("ZTA_INFRA_MACS", "").split(",") if s.strip()
)

# Seconds to keep sending ARP requests for a client IP before giving up on
# resolving its MAC (the neighbour cache may not have it yet right after DHCP).
MAC_LOOKUP_TIMEOUT = float(os.environ.get("ZTA_MAC_LOOKUP_TIMEOUT", "2.0"))

# --- Typed email verification code (live-gateway fix F3) --------------------
# The 6-digit code emailed at registration: how long it stays valid, how many
# wrong tries are allowed before it locks, and how long that lock lasts.
VERIFY_CODE_TTL_MINUTES = int(
    os.environ.get("ZTA_VERIFY_CODE_TTL_MINUTES", "15"))
VERIFY_CODE_MAX_TRIES = int(os.environ.get("ZTA_VERIFY_CODE_MAX_TRIES", "5"))
VERIFY_CODE_LOCK_MINUTES = int(
    os.environ.get("ZTA_VERIFY_CODE_LOCK_MINUTES", "15"))
