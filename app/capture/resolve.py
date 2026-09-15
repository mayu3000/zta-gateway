"""Resolve packet src IPs to Device-table MACs.

The OS ARP/neighbor table is parsed once and cached for a few seconds, so
per-packet lookups stay cheap (no subprocess per packet). This machine's own
adapter IPs/MACs are added explicitly, since the OS cache may not list itself.

Two OS formats are handled:
  Windows — `arp -a`, rows like `192.168.1.5   aa-bb-cc-dd-ee-ff` (dash MACs);
  Linux   — `ip -o neigh show`, rows like `192.168.1.5 dev eth1 lladdr aa:..:ff`.
"""
import platform
import re
import subprocess
import time

# Windows `arp -a`:  IP <ws> MAC (dash or colon separated).
_ARP_LINE = re.compile(
    rb"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
    re.ASCII,
)
# Linux `ip -o neigh`:  IP dev eth1 lladdr aa:bb:cc:dd:ee:ff [STALE|REACHABLE]
_LINUX_NEIGH = re.compile(
    rb"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
    re.ASCII,
)
_MAC_DASH = re.compile(r"-")

_IS_LINUX = platform.system() != "Windows"


def parse_ip_neigh():
    """Parse `ip -o neigh show` -> {ip: normalized_mac} (Linux only)."""
    out = subprocess.run(["ip", "-o", "neigh", "show"],
                         capture_output=True).stdout
    macs = {}
    for m in _LINUX_NEIGH.finditer(out):
        ip = m.group(1).decode()
        mac = m.group(2).decode().lower()
        macs[ip] = mac
    return macs


def parse_arp_table():
    """Parse the OS neighbor table -> {ip: normalized_mac} (all interfaces)."""
    if _IS_LINUX:
        return parse_ip_neigh()
    out = subprocess.run(["arp", "-a"], capture_output=True).stdout
    macs = {}
    for m in _ARP_LINE.finditer(out):
        ip = m.group(1).decode()
        mac = _MAC_DASH.sub(":", m.group(2).decode().lower())
        macs[ip] = mac
    return macs


def local_ip_macs():
    """{ip: mac} for this machine's own adapters (the OS cache omits itself)."""
    from scapy.all import get_if_addr, get_if_hwaddr, get_if_list

    result = {}
    for iface in get_if_list():
        try:
            ip, mac = get_if_addr(iface), get_if_hwaddr(iface)
        except Exception:
            continue
        if ip and ip != "0.0.0.0" and mac and mac != "00:00:00:00:00:00":
            result[ip] = mac
    return result


_cache = {}
_cache_ts = 0.0
_CACHE_TTL = 10.0


def get_mac_for_ip(ip):
    """Return the MAC for a LAN IP, or None if unknown/off-subnet."""
    global _cache, _cache_ts
    now = time.time()
    if now - _cache_ts > _CACHE_TTL:
        _cache = parse_arp_table()
        _cache.update(local_ip_macs())
        _cache_ts = now
    return _cache.get(ip)