"""Resolve packet src IPs to Device-table MACs, reusing the arp -a technique.

The OS ARP table is parsed once and cached for a few seconds, so per-packet
lookups stay cheap (no subprocess per packet). This machine's own adapter
IPs/MACs are added explicitly, since the OS cache may not list itself.
"""
import re
import subprocess
import time

_ARP_LINE = re.compile(
    rb"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
    re.ASCII,
)
_MAC_DASH = re.compile(r"-")


def parse_arp_table():
    """Parse full `arp -a` output -> {ip: normalized_mac} (all interfaces)."""
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