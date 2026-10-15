"""Network discovery "sensor".

Two sensors, chosen per platform:
  Linux (Option A inline gateway): Scapy's native ARP broadcast scan — the
  originally-designed sensor, which works properly on native Linux (raw
  sockets + root) but was deferred on Windows. Falls back to OS-native
  ping + neighbor-table parse if Scapy errors.
  Windows: Scapy only receives its own ARP reply on MinGW/Npcap, so the
  reliable path is a directed-broadcast ping to wake ARP resolution, then
  read the system ARP cache (`arp -a`).
"""
import ipaddress
import platform
import re
import subprocess

from app import config as cfg
from app.capture.resolve import local_ip_macs, parse_arp_table

_IS_LINUX = platform.system() != "Windows"

_STATION_LINE = re.compile(r"^Station\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
                           re.MULTILINE)


def get_wifi_stations(iface=None):
    """MACs currently associated to the Wi-Fi AP on *iface*.

    Uses `iw dev <iface> station dump`, which reflects association state in
    real time (a phone that leaves Wi-Fi disappears within seconds, unlike an
    ARP/neighbor cache entry that lingers for minutes).

    Returns a set of lowercase MACs, or None when this is not a wireless AP
    interface (Windows, wired eth1, `iw` missing, no AP running). None means
    "no Wi-Fi information available", so callers must not filter on it.
    """
    if not _IS_LINUX:
        return None
    iface = iface or cfg.INTERNAL_IFACE
    try:
        proc = subprocess.run(["iw", "dev", iface, "station", "dump"],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {m.lower() for m in _STATION_LINE.findall(proc.stdout)}


def scan_network(ip_range=None, iface=None):
    """Return a list of {ip, mac} for hosts answering on the subnet."""
    if ip_range is None:
        ip_range = cfg.INTERNAL_SUBNET
    if _IS_LINUX:
        try:
            devices = scan_network_scapy(ip_range, iface or cfg.INTERNAL_IFACE)
        except Exception:  # noqa: BLE001 — scapy may lack raw-socket access
            return _scan_ping_arp(ip_range)
        # Wi-Fi AP mode: only devices still associated count as connected.
        stations = get_wifi_stations(iface or cfg.INTERNAL_IFACE)
        if stations is not None:
            devices = [d for d in devices if d["mac"].lower() in stations]
        return devices
    return _scan_ping_arp(ip_range)


def _scan_ping_arp(ip_range):
    """Broadcast-ping wake + neighbor-table parse (works on both OSes)."""
    net = ipaddress.ip_network(ip_range, strict=False)
    broadcast = str(net.broadcast_address)
    if _IS_LINUX:
        ping = ["ping", "-c", "2", "-W", "1", broadcast]
    else:
        ping = ["ping", "-n", "2", "-w", "400", broadcast]
    subprocess.run(ping, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    seen = set()
    devices = []
    # neighbor table omits this machine itself, merge in own adapter rows too.
    arp_entries = parse_arp_table()
    arp_entries.update(local_ip_macs())
    for ip, mac in arp_entries.items():
        if ipaddress.ip_address(ip) not in net:  # only the target subnet
            continue
        if ip == broadcast:  # broadcast, not a host
            continue
        if mac in seen:
            continue
        seen.add(mac)
        devices.append({"ip": ip, "mac": mac})
    return devices


def scan_network_scapy(ip_range=None, iface=None):
    """Scapy ARP broadcast scan — the classic technique (native Linux).

    On Windows/MinGW+Npcap it only ever receives replies from the host
    itself, so it is NOT used there (auto-falls back to _scan_ping_arp).
    """
    if ip_range is None:
        ip_range = cfg.INTERNAL_SUBNET
    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(packet, timeout=3, verbose=0, iface=iface)[0]
    devices = []
    for _sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


if __name__ == "__main__":
    for d in scan_network():
        print(d)