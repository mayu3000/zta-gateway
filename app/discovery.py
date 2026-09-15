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
import subprocess

from app import config as cfg
from app.capture.resolve import local_ip_macs, parse_arp_table

_IS_LINUX = platform.system() != "Windows"


def scan_network(ip_range=None, iface=None):
    """Return a list of {ip, mac} for hosts answering on the subnet."""
    if ip_range is None:
        ip_range = cfg.INTERNAL_SUBNET
    if _IS_LINUX:
        try:
            return scan_network_scapy(ip_range, iface or cfg.INTERNAL_IFACE)
        except Exception:  # noqa: BLE001 — scapy may lack raw-socket access
            pass
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