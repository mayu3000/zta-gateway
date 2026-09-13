"""Network discovery "sensor".

On this Windows machine (MinGW/MSYS2 Python + Npcap) Scapy's ARP scan only
receives the host's own ARP reply and misses every other host — see
`scan_network_scapy` below. The reliable approach here is OS-native: send a
directed broadcast ping to wake ARP resolution, then read the system ARP
cache (`arp -a`). This is the same idea arp-scan implements, minus raw sockets.
"""
import ipaddress
import re
import subprocess

# MAC in arp -a output uses dashes, e.g. 44-95-3b-e5-29-f0 -> 44:95:3b:e5:29:f0
_ARP_LINE = re.compile(
    rb"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
    re.ASCII,
)
_MAC_DASH = re.compile(r"-")


def scan_network(ip_range="192.168.1.0/24"):
    """Return a list of {ip, mac} for hosts answering on the subnet.

    Sends a couple of directed-broadcast ICMP pings so live hosts resolve
    themselves in the OS ARP cache, then parses ``arp -a`` for this subnet.
    """
    net = ipaddress.ip_network(ip_range, strict=False)
    broadcast = str(net.broadcast_address)
    # -w 400 = 400 ms timeout per reply; two pings gives slow devices a chance.
    subprocess.run(
        ["ping", "-n", "2", "-w", "400", broadcast],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    out = subprocess.run(["arp", "-a"], capture_output=True).stdout
    seen = set()
    devices = []
    for m in _ARP_LINE.finditer(out):
        ip = m.group(1).decode()
        if ipaddress.ip_address(ip) not in net:  # only the target subnet
            continue
        if ip == str(net.broadcast_address):  # broadcast, not a host
            continue
        mac = _MAC_DASH.sub(":", m.group(2).decode().lower())
        if mac in seen:
            continue
        seen.add(mac)
        devices.append({"ip": ip, "mac": mac})
    return devices


def scan_network_scapy(ip_range="192.168.1.0/24"):
    """Scapy ARP broadcast scan — the classic technique. Kept for reference.

    NOTE: On this machine (MSYS2/MinGW Python + Npcap) it only ever receives
    replies from the host itself, so it is NOT used as the default sensor.
    """
    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for _sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


if __name__ == "__main__":
    for d in scan_network():
        print(d)