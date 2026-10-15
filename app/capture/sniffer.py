"""Passive traffic sniffer (listen-only, reliable on Windows/Npcap).

Unlike Phase 1's *active* ARP scan — which can't receive other hosts' replies
on this MinGW/Npcap stack — passive sniffing only listens, which Npcap handles
cleanly. The picked interface auto-matches the adapter whose IP sits on the
LAN subnet (configurable via app/config.py; eth1 on the Kali inline gateway).
"""
import ipaddress
from datetime import datetime

from scapy.all import sniff, IP, Ether, TCP, UDP, DNSQR, get_if_list, get_if_addr, conf

from app import config as cfg
from app.capture.buffer import packet_queue, queue_lock


def _pick_interface(subnet=cfg.INTERNAL_SUBNET):
    """Return the interface whose IP is on subnet.

    Falls back to the first non-loopback interface (keeps accidental Windows
    local runs working when the configured subnet matches none), then
    Scapy's default.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    fallback = None
    # Prefer the configured internal interface (eth1 or the Wi-Fi AP wlan0)
    # when it exists and already holds an address on the internal subnet.
    if cfg.INTERNAL_IFACE in get_if_list():
        try:
            if ipaddress.ip_address(get_if_addr(cfg.INTERNAL_IFACE)) in net:
                return cfg.INTERNAL_IFACE
        except Exception:
            pass
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        if not ip or ip == "0.0.0.0":
            continue
        if fallback is None and not ip.startswith("127."):
            fallback = iface
        if ipaddress.ip_address(ip) in net:
            return iface
    return fallback or conf.iface


def handle_packet(pkt):
    if IP not in pkt:
        return

    record = {
        "timestamp": datetime.utcnow(),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "proto": pkt[IP].proto,   # 6=TCP, 17=UDP, 1=ICMP
        "size": len(pkt),
        "dns_query": None,
        "src_mac": None,
        "dst_port": None,         # TCP/UDP dest port for flow fan-out
    }
    if TCP in pkt:
        record["dst_port"] = pkt[TCP].dport
    elif UDP in pkt:
        record["dst_port"] = pkt[UDP].dport
    if Ether in pkt:
        record["src_mac"] = pkt[Ether].src
    if pkt.haslayer(DNSQR):
        record["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore")

    with queue_lock:
        packet_queue.append(record)


def start_sniffing(iface=None, subnet=cfg.INTERNAL_SUBNET):
    if iface is None:
        iface = _pick_interface(subnet)
    print(f"[sniffer] listening on {iface}", flush=True)
    sniff(iface=iface, prn=handle_packet, store=False, filter="ip")