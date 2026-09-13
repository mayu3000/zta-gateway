"""Passive traffic sniffer (listen-only, reliable on Windows/Npcap).

Unlike Phase 1's *active* ARP scan — which can't receive other hosts' replies
on this MinGW/Npcap stack — passive sniffing only listens, which Npcap handles
cleanly. The picked interface auto-matches the adapter whose IP sits on the
LAN subnet.
"""
import ipaddress
from datetime import datetime

from scapy.all import sniff, IP, Ether, TCP, UDP, DNSQR, get_if_list, get_if_addr, conf

from app.capture.buffer import packet_queue, queue_lock


def _pick_interface(subnet="192.168.1.0/24"):
    """Return the interface whose IP is on subnet, else Scapy's default."""
    net = ipaddress.ip_network(subnet, strict=False)
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        if ip and ip != "0.0.0.0" and ipaddress.ip_address(ip) in net:
            return iface
    return conf.iface


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


def start_sniffing(iface=None, subnet="192.168.1.0/24"):
    if iface is None:
        iface = _pick_interface(subnet)
    print(f"[sniffer] listening on {iface}", flush=True)
    sniff(iface=iface, prn=handle_packet, store=False, filter="ip")