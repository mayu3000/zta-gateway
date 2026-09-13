"""Summarize each device's recent traffic into a per-MAC feature vector.

This is the "behavioral analysis" core: for every 30s window it aggregates
volume (packets/bytes), fan-out (distinct destinations), DNS activity and
protocol mix per device — the UEBA-style features from the design.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from app.capture.buffer import packet_queue, queue_lock
from app.capture.resolve import get_mac_for_ip

WINDOW_SECONDS = 30


def extract_features(window_seconds=WINDOW_SECONDS):
    """Return {mac: {feature_name: value}} for the last `window_seconds`."""
    with queue_lock:
        recent_packets = list(packet_queue)
    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
    recent = [p for p in recent_packets if p["timestamp"] >= cutoff]

    per_device = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "unique_dst_ips": set(),
        "unique_flows": set(),   # (dst_ip, dst_port) — the scan/C2 fan-out signal
        "dns_queries": set(),
        "tcp_count": 0,
        "udp_count": 0,
    })

    for p in recent:
        mac = get_mac_for_ip(p["src_ip"]) or p.get("src_mac")
        if not mac:
            continue
        d = per_device[mac]
        d["packet_count"] += 1
        d["byte_count"] += p["size"]
        d["unique_dst_ips"].add(p["dst_ip"])
        if p["dst_port"] is not None:
            d["unique_flows"].add((p["dst_ip"], p["dst_port"]))
        if p["dns_query"]:
            d["dns_queries"].add(p["dns_query"])
        if p["proto"] == 6:
            d["tcp_count"] += 1
        elif p["proto"] == 17:
            d["udp_count"] += 1

    # convert sets to counts for storage/scoring
    result = {}
    for mac, d in per_device.items():
        result[mac] = {
            "packet_count": d["packet_count"],
            "byte_count": d["byte_count"],
            "unique_dst_count": len(d["unique_dst_ips"]),
            "unique_flow_count": len(d["unique_flows"]),
            "dns_query_count": len(d["dns_queries"]),
            "tcp_ratio": d["tcp_count"] / max(d["packet_count"], 1),
        }
    return result