"""Fixed thresholds for Phase 2 (upgraded to adaptive baselines in Phase 3).

Tuned against observed "normal" behavior on this network (~1100 packets,
~100 flows, ~25 dst IPs per 30s of browsing). A port scan produces ~1000
unique dst ip:port flows in a burst — the clearest scan signal.
"""

THRESHOLDS = {
    "packet_count": 2500,       # packets per 30s window (normal browsing ~1.1k)
    "byte_count": 5_000_000,    # ~5MB per 30s
    "unique_dst_count": 40,     # distinct dst IPs per 30s (browsing ~25)
    "unique_flow_count": 200,   # distinct dst ip:port pairs per 30s (scan ~1000)
    "dns_query_count": 15,      # distinct DNS lookups per 30s
}