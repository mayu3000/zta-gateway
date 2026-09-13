"""Basic risk scoring engine: weighted feature ratios vs fixed thresholds.

Flow fan-out is weighted highest — a burst of unique dst ip:port pairs is the
classic port-scan / C2 beaconing signal, while volume/dst/DNS contribute
context. A capped ratio keeps any single metric from dominating past 2x.
"""
from app.baseline.thresholds import THRESHOLDS

WEIGHTS = {
    "packet_count": 10,
    "byte_count": 10,
    "unique_dst_count": 15,
    "unique_flow_count": 35,    # scan/C2 signal — weighted highest
    "dns_query_count": 20,
}


def compute_risk_score(features: dict) -> int:
    score = 0
    for key, weight in WEIGHTS.items():
        value = features.get(key, 0)
        limit = THRESHOLDS[key]
        if limit == 0:
            continue
        ratio = min(value / limit, 2.0)   # cap so one metric can't dominate past 2x
        score += weight * ratio
    return min(int(score), 100)


def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"