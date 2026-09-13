"""Z-score anomaly scoring against each device's own learned baseline.

Replaces Phase 2's fixed global thresholds: a window is risky when it deviates
from *this device's* normal (in std devs), not when it crosses a global number.
Until a device has learned its baseline it gets a low, non-punitive score so a
brand-new legitimate device is never quarantined on day one.
"""
from app.baseline.model import get_std
from app.baseline.config import Z_SCORE_MEDIUM, Z_SCORE_HIGH

FEATURE_WEIGHTS = {
    "packet_count": 20,
    "byte_count": 20,
    "unique_flow_count": 40,   # weighted highest — the scan/C2 fan-out signal
    "dns_query_count": 20,
}


def z_score(value, mean, std):
    if std == 0:
        return 0.0
    return abs(value - mean) / std


def compute_risk_score(features: dict, baseline) -> tuple[int, dict]:
    """Return (score 0-100, per-feature z-score detail)."""
    if not baseline or not baseline.learning_complete:
        return 5, {"status": "learning"}

    field_map = {
        "packet_count": (baseline.packet_count_mean, baseline.packet_count_m2),
        "byte_count": (baseline.byte_count_mean, baseline.byte_count_m2),
        "unique_flow_count": (baseline.unique_flow_mean, baseline.unique_flow_m2),
        "dns_query_count": (baseline.dns_query_mean, baseline.dns_query_m2),
    }

    scores = {}
    total = 0
    for key, weight in FEATURE_WEIGHTS.items():
        mean, m2 = field_map[key]
        std = get_std(m2, baseline.sample_count)
        z = z_score(features.get(key, 0), mean, std)
        # normalize: z >= Z_SCORE_HIGH contributes full weight
        contribution = min(z / Z_SCORE_HIGH, 1.0) * weight
        scores[key] = round(z, 2)
        total += contribution

    return min(int(total), 100), scores


def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"