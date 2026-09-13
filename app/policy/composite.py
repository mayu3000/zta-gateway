"""Composite risk engine combining Identity + Device + Network + Behavior.

Maps 1:1 to the review-design gap: papers typically covered one dimension each;
this combines all four into one lightweight weighted score, with Behavior (the
most mature signal, Phase 3) weighted highest.
"""
from app.policy.identity_risk import compute_identity_risk
from app.policy.device_risk import compute_device_risk
from app.policy.network_risk import compute_network_risk
from app.policy.scoring import compute_risk_score as compute_behavior_risk

WEIGHTS = {
    "identity": 0.20,
    "device":   0.20,
    "network":  0.25,
    "behavior": 0.35,   # keep behavior weighted highest — it's your most mature signal
}


def compute_composite_risk(device, features, baseline, dns_queries, dst_ports):
    identity = compute_identity_risk(device.ip)
    dev_risk = compute_device_risk(device)
    net_risk, flagged_domains = compute_network_risk(dns_queries, dst_ports)
    behavior, _detail = compute_behavior_risk(features, baseline)

    total = (
        identity * WEIGHTS["identity"] +
        dev_risk * WEIGHTS["device"] +
        net_risk * WEIGHTS["network"] +
        behavior * WEIGHTS["behavior"]
    )

    return {
        "identity": identity,
        "device": dev_risk,
        "network": net_risk,
        "behavior": behavior,
        "total": min(int(total), 100),
        "flagged_domains": flagged_domains,
        "fan_out": features.get("unique_flow_count", 0),
    }