"""Threat Traceback — reconstruct a device's escalation from queryable history.

RiskHistory already holds one row per device per 30s scoring window (identity /
device / network / behavior / total + flagged domains), and Ban holds the final
action. Traceback just queries and presents that raw material coherently — no
new capture.
"""
from app.models import RiskHistory, Ban

FIRST_ANOMALY_RISK = 35   # first index where the score reached MEDIUM+


def reconstruct_timeline(mac, limit=None):
    history = (RiskHistory.query
               .filter_by(mac=mac)
               .order_by(RiskHistory.timestamp.asc())
               .all())
    ban = (Ban.query
           .filter_by(mac=mac)
           .order_by(Ban.since.desc())
           .first())

    if not history:
        return {"mac": mac, "timeline": [], "summary": "No history available"}

    if limit:
        history = history[-limit:]

    first_anomaly = next(
        (h for h in history if (h.total_risk or 0) >= FIRST_ANOMALY_RISK),
        None)

    timeline = [{
        "timestamp": h.timestamp.isoformat(),
        "total_risk": h.total_risk,
        "identity": h.identity_risk,
        "device": h.device_risk,
        "network": h.network_risk,
        "behavior": h.behavior_risk,
        "flagged_domains": h.flagged_domains,
    } for h in history]

    return {
        "mac": mac,
        "first_seen_anomaly": (first_anomaly.timestamp.isoformat()
                               if first_anomaly else None),
        "escalation_path": [h.total_risk for h in history],
        "final_action": (f"Banned at {ban.since.isoformat()} — {ban.reason}"
                         if ban else "No ban recorded"),
        "timeline": timeline,
    }