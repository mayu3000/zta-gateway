"""Identity risk: recent failed authentications originating from a device IP."""
from datetime import datetime, timedelta

from app.models import AuthEvent

WINDOW_MINUTES = 15
FAILED_LOGIN_WEIGHT = 15   # per failed attempt, capped


def compute_identity_risk(ip: str) -> int:
    if not ip:
        return 0
    cutoff = datetime.utcnow() - timedelta(minutes=WINDOW_MINUTES)
    failed = AuthEvent.query.filter(
        AuthEvent.ip == ip,
        AuthEvent.result == "Failed",
        AuthEvent.timestamp >= cutoff,
    ).count()
    return min(failed * FAILED_LOGIN_WEIGHT, 100)