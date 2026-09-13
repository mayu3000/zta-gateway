"""Device risk: zero-trust default — unapproved / newly-seen devices score higher."""
from datetime import datetime, timedelta

NEW_DEVICE_HOURS = 24        # devices younger than this are inherently riskier
UNKNOWN_STATUS_SCORE = 60
NEW_DEVICE_SCORE = 30
KNOWN_DEVICE_SCORE = 0


def compute_device_risk(device) -> int:
    if device.status == "unknown":
        return UNKNOWN_STATUS_SCORE
    if device.status == "banned":
        return 100
    age = datetime.utcnow() - device.first_seen
    if age < timedelta(hours=NEW_DEVICE_HOURS):
        return NEW_DEVICE_SCORE
    return KNOWN_DEVICE_SCORE