"""Forensic / incident logging.

Every meaningful decision point (risk-level transition, quarantine, unban)
appends one JSON line to logs/forensic.log. The file itself becomes a readable
incident timeline independent of the DB.
"""
import json
import os
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "logs", "forensic.log")


def log_forensic_event(mac, action, detail):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "mac": mac,
        "action": action,
        "detail": detail,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")