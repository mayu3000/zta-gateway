"""Phase 7 escalation: repeat offenders are banned at a lower threshold.

Zero-trust corollary — an unban resets a device's *state* to unknown, but
the network does not forget that it misbehaved before. The effective ban
threshold drops with each prior ban, so a repeat offender is judged more
harshly than a first-time one.
"""


def get_escalation_multiplier(mac, ban_count=None) -> float:
    """Return the threshold multiplier for a MAC based on prior bans.

    prior bans: 0 -> 1.00, 1 -> 0.75, 2+ -> 0.50
    """
    if ban_count is None:
        from app.models import Ban
        ban_count = Ban.query.filter_by(mac=mac).count()
    if ban_count >= 2:
        return 0.5
    if ban_count == 1:
        return 0.75
    return 1.0


def effective_ban_threshold(base_threshold: int, mac: str) -> float:
    """Base threshold adjusted by prior-ban history for `mac`."""
    return base_threshold * get_escalation_multiplier(mac)