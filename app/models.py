from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    # Phase 6: registration workflow — pending until an admin approves.
    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    # Phase 7: email verification (login also requires email_verified).
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(64), unique=True, nullable=True)


class AuthEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip = db.Column(db.String(20))
    result = db.Column(db.String(10))   # "Success" / "Failed"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), unique=True, nullable=False)
    ip = db.Column(db.String(20))
    hostname = db.Column(db.String(120))
    user = db.Column(db.String(80))     # identity mapped to this device (usually unresolved)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="unknown")  # unknown/approved/banned
    # Portal gate: link to the user who signed in on this device.
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    granted_at = db.Column(db.DateTime, nullable=True)

    # Phase 4 composite risk sub-scores (0-100)
    identity_risk = db.Column(db.Integer, default=0)
    device_risk = db.Column(db.Integer, default=0)
    network_risk = db.Column(db.Integer, default=0)
    behavior_risk = db.Column(db.Integer, default=0)
    total_risk = db.Column(db.Integer, default=0)
    flagged_domains = db.Column(db.String(500), default="")   # comma-joined
    fan_out = db.Column(db.Integer, default=0)

    risk_score = db.Column(db.Integer, default=0)          # legacy alias of total_risk
    risk_level = db.Column(db.String(10), default="LOW")   # LOW/MEDIUM/HIGH

    baseline = db.relationship(
        "DeviceBaseline",
        uselist=False,
        primaryjoin="Device.mac == DeviceBaseline.mac",
        foreign_keys="DeviceBaseline.mac",
    )


class DeviceBaseline(db.Model):
    """Per-device learned "normal" (Welford online mean/variance, no raw history)."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), db.ForeignKey("device.mac"), unique=True)

    # running statistics (Welford's online algorithm)
    sample_count = db.Column(db.Integer, default=0)

    packet_count_mean = db.Column(db.Float, default=0.0)
    packet_count_m2 = db.Column(db.Float, default=0.0)     # for variance

    byte_count_mean = db.Column(db.Float, default=0.0)
    byte_count_m2 = db.Column(db.Float, default=0.0)

    unique_flow_mean = db.Column(db.Float, default=0.0)
    unique_flow_m2 = db.Column(db.Float, default=0.0)

    dns_query_mean = db.Column(db.Float, default=0.0)
    dns_query_m2 = db.Column(db.Float, default=0.0)

    learning_complete = db.Column(db.Boolean, default=False)


class Ban(db.Model):
    """Active/past quarantines (Fig.6 "Active bans" table)."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), db.ForeignKey("device.mac"))
    reason = db.Column(db.String(200))
    risk_score_at_ban = db.Column(db.Integer)
    since = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    unbanned_at = db.Column(db.DateTime, nullable=True)


class RiskHistory(db.Model):
    """One row per device per 30s scoring window — the traceback audit trail."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    identity_risk = db.Column(db.Integer)
    device_risk = db.Column(db.Integer)
    network_risk = db.Column(db.Integer)
    behavior_risk = db.Column(db.Integer)
    total_risk = db.Column(db.Integer)
    flagged_domains = db.Column(db.String(500))


class DNSLog(db.Model):
    """Phase 7: full DNS audit trail — every domain a device queries per window."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20))
    domain = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    flagged = db.Column(db.Boolean, default=False)


class BandwidthLog(db.Model):
    """Phase 7: per-device byte totals per 30s window (daily/hourly rollups
    are derivable from this)."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20))
    window_start = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_sent = db.Column(db.Integer, default=0)
    bytes_received = db.Column(db.Integer, default=0)


class PortalSession(db.Model):
    """Phase 9 portal gate: one row per device sign-in session."""
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), db.ForeignKey("device.mac"))
    username = db.Column(db.String(80))
    state = db.Column(db.String(20), default="granted")  # granted/expired/revoked
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)