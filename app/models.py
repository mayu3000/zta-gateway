from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), unique=True, nullable=False)
    ip = db.Column(db.String(20))
    hostname = db.Column(db.String(120))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="unknown")  # unknown/approved/banned
    risk_score = db.Column(db.Integer, default=0)          # 0-100
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