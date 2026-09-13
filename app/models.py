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
