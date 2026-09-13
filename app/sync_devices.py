from app.discovery import scan_network
from app.models import db, Device
from datetime import datetime

def sync_devices(app):
    with app.app_context():
        found = scan_network()
        for d in found:
            device = Device.query.filter_by(mac=d["mac"]).first()
            if device:
                device.ip = d["ip"]
                device.last_seen = datetime.utcnow()
            else:
                device = Device(mac=d["mac"], ip=d["ip"], status="unknown")
                db.session.add(device)
        db.session.commit()
