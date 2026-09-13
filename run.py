import threading, time
from app import create_app
from app.sync_devices import sync_devices
from app.capture.sniffer import start_sniffing
from app.features.extract import extract_features
from app.policy.scoring import compute_risk_score, risk_level
from app.baseline.model import update_baseline
from app.models import db, Device

app = create_app()

def periodic_device_scan():
    while True:
        sync_devices(app)
        time.sleep(30)

def periodic_risk_scoring():
    while True:
        time.sleep(30)
        with app.app_context():
            features = extract_features()
            for mac, feats in features.items():
                baseline = update_baseline(mac, feats)   # learn from this window
                score, detail = compute_risk_score(feats, baseline)
                level = risk_level(score)

                device = Device.query.filter_by(mac=mac).first()
                if device:
                    device.risk_score = score
                    device.risk_level = level
                    db.session.commit()

                print(f"{mac}: score={score} level={level} "
                      f"samples={baseline.sample_count} detail={detail}", flush=True)

if __name__ == "__main__":
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_device_scan, daemon=True).start()
    threading.Thread(target=periodic_risk_scoring, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)