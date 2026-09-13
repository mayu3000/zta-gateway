import threading, time
from app import create_app
from app.sync_devices import sync_devices
from app.capture.sniffer import start_sniffing
from app.features.extract import extract_features
from app.policy.composite import compute_composite_risk
from app.policy.scoring import risk_level
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
                device = Device.query.filter_by(mac=mac).first()
                if not device:
                    continue

                result = compute_composite_risk(
                    device, feats, baseline,
                    feats["dns_queries"], feats["dst_ports"],
                )
                device.identity_risk = result["identity"]
                device.device_risk = result["device"]
                device.network_risk = result["network"]
                device.behavior_risk = result["behavior"]
                device.total_risk = result["total"]
                device.risk_score = result["total"]            # legacy alias
                device.risk_level = risk_level(result["total"])
                device.flagged_domains = ",".join(result["flagged_domains"])
                device.fan_out = result["fan_out"]
                db.session.commit()

                print(f"{mac}: id={result['identity']} dev={result['device']} "
                      f"net={result['network']} beh={result['behavior']} "
                      f"total={result['total']} {device.risk_level} "
                      f"flags={result['flagged_domains']} samples={baseline.sample_count}", flush=True)

if __name__ == "__main__":
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_device_scan, daemon=True).start()
    threading.Thread(target=periodic_risk_scoring, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)