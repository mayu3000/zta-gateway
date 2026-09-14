import threading, time
from app import create_app
from app.sync_devices import sync_devices
from app.capture.sniffer import start_sniffing
from app.features.extract import extract_features
from app.policy.composite import compute_composite_risk
from app.policy.scoring import risk_level
from app.baseline.model import update_baseline
from app.enforcement.quarantine import (
    quarantine_device, release_device, INJECTION_AVAILABLE,
)
from app.logging.forensic import log_forensic_event
from app.models import db, Device, Ban, RiskHistory

app = create_app()

HIGH_RISK_BAN_THRESHOLD = 70

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
                total = result["total"]
                level = risk_level(total)
                prev_level = device.risk_level
                prev_status = device.status

                device.identity_risk = result["identity"]
                device.device_risk = result["device"]
                device.network_risk = result["network"]
                device.behavior_risk = result["behavior"]
                device.total_risk = total
                device.risk_score = total                  # legacy alias
                device.risk_level = level
                device.flagged_domains = ",".join(result["flagged_domains"])
                device.fan_out = result["fan_out"]

                # Audit trail row (traceback raw material)
                db.session.add(RiskHistory(
                    mac=mac,
                    identity_risk=result["identity"],
                    device_risk=result["device"],
                    network_risk=result["network"],
                    behavior_risk=result["behavior"],
                    total_risk=total,
                    flagged_domains=device.flagged_domains,
                ))

                # Forensic log on risk-level transitions (LOW->MEDIUM, MEDIUM->HIGH, ...)
                if prev_level and prev_level != level:
                    log_forensic_event(
                        mac, "RISK_TRANSITION",
                        f"{prev_level} -> {level} (total {total})")

                # Enforcement: cross HIGH threshold + not already banned -> quarantine
                existing_ban = Ban.query.filter_by(mac=mac, active=True).first()
                if total >= HIGH_RISK_BAN_THRESHOLD and not existing_ban:
                    injected = quarantine_device(device.ip, mac)
                    mode = "ARP spoof active" if injected else \
                        "recorded-only (Windows injection unavailable)"
                    db.session.add(Ban(
                        mac=mac,
                        reason=f"Composite risk score {total} classified HIGH",
                        risk_score_at_ban=total,
                    ))
                    device.status = "banned"
                    db.session.commit()
                    log_forensic_event(
                        mac, "QUARANTINE",
                        {"total_score": total,
                         "reason": f"Composite risk score {total} classified HIGH",
                         "enforcement_mode": mode})
                else:
                    db.session.commit()

                if prev_status != device.status and device.status in (
                        "banned", "unknown"):
                    log_forensic_event(
                        mac, "STATUS_CHANGE",
                        f"{prev_status} -> {device.status} (total {total})")

                print(f"{mac}: id={result['identity']} dev={result['device']} "
                      f"net={result['network']} beh={result['behavior']} "
                      f"total={total} {device.risk_level} "
                      f"flags={result['flagged_domains']} samples={baseline.sample_count}"
                      f" status={device.status}", flush=True)

if __name__ == "__main__":
    if not INJECTION_AVAILABLE:
        print("[enforcement] ARP injection unavailable on Windows/MinGW — "
              "quarantines will be recorded (DB + forensic log), not spoofed "
              "on the wire. True isolation validated on Linux/VM.")
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_device_scan, daemon=True).start()
    threading.Thread(target=periodic_risk_scoring, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)