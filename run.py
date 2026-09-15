import threading, time
from app import create_app, config as cfg
from app.sync_devices import sync_devices
from app.capture.sniffer import start_sniffing
from app.features.extract import extract_features
from app.policy.composite import compute_composite_risk
from app.policy.scoring import risk_level
from app.baseline.model import update_baseline
from app.enforcement.quarantine import (
    quarantine_device, release_device, ENFORCEMENT_MODE,
)
from app.logging.forensic import log_forensic_event
from app.models import db, Device, Ban, RiskHistory, DNSLog, BandwidthLog
from app.enforcement.escalation import effective_ban_threshold
from app.policy.network_risk import is_blocked_domain

app = create_app()

HIGH_RISK_BAN_THRESHOLD = 70

def periodic_device_scan():
    while True:
        sync_devices(app)
        time.sleep(30)

def run_scoring_window(app):
    """One scoring pass over the current packet buffer (all devices).

    Extracted from the daemon loop so tests can drive the *real* pipeline
    (Phase 8 integration testing) without waiting on wall-clock windows.
    Returns {mac: {"total": int, "level": str, "banned": bool}}.
    """
    summary = {}
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

            # Phase 7: persist the full DNS audit trail (every domain this
            # window, not just flagged ones) + per-window byte totals.
            for domain in feats["dns_queries"]:
                db.session.add(DNSLog(
                    mac=mac,
                    domain=domain,
                    flagged=is_blocked_domain(domain),
                ))
            db.session.add(BandwidthLog(
                mac=mac,
                bytes_sent=feats["byte_count"],
            ))

            # Forensic log on risk-level transitions (LOW->MEDIUM, MEDIUM->HIGH, ...)
            if prev_level and prev_level != level:
                log_forensic_event(
                    mac, "RISK_TRANSITION",
                    f"{prev_level} -> {level} (total {total})")

            # Enforcement: cross (escalated) threshold + not already banned
            # -> quarantine. Repeat offenders have a lower effective
            # threshold (Phase 7 escalation rules).
            banned_now = False
            existing_ban = Ban.query.filter_by(mac=mac, active=True).first()
            threshold = effective_ban_threshold(HIGH_RISK_BAN_THRESHOLD, mac)
            if total >= threshold and not existing_ban:
                prior = Ban.query.filter_by(mac=mac).count()
                injected = quarantine_device(device.ip, mac,
                                             gateway_ip=cfg.GATEWAY_INTERNAL_IP)
                mode = {"iptables": "iptables DROP active",
                        "arp": "ARP spoof active",
                        "recorded": "recorded-only (test/Windows mode)"}.get(
                            ENFORCEMENT_MODE, "recorded")
                db.session.add(Ban(
                    mac=mac,
                    reason=f"Composite risk score {total} crossed "
                           f"effective threshold {threshold:.0f} "
                           f"(base {HIGH_RISK_BAN_THRESHOLD}, prior bans {prior})",
                    risk_score_at_ban=total,
                ))
                device.status = "banned"
                db.session.commit()
                banned_now = True
                log_forensic_event(
                    mac, "QUARANTINE",
                    {"total_score": total,
                     "effective_threshold": round(threshold, 2),
                     "reason": f"Composite risk score {total} classified HIGH",
                     "enforcement_mode": mode})
            else:
                db.session.commit()

            if prev_status != device.status and device.status in (
                    "banned", "unknown"):
                log_forensic_event(
                    mac, "STATUS_CHANGE",
                    f"{prev_status} -> {device.status} (total {total})")

            summary[mac] = {"total": total, "level": level, "banned": banned_now}

            print(f"{mac}: id={result['identity']} dev={result['device']} "
                  f"net={result['network']} beh={result['behavior']} "
                  f"total={total} {device.risk_level} "
                  f"flags={result['flagged_domains']} samples={baseline.sample_count}"
                  f" status={device.status}", flush=True)
    return summary


def periodic_risk_scoring():
    while True:
        time.sleep(30)
        run_scoring_window(app)

if __name__ == "__main__":
    _mode_msgs = {
        "iptables": "[enforcement] iptables DROP active (Linux, root)",
        "arp": "[enforcement] ARP spoof active",
        "recorded": "[enforcement] recorded-only mode — quarantines are "
                    "logged (DB + forensic log) but not enforced on the wire. "
                    "Run as root on Linux (ZTA_ENFORCE=iptables) to isolate.",
    }
    print(_mode_msgs.get(ENFORCEMENT_MODE, _mode_msgs["recorded"]), flush=True)
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_device_scan, daemon=True).start()
    threading.Thread(target=periodic_risk_scoring, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)