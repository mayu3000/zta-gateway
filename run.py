"""ZTA Gateway daemon entry point.

Heavy imports are deferred so that `from run import run_scoring_window`
(used by tests) does not trigger full Flask app initialization — which
overflows MSYS2/MinGW Python's small C stack when combined with the
portal-gate models.
"""
import threading
import time
from datetime import datetime, timedelta

# Lazy app instance: created in main() or by tests that import run_scoring_window.
app = None


def _get_app():
    """Get or create the Flask app singleton."""
    global app
    if app is None:
        from app import create_app
        app = create_app()
    return app


HIGH_RISK_BAN_THRESHOLD = 70


def periodic_device_scan():
    from app.sync_devices import sync_devices
    while True:
        sync_devices(_get_app())
        time.sleep(30)


def run_scoring_window(app):
    """One scoring pass over the current packet buffer (all devices).

    Extracted from the daemon loop so tests can drive the *real* pipeline
    (Phase 8 integration testing) without waiting on wall-clock windows.
    Returns {mac: {"total": int, "level": str, "banned": bool}}.
    """
    from app.features.extract import extract_features
    from app.baseline.model import update_baseline
    from app.policy.composite import compute_composite_risk
    from app.policy.scoring import risk_level
    from app.policy.network_risk import is_blocked_domain
    from app.enforcement.escalation import effective_ban_threshold
    from app.enforcement.quarantine import quarantine_device, ENFORCEMENT_MODE
    from app.logging.forensic import log_forensic_event
    from app import config as cfg
    from app.notify import notify_medium, notify_ban
    from app.models import (db, Device, Ban, RiskHistory, DNSLog,
                           BandwidthLog)

    summary = {}
    with app.app_context():
        features = extract_features()
        for mac, feats in features.items():
            baseline = update_baseline(mac, feats)
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

            # Phase 10: count consecutive MEDIUM windows (ZTA_NOTIFY_MIN_WINDOWS).
            if level == "MEDIUM":
                device.medium_streak = (device.medium_streak or 0) + 1
            else:
                device.medium_streak = 0

            device.identity_risk = result["identity"]
            device.device_risk = result["device"]
            device.network_risk = result["network"]
            device.behavior_risk = result["behavior"]
            device.total_risk = total
            device.risk_score = total
            device.risk_level = level
            device.flagged_domains = ",".join(result["flagged_domains"])
            device.fan_out = result["fan_out"]

            db.session.add(RiskHistory(
                mac=mac,
                identity_risk=result["identity"],
                device_risk=result["device"],
                network_risk=result["network"],
                behavior_risk=result["behavior"],
                total_risk=total,
                flagged_domains=device.flagged_domains,
            ))

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

            if prev_level and prev_level != level:
                log_forensic_event(
                    mac, "RISK_TRANSITION",
                    f"{prev_level} -> {level} (total {total})")

            # Phase 10: decide whether to warn the owner on rising into MEDIUM.
            # A device that jumps straight to HIGH (skipping MEDIUM) gets only
            # the ban notice. A device first seen already at MEDIUM/HIGH has no
            # previous level and therefore gets no medium warning (documented).
            warn_medium = (
                level == "MEDIUM" and prev_level in ("LOW", "MEDIUM")
                and (device.medium_streak or 0) >= cfg.NOTIFY_MIN_WINDOWS)

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
                # Phase 10: ban notice to the owner (background, best-effort).
                notify_ban(app, device, total,
                           "activity classified as HIGH risk "
                           "(connection attempts and/or blocklisted sites)")
            else:
                db.session.commit()

            # Phase 10: send the medium warning only AFTER the scoring
            # transaction is committed, so the background send never races the
            # window's writes (matters for SQLite's file lock).
            if warn_medium:
                notify_medium(app, device, total, result)

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
        run_scoring_window(_get_app())


def periodic_session_expiry():
    """Revoke sessions idle past the TTL (every 30s)."""
    while True:
        time.sleep(30)
        with _get_app().app_context():
            from app.models import PortalSession
            from app.enforcement.portal import revoke_access
            now = datetime.utcnow()
            expired = PortalSession.query.filter(
                PortalSession.state == "granted",
                PortalSession.expires_at < now,
            ).all()
            for ps in expired:
                ps.state = "expired"
                revoke_access(ps.mac)
            if expired:
                db.session.commit()
                print(f"[portal] expired {len(expired)} idle session(s)", flush=True)


def periodic_connected_check():
    """Revoke sessions for devices that left the network."""
    while True:
        time.sleep(60)
        with _get_app().app_context():
            from app import config as cfg
            from app.models import PortalSession, Device
            from app.enforcement.portal import revoke_access
            from app.models import db
            cutoff = datetime.utcnow() - timedelta(
                seconds=cfg.CONNECTED_TTL_SECONDS)
            stale = PortalSession.query.filter(
                PortalSession.state == "granted",
            ).join(Device, PortalSession.mac == Device.mac).filter(
                Device.last_seen < cutoff,
            ).all()
            for ps in stale:
                ps.state = "revoked"
                revoke_access(ps.mac)
            if stale:
                db.session.commit()
                print(f"[portal] revoked {len(stale)} stale session(s)", flush=True)


if __name__ == "__main__":
    from app.enforcement.quarantine import ENFORCEMENT_MODE
    from app.capture.sniffer import start_sniffing
    from app import config as cfg

    _mode_msgs = {
        "iptables": "[enforcement] iptables DROP active (Linux, root)",
        "arp": "[enforcement] ARP spoof active",
        "recorded": "[enforcement] recorded-only mode — quarantines are "
                    "logged (DB + forensic log) but not enforced on the wire. "
                    "Run as root on Linux (ZTA_ENFORCE=iptables) to isolate.",
    }
    print(_mode_msgs.get(ENFORCEMENT_MODE, _mode_msgs["recorded"]), flush=True)
    _app = _get_app()
    from app.mail import mail_mode
    print(f"[mail] {mail_mode(_app)}", flush=True)
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=periodic_device_scan, daemon=True).start()
    threading.Thread(target=periodic_risk_scoring, daemon=True).start()

    # --- Portal gate startup reconciliation ---
    if cfg.PORTAL_GATE:
        from app.enforcement.portal import setup_gate, restore_from_db

        setup_gate()
        bans_restored, sessions_restored = restore_from_db(_app)

        from app.portal_redirect import start_portal_listener
        start_portal_listener()
        print(f"[portal] gate ON, interfaces: "
              f"{','.join(cfg.INTERNAL_IFACES)}", flush=True)
        print(f"[portal] restored {bans_restored} ban(s), "
              f"{sessions_restored} active session(s) "
              f"(DNS intercept: "
              f"{'on' if cfg.DNS_INTERCEPT else 'off'})", flush=True)

        threading.Thread(target=periodic_session_expiry, daemon=True).start()
        threading.Thread(target=periodic_connected_check, daemon=True).start()

    _app.run(host="0.0.0.0", port=5000)
