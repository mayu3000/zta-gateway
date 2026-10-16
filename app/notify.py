"""Phase 10: email warnings when a device's risk level rises.

Two notices:
  * notify_medium — the device rose to MEDIUM (unusual but not yet blocked).
  * notify_ban    — the device was quarantined.

Design rules (see EMAIL_WARNING_PLAN.md):
  * Scoring must never fail or slow down because of email — the actual send
    runs in a daemon thread and every error is caught.
  * No secrets, tokens or full DNS history in a message. One plain sentence.
  * The recipient is the signed-in user's email, else an admin-set contact.
"""
import threading
import logging
from datetime import datetime, timedelta

from app import config as cfg
from app.logging.forensic import log_forensic_event

log = logging.getLogger("zta.notify")

# India Standard Time = UTC+05:30 (the deployment timezone).
IST = timedelta(hours=5, minutes=30)


def _now_ist():
    return (datetime.utcnow() + IST).strftime("%Y-%m-%d %H:%M IST")


def _device_label(device):
    """Human label: hostname if known, else the last 6 hex chars of the MAC."""
    if device.hostname:
        return device.hostname
    return f"device ...{device.mac.replace(':', '')[-6:]}"


def resolve_recipient(device):
    """Who gets the email: signed-in user's address, else the admin contact."""
    from app.models import User, db
    if device.user_id:
        user = db.session.get(User, device.user_id)
        if user and user.email:
            return user.email
    if device.notify_email:
        return device.notify_email
    return None


def describe_reason(result):
    """Turn the scoring result into one plain sentence (no raw domains)."""
    flagged = result.get("flagged_domains") or []
    if flagged:
        return "repeated visits to websites on the gateway's blocklist"

    candidates = [
        (result.get("behavior", 0),
         "a sudden burst of connection attempts in a short time"),
        (result.get("identity", 0),
         "repeated failed sign-in attempts"),
        (result.get("network", 0),
         "contacts with addresses the gateway considers suspicious"),
        (result.get("device", 0),
         "a device the gateway does not recognise"),
    ]
    score, text = max(candidates, key=lambda c: c[0])
    if score <= 0:
        return "an unusual pattern of network activity"
    return text


def _in_cooldown(mac):
    """True if a medium_warning was sent for this MAC within the cooldown."""
    from app.models import Notification
    cutoff = datetime.utcnow() - timedelta(minutes=cfg.NOTIFY_COOLDOWN_MINUTES)
    return Notification.query.filter(
        Notification.mac == mac,
        Notification.kind == "medium_warning",
        Notification.created_at >= cutoff,
    ).first() is not None


def _record(mac, recipient, kind, score, reason, status, error=None,
            commit=True):
    """Write a Notification audit row."""
    from app.models import db, Notification
    db.session.add(Notification(
        mac=mac, recipient=recipient, kind=kind, score=score,
        reason=reason, status=status, error=error,
    ))
    if commit:
        db.session.commit()


def _recipients_for(recipient):
    """Primary recipient plus the configured admin copy (if any)."""
    recipients = [recipient]
    if cfg.NOTIFY_ADMIN_COPY and cfg.NOTIFY_ADMIN_COPY != recipient:
        recipients.append(cfg.NOTIFY_ADMIN_COPY)
    return recipients


def _spawn_send(app, mac, recipient, kind, score, reason, subject,
                body_text, body_html):
    """Send the email in a daemon thread; record sent/failed afterwards."""
    recipients = _recipients_for(recipient)

    def _worker():
        with app.app_context():
            from app.mail import send_risk_email
            status, error = "sent", None
            try:
                for addr in recipients:
                    send_risk_email(app, addr, subject, body_text, body_html)
            except Exception as exc:  # noqa: BLE001 — never break scoring
                status, error = "failed", str(exc)[:300]
                log_forensic_event(mac, "NOTIFY_FAILED", {
                    "kind": kind, "to": recipient, "error": error})
            try:
                _record(mac, recipient, kind, score, reason, status, error)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not write Notification row: %s", exc)

    threading.Thread(target=_worker, daemon=True).start()


def _medium_body(device, reason):
    return (
        f"Security notice: unusual activity on your device\n\n"
        f"Device: {_device_label(device)}\n"
        f"Time: {_now_ist()}\n"
        f"Risk level: MEDIUM\n\n"
        f"The gateway observed {reason}.\n\n"
        f"If this activity continues and the level reaches HIGH, the device "
        f"will be blocked from the network.\n"
        f"If you did not expect this, contact the network administrator."
    )


def _ban_body(device, reason):
    return (
        f"Your device has been blocked\n\n"
        f"Device: {_device_label(device)}\n"
        f"Time: {_now_ist()}\n"
        f"Risk level: HIGH\n\n"
        f"The gateway observed {reason}.\n\n"
        f"The device has been blocked from the network to protect it and the "
        f"other devices.\n"
        f"To appeal, contact the network administrator, who can release the "
        f"device; you will then need to sign in again."
    )


def notify_medium(app, device, total, result):
    """Warn the owner that the device reached MEDIUM risk."""
    if not cfg.NOTIFY:
        return

    reason = describe_reason(result)
    recipient = resolve_recipient(device)
    if not recipient:
        _record(device.mac, None, "medium_warning", total, reason, "skipped",
                error="no recipient configured")
        log_forensic_event(device.mac, "NOTIFY_SKIPPED",
                           {"kind": "medium_warning", "reason": "no recipient"})
        return

    if _in_cooldown(device.mac):
        return

    _spawn_send(
        app, device.mac, recipient, "medium_warning", total, reason,
        "Security notice: unusual activity on your device",
        _medium_body(device, reason), None)


def notify_ban(app, device, total, reason):
    """Tell the owner the device was blocked."""
    if not cfg.NOTIFY or not cfg.NOTIFY_BAN_NOTICE:
        return

    recipient = resolve_recipient(device)
    if not recipient:
        _record(device.mac, None, "ban_notice", total, reason, "skipped",
                error="no recipient configured")
        log_forensic_event(device.mac, "NOTIFY_SKIPPED",
                           {"kind": "ban_notice", "reason": "no recipient"})
        return

    _spawn_send(
        app, device.mac, recipient, "ban_notice", total, reason,
        "Your device has been blocked",
        _ban_body(device, reason), None)
