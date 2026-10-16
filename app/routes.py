import json
import re
import secrets
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, session,
                   url_for, flash, current_app, jsonify)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from . import config as cfg
from .models import User, Device, AuthEvent, Ban, PortalSession, Notification, db
from .enforcement.quarantine import release_device
from .enforcement.portal import grant_access, revoke_access as portal_revoke_access
from .capture.resolve import get_mac_for_ip
from .logging.forensic import log_forensic_event, LOG_PATH
from .traceback.tracer import reconstruct_timeline
from .mail import send_verification_email

main = Blueprint("main", __name__)

# Simple address check for the admin-set device contact (Phase 10).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --- auth guards -----------------------------------------------------------

def _current_user():
    username = session.get("user")
    if not username:
        return None
    return User.query.filter_by(username=username).first()


def admin_required(f):
    """Phase 7 hardening: every /admin route must belong to an admin user.

    Closes the Phase 6 gap where any logged-in user could hit pending-approval
    / unban / traceback endpoints.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user:
            return redirect(url_for("main.login"))
        if not user.is_admin:
            return "Forbidden — admin access required.", 403
        return f(*args, **kwargs)
    return wrapper


# --- auth flow -------------------------------------------------------------

@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        success = bool(user) and check_password_hash(
            user.password_hash, request.form["password"])
        db.session.add(AuthEvent(
            username=request.form["username"],
            ip=request.remote_addr,
            result="Success" if success else "Failed",
        ))
        db.session.commit()
        if not success:
            return "Invalid credentials", 401
        if not user.email_verified:
            return "Please verify your email first.", 403
        if user.status != "approved":
            return "Your account is pending admin approval.", 403
        session["user"] = user.username

        # Portal gate: resolve MAC and grant network access.
        if cfg.PORTAL_GATE and request.remote_addr != "127.0.0.1":
            mac = get_mac_for_ip(request.remote_addr)
            if mac:
                device = Device.query.filter_by(mac=mac).first()
                if device:
                    device.user_id = user.id
                    device.status = "approved"
                    device.granted_at = datetime.utcnow()
                    ps = PortalSession(
                        mac=mac, username=user.username,
                        state="granted",
                        expires_at=datetime.utcnow() + timedelta(
                            minutes=cfg.SESSION_TTL_MINUTES),
                    )
                    db.session.add(ps)
                    db.session.commit()
                    grant_access(mac)
                    log_forensic_event(mac, "GRANT_ACCESS",
                                        f"User {user.username} signed in")
                else:
                    log_forensic_event(
                        request.remote_addr, "GRANT_ACCESS_FAIL",
                        f"User {user.username} signed in but MAC {mac} "
                        f"has no device record")
        return redirect(url_for("main.admin_dashboard"))
    return render_template("login.html")


@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not email:
            return "Username, email and password are all required.", 400
        if password != confirm:
            return "Passwords do not match.", 400
        if User.query.filter_by(username=username).first():
            return "Username already taken.", 400
        if User.query.filter_by(email=email).first():
            return "Email already registered.", 400

        token = secrets.token_urlsafe(32)
        try:
            db.session.add(User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                status="pending",
                is_admin=False,
                verification_token=token,
            ))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return "Username or email already registered.", 400

        verify_url = url_for("main.verify_email", token=token, _external=True)
        send_verification_email(current_app._get_current_object(),
                                email, username, verify_url)

        flash("Registration submitted. Check your email (or the server console "
              "in lab mode) for the verification link, then wait for admin approval.")
        return redirect(url_for("main.login"))
    return render_template("register.html")


@main.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return "Invalid or expired verification link.", 400
    user.email_verified = True
    user.verification_token = None   # one-time use
    db.session.commit()
    return render_template("verify_success.html", username=user.username)


# --- admin console ----------------------------------------------------------

@main.route("/admin/pending")
@admin_required
def pending_users():
    pending = User.query.filter_by(status="pending").order_by(
        User.registered_at.asc()).all()
    return render_template("pending_users.html", pending=pending)


@main.route("/admin/approve/<int:user_id>", methods=["POST"])
@admin_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    user.status = "approved"
    db.session.commit()
    log_forensic_event(user.username, "USER_APPROVED",
                       f"Approved registration for {user.username}")
    return redirect(url_for("main.pending_users"))


@main.route("/admin/reject/<int:user_id>", methods=["POST"])
@admin_required
def reject_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    user.status = "rejected"
    db.session.commit()
    log_forensic_event(user.username, "USER_REJECTED",
                       f"Rejected registration for {user.username}")
    return redirect(url_for("main.pending_users"))


@main.route("/admin")
@admin_required
def admin_dashboard():
    # "Connected" = seen by the discovery sensor recently. Devices that left the
    # network age out after CONNECTED_TTL_SECONDS, but a banned device always
    # stays listed so the table matches the Active Bans tile.
    cutoff = datetime.utcnow() - timedelta(seconds=cfg.CONNECTED_TTL_SECONDS)
    devices = (Device.query
               .filter(or_(Device.last_seen >= cutoff, Device.status == "banned"))
               .all())
    active_bans = Ban.query.filter_by(active=True).order_by(Ban.since.desc()).all()
    pending = User.query.filter_by(status="pending").all()
    recent_events = (AuthEvent.query
                     .order_by(AuthEvent.timestamp.desc())
                     .limit(20).all())

    stats = {
        "total_devices": len(devices),
        "high_risk": sum(1 for d in devices if d.risk_level == "HIGH"),
        "medium_risk": sum(1 for d in devices if d.risk_level == "MEDIUM"),
        "active_bans": len(active_bans),
        "pending_users": len(pending),
    }
    sessions = PortalSession.query.filter_by(state="granted").all()
    # Phase 10: recent risk/ban notices + which devices were warned recently.
    notifications = (Notification.query
                     .order_by(Notification.created_at.desc())
                     .limit(25).all())
    warn_cutoff = datetime.utcnow() - timedelta(hours=24)
    warned_macs = {n.mac for n in notifications
                   if n.kind == "medium_warning"
                   and n.created_at and n.created_at >= warn_cutoff}
    return render_template("admin.html", devices=devices,
                           active_bans=active_bans,
                           recent_events=recent_events,
                           pending_users=pending,
                           sessions=sessions,
                           notifications=notifications,
                           warned_macs=warned_macs,
                           stats=stats)


@main.route("/admin/device/<mac>/contact", methods=["POST"])
@admin_required
def set_device_contact(mac):
    """Set or clear the contact email used for risk/ban notices (Phase 10)."""
    device = Device.query.filter_by(mac=mac).first()
    if not device:
        return "Device not found", 404
    address = request.form.get("notify_email", "").strip()
    if address and not _EMAIL_RE.match(address):
        flash("Invalid email address — not saved.")
        return redirect(url_for("main.admin_dashboard"))
    device.notify_email = address or None
    db.session.commit()
    log_forensic_event(mac, "SET_CONTACT",
                       {"notify_email": address or None})
    return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/revoke/<mac>", methods=["POST"])
@admin_required
def revoke_access(mac):
    ps = PortalSession.query.filter_by(mac=mac, state="granted").first()
    if ps:
        ps.state = "revoked"
        db.session.commit()
    portal_revoke_access(mac)
    log_forensic_event(mac, "REVOKE_ACCESS", "Admin revoked access")
    return redirect(url_for("main.admin_dashboard"))


# Backwards-compat: the Phase 1-5 dashboard now lives at /admin.
@main.route("/dashboard")
@admin_required
def dashboard():
    return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/unban/<mac>", methods=["POST"])
@admin_required
def unban(mac):
    ban = Ban.query.filter_by(mac=mac, active=True).first()
    if ban:
        ban.active = False
        ban.unbanned_at = datetime.utcnow()
    device = Device.query.filter_by(mac=mac).first()
    if device:
        release_device(device.ip, mac)
        # Zero-trust choice: unban does NOT restore approval — it resets to
        # "unknown" so the device has to re-earn trust from scratch.
        device.status = "unknown"
        device.user_id = None
        device.granted_at = None
    else:
        release_device(None, mac)
    # Revoke any portal session for this MAC.
    ps = PortalSession.query.filter_by(mac=mac, state="granted").first()
    if ps:
        ps.state = "revoked"
    portal_revoke_access(mac)
    db.session.commit()
    log_forensic_event(mac, "UNBAN", "Released from quarantine (status -> unknown)")
    return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/traceback/<mac>")
@admin_required
def traceback_view(mac):
    data = reconstruct_timeline(mac)
    return render_template("traceback.html", data=data)


@main.route("/logout")
def logout():
    # Portal gate: revoke access for the session's devices before clearing.
    if cfg.PORTAL_GATE and request.remote_addr != "127.0.0.1":
        mac = get_mac_for_ip(request.remote_addr)
        if mac:
            portal_revoke_access(mac)
            ps = PortalSession.query.filter_by(
                mac=mac, state="granted").first()
            if ps:
                ps.state = "revoked"
                db.session.commit()
            log_forensic_event(mac, "REVOKE_ACCESS",
                                "User logged out")
    session.clear()
    return redirect(url_for("main.login"))


# --- captive portal probes -------------------------------------------------
# OS captive-portal detection hits specific probe domains (dnsmasq resolves
# them to the gateway). Responding with something other than the expected
# response makes the OS pop its native sign-in page. Works for:
#   /generate_204          – Android / ChromeOS (expects empty 204)
#   /connecttest.txt       – Windows (expects "Microsoft Connect Test")
#   /hotspot-detect.html  – Apple (expects a "Success" HTML page)


@main.route("/generate_204")
@main.route("/connecttest.txt")
@main.route("/hotspot-detect.html")
def captive_probe():
    return redirect(url_for("main.login"))


# --- Demo monitoring (display-only) ----------------------------------------
# Two additive, read-only JSON endpoints for the dashboard's live event feed
# and ban toast. They change nothing in scoring, baseline or enforcement; they
# only expose existing data.

@main.route("/api/recent-events")
def recent_events():
    """Last 15 forensic log entries, newest first (dashboard live feed)."""
    if "user" not in session:
        return jsonify([]), 401
    events = []
    try:
        with open(LOG_PATH) as f:
            lines = f.readlines()[-15:]
        for line in reversed(lines):
            try:
                events.append(json.loads(line))
            except (ValueError, TypeError):
                continue          # skip a torn/blank trailing line
    except FileNotFoundError:
        pass
    return jsonify(events)


@main.route("/api/device-status")
def device_status_api():
    """Minimal per-device risk snapshot for the ban toast."""
    if "user" not in session:
        return jsonify([]), 401
    devices = Device.query.all()
    return jsonify([{"mac": d.mac, "risk_level": d.risk_level}
                    for d in devices])
