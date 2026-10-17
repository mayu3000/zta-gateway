import json
import re
import secrets
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, session,
                   url_for, flash, current_app, jsonify)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError
from . import config as cfg
from .models import (User, Device, AuthEvent, Ban, PortalSession, Notification,
                     DNSLog, BandwidthLog, db)
from .enforcement.quarantine import release_device
from .enforcement.portal import grant_access, revoke_access as portal_revoke_access
from .capture.resolve import get_mac_for_ip, get_mac_for_ip_wait
from .logging.forensic import log_forensic_event, LOG_PATH
from .traceback.tracer import reconstruct_timeline
from .mail import send_verification_email

main = Blueprint("main", __name__)

# Simple address check for the admin-set device contact (Phase 10).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _human_bytes(n):
    """Render a byte count for the activity page (2.0 MB, 512 B, ...)."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


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
            return render_template(
                "portal_status.html",
                heading="Verify your email first",
                message="We emailed you a 6-digit code. Type it on the portal "
                        "(or open the link in the email) to activate this "
                        "account.",
                link_url=url_for("main.verify_code", username=user.username),
                link_text="Enter verification code"), 403
        if user.status != "approved":
            return render_template(
                "portal_status.html",
                heading="Waiting for admin approval",
                message="Your email is verified. An administrator still has to "
                        "approve this account (gateway dashboard → Pending "
                        "Users). Sign in again once they have.",
                link_url=url_for("main.login"),
                link_text="Sign in again"), 403
        session["user"] = user.username

        # Portal gate: resolve MAC and grant network access.
        if cfg.PORTAL_GATE and request.remote_addr != "127.0.0.1":
            # F4.1: the neighbour cache may not hold the client yet right after
            # it got a lease, so actively ARP for it before giving up.
            mac = get_mac_for_ip_wait(request.remote_addr)
            if not mac:
                log_forensic_event(
                    request.remote_addr, "GRANT_ACCESS_FAIL",
                    f"User {user.username} signed in but MAC lookup failed for "
                    f"{request.remote_addr} "
                    f"(no ARP reply within {cfg.MAC_LOOKUP_TIMEOUT}s)")
                return render_template(
                    "portal_status.html",
                    heading="Could not identify your device",
                    message="You are signed in, but the gateway could not read "
                            "this device's MAC address, so it cannot open the "
                            "network for it. Reconnect the device and try "
                            "again.",
                    link_url=url_for("main.login"),
                    link_text="Try again"), 503

            # F4.5: infrastructure MACs (access point, admin laptop) are always
            # approved and never redirected.
            if mac in cfg.INFRA_MACS:
                grant_access(mac)
                log_forensic_event(
                    mac, "GRANT_ACCESS",
                    f"Infra MAC {mac} (user {user.username}) — never gated")
                return render_template(
                    "portal_status.html",
                    heading="You are connected",
                    message="This is an approved infrastructure device.",
                    link_url=url_for("main.admin_dashboard"),
                    link_text="Open the dashboard")

            device = Device.query.filter_by(mac=mac).first()
            if not device:
                log_forensic_event(
                    request.remote_addr, "GRANT_ACCESS_FAIL",
                    f"User {user.username} signed in but MAC {mac} has no "
                    f"device record yet")
                return render_template(
                    "portal_status.html",
                    heading="Device not recognized yet",
                    message="You are signed in, but this device is not in the "
                            "gateway's device list yet. Wait a few seconds for "
                            "discovery to see it, then sign in again.",
                    link_url=url_for("main.login"),
                    link_text="Try again"), 503

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
            # F4.3: an explicit "you are connected" page so the client's own
            # connectivity probe can clear its sign-in notification.
            return render_template(
                "portal_status.html",
                heading="You are connected",
                message="Access granted — you can browse the internet now.",
                link_url=url_for("main.admin_dashboard"),
                link_text="Open the dashboard")
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
        # F3: a 6-digit code alongside the link, so the user can verify from the
        # signed-out phone (which has no internet to read its own email).
        code = f"{secrets.randbelow(1_000_000):06d}"
        try:
            db.session.add(User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                status="pending",
                is_admin=False,
                verification_token=token,
                verification_code_hash=generate_password_hash(code),
                verification_code_expires=datetime.utcnow() + timedelta(
                    minutes=cfg.VERIFY_CODE_TTL_MINUTES),
            ))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return "Username or email already registered.", 400

        verify_url = url_for("main.verify_email", token=token, _external=True)
        send_verification_email(current_app._get_current_object(),
                                email, username, verify_url, code=code)

        flash("Registration submitted. We emailed a 6-digit code and a link — "
              "verify, then wait for admin approval.")
        return redirect(url_for("main.verify_code", username=username))
    return render_template("register.html")


@main.route("/verify-code", methods=["GET", "POST"])
def verify_code():
    """F3: typed 6-digit code, an alternative to the emailed link.

    Single use, 15-minute expiry, and it locks for 15 minutes after 5 wrong
    tries. The link route (:func:`verify_email`) still works.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        code = request.form.get("code", "").strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template("verify_code.html", username=username,
                                   error="No such account."), 404
        if user.email_verified:
            return render_template(
                "portal_status.html",
                heading="Already verified",
                message="Your email is already verified — you can sign in.",
                link_url=url_for("main.login"),
                link_text="Go to sign in")

        now = datetime.utcnow()
        if user.verification_locked_until and user.verification_locked_until > now:
            mins = int((user.verification_locked_until - now).total_seconds()
                       // 60) + 1
            return render_template(
                "verify_code.html", username=username,
                error=f"Too many wrong codes. Try again in {mins} minute(s)."), 429
        if (not user.verification_code_hash or not user.verification_code_expires
                or user.verification_code_expires < now):
            return render_template(
                "verify_code.html", username=username,
                error="That code has expired. Register again to get a new one."), 410
        if not check_password_hash(user.verification_code_hash, code):
            user.verification_attempts = (user.verification_attempts or 0) + 1
            if user.verification_attempts >= cfg.VERIFY_CODE_MAX_TRIES:
                user.verification_attempts = 0
                user.verification_locked_until = now + timedelta(
                    minutes=cfg.VERIFY_CODE_LOCK_MINUTES)
                db.session.commit()
                log_forensic_event(
                    username, "EMAIL_VERIFY_LOCKED",
                    f"{cfg.VERIFY_CODE_MAX_TRIES} wrong codes — locked "
                    f"{cfg.VERIFY_CODE_LOCK_MINUTES} min")
                return render_template(
                    "verify_code.html", username=username,
                    error=f"Too many wrong codes. Locked for "
                          f"{cfg.VERIFY_CODE_LOCK_MINUTES} minutes."), 429
            db.session.commit()
            left = cfg.VERIFY_CODE_MAX_TRIES - user.verification_attempts
            return render_template(
                "verify_code.html", username=username,
                error=f"Wrong code. {left} attempt(s) left."), 400

        user.email_verified = True
        user.verification_token = None
        user.verification_code_hash = None
        user.verification_code_expires = None
        user.verification_attempts = 0
        user.verification_locked_until = None
        db.session.commit()
        log_forensic_event(username, "EMAIL_VERIFIED", "Typed code verified")
        return render_template("verify_success.html", username=user.username)

    return render_template("verify_code.html",
                           username=request.args.get("username", ""),
                           error=None)


@main.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return "Invalid or expired verification link.", 400
    user.email_verified = True
    user.verification_token = None   # one-time use
    # The link and the typed code are alternatives; clear the code too.
    user.verification_code_hash = None
    user.verification_code_expires = None
    user.verification_attempts = 0
    user.verification_locked_until = None
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


@main.route("/admin/mark-verified/<int:user_id>", methods=["POST"])
@admin_required
def mark_email_verified(user_id):
    """F3.6: lab fallback when SMTP is unavailable.

    Logged to the forensic log. Does NOT bypass the separate admin approval.
    """
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    user.email_verified = True
    user.verification_token = None
    user.verification_code_hash = None
    user.verification_code_expires = None
    user.verification_attempts = 0
    user.verification_locked_until = None
    db.session.commit()
    log_forensic_event(
        user.username, "EMAIL_VERIFIED_MANUAL",
        f"Admin marked {user.username}'s email verified (lab fallback)")
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


@main.route("/admin/device/<mac>/activity")
@admin_required
def activity_view(mac):
    """F7.4: per-device "Website Activity" — what this device actually did.

    Read-only view over the Phase 7 audit trail (dns_log / bandwidth_log), the
    raw material the scoring loop writes every 30s window. The sniffer only
    parses the DNS question, so this shows the domains a device *resolved*, not
    URLs or page titles (see docs/RUNBOOK-COMBINED.md).
    """
    device = Device.query.filter_by(mac=mac).first()
    if not device:
        return "Device not found", 404

    limit = cfg.ACTIVITY_LIMIT
    lookups = (DNSLog.query
               .filter_by(mac=mac)
               .order_by(DNSLog.timestamp.desc())
               .limit(limit).all())
    windows = (BandwidthLog.query
               .filter_by(mac=mac)
               .order_by(BandwidthLog.window_start.desc())
               .limit(limit).all())

    # Roll the most-resolved domains up. max(flagged) marks a domain as flagged
    # if *any* lookup of it matched the blocklist.
    top = (db.session.query(DNSLog.domain,
                            func.count(DNSLog.id).label("hits"),
                            func.max(DNSLog.flagged).label("flagged"))
           .filter(DNSLog.mac == mac)
           .group_by(DNSLog.domain)
           .order_by(func.count(DNSLog.id).desc())
           .limit(cfg.ACTIVITY_TOP_DOMAINS).all())

    dns_total = db.session.query(func.count(DNSLog.id)) \
        .filter(DNSLog.mac == mac).scalar() or 0
    flagged_total = db.session.query(func.count(DNSLog.id)) \
        .filter(DNSLog.mac == mac, DNSLog.flagged.is_(True)).scalar() or 0
    bytes_total = db.session.query(func.sum(BandwidthLog.bytes_sent)) \
        .filter(BandwidthLog.mac == mac).scalar() or 0

    return render_template(
        "activity.html",
        device=device,
        lookups=lookups,
        windows=windows,
        top=top,
        dns_total=dns_total,
        flagged_total=flagged_total,
        bytes_total=_human_bytes(bytes_total),
        limit=limit)


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
