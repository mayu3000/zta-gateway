import secrets
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, session,
                   url_for, flash, current_app)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from .models import User, Device, AuthEvent, Ban, db
from .enforcement.quarantine import release_device
from .logging.forensic import log_forensic_event
from .traceback.tracer import reconstruct_timeline
from .mail import send_verification_email

main = Blueprint("main", __name__)


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
    devices = Device.query.all()
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
    return render_template("admin.html", devices=devices,
                           active_bans=active_bans,
                           recent_events=recent_events,
                           pending_users=pending,
                           stats=stats)


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
    else:
        release_device(None, mac)
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
    session.clear()
    return redirect(url_for("main.login"))