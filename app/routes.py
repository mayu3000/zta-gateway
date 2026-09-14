from flask import Blueprint, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash
from datetime import datetime
from .models import User, Device, AuthEvent, Ban, db
from .enforcement.quarantine import release_device
from .logging.forensic import log_forensic_event
from .traceback.tracer import reconstruct_timeline
from .sync_devices import sync_devices

main = Blueprint("main", __name__)

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
        if success:
            session["user"] = user.username
            return redirect(url_for("main.dashboard"))
        return "Invalid credentials", 401
    return render_template("login.html")

@main.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("main.login"))
    devices = Device.query.all()
    active_bans = Ban.query.filter_by(active=True).order_by(Ban.since.desc()).all()
    return render_template("dashboard.html", devices=devices,
                           active_bans=active_bans)

@main.route("/admin/unban/<mac>", methods=["POST"])
def unban(mac):
    if "user" not in session:
        return redirect(url_for("main.login"))
    ban = Ban.query.filter_by(mac=mac, active=True).first()
    if ban:
        ban.active = False
        ban.unbanned_at = datetime.utcnow()
    release_device(mac)
    device = Device.query.filter_by(mac=mac).first()
    if device:
        # Zero-trust choice: unban does NOT restore approval — it resets to
        # "unknown" so the device has to re-earn trust from scratch.
        device.status = "unknown"
    db.session.commit()
    log_forensic_event(mac, "UNBAN", "Released from quarantine (status -> unknown)")
    return redirect(url_for("main.dashboard"))

@main.route("/admin/traceback/<mac>")
def traceback_view(mac):
    if "user" not in session:
        return redirect(url_for("main.login"))
    data = reconstruct_timeline(mac)
    return render_template("traceback.html", data=data)

@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))
