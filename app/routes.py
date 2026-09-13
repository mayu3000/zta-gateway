from flask import Blueprint, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash
from .models import User, Device, AuthEvent, db
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
    return render_template("dashboard.html", devices=devices)

@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))
