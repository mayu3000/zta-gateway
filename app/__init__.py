import os

from flask import Flask
from .models import db, User
from werkzeug.security import generate_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()   # load .env (gitignored) before reading any settings
except ImportError:  # pragma: no cover — python-dotenv is a soft dependency
    pass

def _ensure_columns():
    """Additive, idempotent SQLite migration for columns create_all() misses.

    ``db.create_all()`` only creates missing *tables*; an existing db/zta.db
    keeps its old schema, so a new column would raise "no such column" at
    runtime. These ALTER TABLE statements are additive and safe to re-run.
    """
    from sqlalchemy import inspect, text
    existing = {c["name"] for c in inspect(db.engine).get_columns("user")}
    wanted = {
        # F3: typed 6-digit verification code.
        "verification_code_hash": "VARCHAR(200)",
        "verification_code_expires": "DATETIME",
        "verification_attempts": "INTEGER",
        "verification_locked_until": "DATETIME",
    }
    added = []
    for name, ddl in wanted.items():
        if name not in existing:
            db.session.execute(
                text(f"ALTER TABLE user ADD COLUMN {name} {ddl}"))
            added.append(name)
    if added:
        db.session.commit()
        print(f"[migrate] added user column(s): {', '.join(added)}", flush=True)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-later"
    # Tests set ZTA_DB to a throwaway database so they never collide with the
    # live server's db/zta.db (which a soak-testing run.py may have open).
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "ZTA_DB", "sqlite:///../db/zta.db")

    # Phase 10: SMTP settings for real email delivery (from .env / environment).
    # When MAIL_SERVER is unset, mail.py falls back to lab mode.
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
    app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "1") == "1"
    app.config["MAIL_USE_SSL"] = os.environ.get("MAIL_USE_SSL", "0") == "1"
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")

    db.init_app(app)

    with app.app_context():
        db.create_all()
        _ensure_columns()
        # create a default admin user if none exists (Phase 1 shortcut)
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin",
                         email="admin@local",
                         password_hash=generate_password_hash("admin123"),
                         status="approved",
                         is_admin=True,
                         email_verified=True)
            db.session.add(admin)
            db.session.commit()

    from .routes import main
    app.register_blueprint(main)

    # Phase 7 captive portal: gate unapproved devices at the login page.
    from .middleware import captive_portal_check
    app.before_request(captive_portal_check)

    return app
