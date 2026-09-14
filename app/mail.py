"""Phase 7 email delivery for verification links.

Uses Flask-Mail when it's installed AND the app is configured with SMTP
settings. Otherwise falls back to console + forensic-log delivery: the
verification URL is printed to the server console and written to the
forensic log so the full verify flow is exercisable without a live mail
server (LAB MODE — documented as such in the report).
"""
import logging

from app.logging.forensic import log_forensic_event

try:
    from flask_mail import Mail as _FlaskMail, Message
    FLASK_MAIL_AVAILABLE = True
except ImportError:  # pragma: no cover — not installed in bare venv
    FLASK_MAIL_AVAILABLE = False

log = logging.getLogger("zta.mail")

_LAST_VERIFY_URL = None   # exposes the most recent link for tests / console


def get_last_verification_url():
    """Return the most recently generated verification URL (LAB MODE helper)."""
    return _LAST_VERIFY_URL


def mail_ext(app):
    """Return the configured Flask-Mail extension instance, or None."""
    if not FLASK_MAIL_AVAILABLE:
        return None
    from flask import Flask
    if not app.config.get("MAIL_SERVER"):
        return None
    if not hasattr(app, "extensions"):
        app.extensions = {}
    ext = _FlaskMail(app)
    app.extensions.setdefault("mail", ext)
    return ext


def send_verification_email(app, email_address, username, verify_url):
    """Deliver the verification link: real SMTP if configured, else console."""
    global _LAST_VERIFY_URL
    _LAST_VERIFY_URL = verify_url

    ext = mail_ext(app)
    if ext is not None:
        try:
            msg = Message(
                "Verify your ZTA Gateway account",
                sender=app.config.get("MAIL_DEFAULT_SENDER",
                                      "noreply@ztagateway.local"),
                recipients=[email_address])
            msg.body = (f"Hi {username},\n\n"
                        f"Click this link to verify your email for ZTA Gateway:\n"
                        f"{verify_url}\n\n"
                        f"If you didn't request this, you can ignore this email.")
            ext.send(msg)
            log.info("verification email sent to %s", email_address)
            return "smtp"
        except Exception as exc:  # don't let mail failures block registration
            log.warning("SMTP send failed (%s); falling back to console", exc)

    # LAB MODE fallback — no live mail server. The link still reaches the user
    # via the server console and the forensic audit log.
    print(f"[mail:LAB-MODE] VERIFY {email_address}: {verify_url}", flush=True)
    log_forensic_event(username, "EMAIL_VERIFY",
                       {"to": email_address, "url": verify_url})
    return "console"