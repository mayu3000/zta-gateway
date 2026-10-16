"""Phase 7 captive-portal gate (application layer).

An unapproved device (status != "approved") that opens any page on the
gateway gets cleanly redirected to the login page — the hotel-Wi-Fi effect,
implemented at the HTTP layer on top of the already-tracked device status.

The admin console (`/admin/*`) and auth flows (`/login`, `/register`,
`/verify`) are always reachable, otherwise a freshly-approved or unknown
device could not reach the very pages needed to re-earn/see trust status,
and an admin could never unban a device from a machine with status unknown.

A true network-level variant (DNS hijack for *any* hostname -> portal) is
documented as future work in CLAUDE.md / the report.
"""
from flask import request, redirect, url_for

from app.models import Device

# Paths that never trigger the captive gate.
UNRESTRICTED_PATHS = (
    "/login",
    "/register",
    "/verify",
    "/logout",
    "/admin",
    "/static",
)


def captive_portal_check():
    """before_request hook: gate unapproved device IPs at the login page.

    When the portal gate is ON, also check the PortalSession — a device
    with an expired or revoked session is redirected to login.

    Returns None to allow through, or a redirect/response to block.
    """
    if any(request.path.startswith(p) for p in UNRESTRICTED_PATHS):
        return None

    # Admin sessions from the gateway machine itself are never gated.
    if request.remote_addr == "127.0.0.1":
        return None

    from app import config as cfg
    if not cfg.PORTAL_GATE:
        # Original behaviour: gate only KNOWN unapproved devices.
        client_ip = request.remote_addr
        device = Device.query.filter_by(ip=client_ip).first()
        if device and device.status not in ("approved",):
            return redirect(url_for("main.login"))
        return None

    # Gate is ON: check if this IP has a valid portal session.
    from app.capture.resolve import get_mac_for_ip
    from app.models import PortalSession
    mac = get_mac_for_ip(request.remote_addr)
    if mac:
        ps = PortalSession.query.filter_by(mac=mac, state="granted").first()
        if ps:
            from datetime import datetime
            if ps.expires_at and ps.expires_at < datetime.utcnow():
                ps.state = "expired"
                from app.models import db
                db.session.commit()
                return redirect(url_for("main.login"))
            # Valid session — let through.
            return None

    # No valid session — redirect to portal.
    return redirect(url_for("main.login"))