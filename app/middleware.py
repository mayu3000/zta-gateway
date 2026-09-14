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

    Returns None to allow through, or a redirect/response to block.
    """
    if any(request.path.startswith(p) for p in UNRESTRICTED_PATHS):
        return None

    # Find the device by the client IP. Clients the gateway doesn't know
    # (e.g. the admin's own browser on the gateway machine, 127.0.0.1) pass
    # through — only KNOWN unapproved devices are gated.
    client_ip = request.remote_addr
    device = Device.query.filter_by(ip=client_ip).first()
    if device and device.status not in ("approved",):
        return redirect(url_for("main.login"))
    return None