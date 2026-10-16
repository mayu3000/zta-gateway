"""Phase 9: portal redirect listener (P1.3).

Tiny HTTP server on port 80. Every request from a blocked device gets:
  - A 302 redirect to ZTA_PORTAL_URL for normal pages
  - OS captive-portal probe responses for connectivity check endpoints
    so the OS pops its native "Sign in to Wi-Fi" notification.

Runs as a daemon thread when ZTA_PORTAL_GATE=1; a no-op on Windows.
"""
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

from app import config as cfg

log = logging.getLogger(__name__)

# OS captive-portal probe paths and their expected responses.
# If we answer with anything other than the expected response, the OS
# knows it's behind a captive portal and pops the sign-in page.
_PROBE_RESPONSES = {
    "/generate_204": (b"", 204),
    "/gen_204": (b"", 204),
    "/hotspot-detect.html": (
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
        b"<BODY>Success</BODY></HTML>", 200),
    "/library/test/success.html": (
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
        b"<BODY>Success</BODY></HTML>", 200),
    "/connecttest.txt": (b"Microsoft Connect Test", 200),
    "/ncsi.txt": (b"Microsoft NCSI", 200),
}


class _PortalHandler(BaseHTTPRequestHandler):
    """Redirect handler: 302 to the login page, or answer OS probes."""

    def do_GET(self):
        probe = _PROBE_RESPONSES.get(self.path)
        if probe:
            body, code = probe
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(302)
            self.send_header("Location", cfg.PORTAL_URL)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        pass  # silence per-request logs


_server_thread = None
_server = None


def start_portal_listener():
    """Start the port-80 redirect server as a daemon thread."""
    global _server_thread, _server

    if not cfg.PORTAL_GATE:
        return

    def _serve():
        global _server
        _server = HTTPServer(("0.0.0.0", 80), _PortalHandler)
        log.info("[portal] redirect listener on :80 -> %s", cfg.PORTAL_URL)
        _server.serve_forever()

    _server_thread = threading.Thread(target=_serve, daemon=True)
    _server_thread.start()
    log.info("[portal] redirect listener thread started")


def stop_portal_listener():
    """Stop the redirect server (if running)."""
    global _server
    if _server:
        _server.shutdown()
        _server.server_close()
