"""Phase 10 — Email warning tests.

Drives the REAL `run_scoring_window()` with synthetic packet buffers, exactly
as tests/test_integration.py does, but forces the risk level via a patched
composite/level so each transition is deterministic. The mail sender is mocked
and the background thread is replaced with an inline shim so the assertions are
deterministic on every platform.

Run:  ./venv/bin/python tests/test_notify.py
"""
import os
import sys
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

# Must set ZTA_DB before importing app modules.
_db_abs = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "db", "zta_notify_test.db"
))
os.environ["ZTA_DB"] = f"sqlite:///{_db_abs}"
os.environ.setdefault("ZTA_ENFORCE", "recorded")   # no iptables under tests

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

if os.path.exists(_db_abs):
    os.remove(_db_abs)

from app import create_app, config as cfg
from app.capture.buffer import packet_queue, queue_lock
from app.models import db, Device, Notification
from app.notify import notify_medium, notify_ban, resolve_recipient, \
    describe_reason
from run import run_scoring_window

MAC = "de:ad:be:ef:00:01"
IP = "192.168.1.50"


class ImmediateThread:
    """Run the worker inline instead of on a daemon thread (deterministic)."""

    def __init__(self, target=None, daemon=None, **kwargs):
        self._target = target

    def start(self):
        self._target()


def pkt(mac=MAC, ip=IP):
    return {"timestamp": datetime.utcnow(), "src_ip": ip, "dst_ip": "1.1.1.1",
            "proto": 6, "size": 300, "dns_query": None, "src_mac": mac,
            "dst_port": 443}


def fake_result(total, behavior=20, network=20, identity=0, device=0,
                flagged=None, fan_out=10):
    return {"identity": identity, "device": device, "network": network,
            "behavior": behavior, "total": total, "fan_out": fan_out,
            "flagged_domains": flagged or []}


class NotifyTestBase(unittest.TestCase):
    def setUp(self):
        self._cfg = {k: getattr(cfg, k) for k in (
            "NOTIFY", "NOTIFY_COOLDOWN_MINUTES", "NOTIFY_MIN_WINDOWS",
            "NOTIFY_BAN_NOTICE", "NOTIFY_ADMIN_COPY")}
        cfg.NOTIFY = True
        cfg.NOTIFY_COOLDOWN_MINUTES = 10
        cfg.NOTIFY_MIN_WINDOWS = 1
        cfg.NOTIFY_BAN_NOTICE = True
        cfg.NOTIFY_ADMIN_COPY = ""

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

        # Inline "thread" so the send + audit row complete before we assert.
        # Patch the module reference inside notify.py only — patching
        # threading.Thread globally would break subprocess elsewhere.
        self._thread_patch = patch("app.notify.threading",
                                   SimpleNamespace(Thread=ImmediateThread))
        self._thread_patch.start()

    def tearDown(self):
        self._thread_patch.stop()
        for k, v in self._cfg.items():
            setattr(cfg, k, v)
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    # -- helpers -----------------------------------------------------------
    def seed_device(self, notify_email="owner@example.com",
                    risk_level="LOW", mac=MAC, ip=IP):
        d = Device(mac=mac, ip=ip, hostname=None, status="unknown",
                   risk_level=risk_level, notify_email=notify_email)
        db.session.add(d)
        db.session.commit()
        return d

    def drive(self, total, level, mac=MAC, ip=IP):
        """Run one scoring window forcing (total, level)."""
        with patch("app.policy.composite.compute_composite_risk",
                   return_value=fake_result(total)), \
             patch("app.policy.scoring.risk_level", return_value=level), \
             patch("app.features.extract.get_mac_for_ip", return_value=None):
            with queue_lock:
                packet_queue.clear()
                packet_queue.append(pkt(mac, ip))
            return run_scoring_window(self.app)

    def rows(self, kind=None):
        db.session.expire_all()
        q = Notification.query
        if kind:
            q = q.filter_by(kind=kind)
        return q.all()


class MediumWarningTests(NotifyTestBase):
    def test_low_to_medium_sends_one_warning(self):
        self.seed_device()
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")
        rows = self.rows("medium_warning")
        self.assertEqual(len(rows), 1, "expected exactly one warning row")
        self.assertEqual(rows[0].status, "sent")
        self.assertEqual(rows[0].recipient, "owner@example.com")
        self.assertEqual(mock_send.call_count, 1)

    def test_second_warning_within_cooldown_sends_nothing(self):
        self.seed_device()
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")
            self.drive(40, "MEDIUM")     # inside the 10-minute cooldown
        rows = self.rows("medium_warning")
        self.assertEqual(len(rows), 1, "cooldown should suppress the second")
        self.assertEqual(mock_send.call_count, 1)

    def test_no_recipient_writes_skipped_row(self):
        self.seed_device(notify_email=None)
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")
        rows = self.rows("medium_warning")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "skipped")
        mock_send.assert_not_called()

    def test_sender_error_records_failed_without_raising(self):
        self.seed_device()
        mock_send = MagicMock(side_effect=RuntimeError("SMTP down"))
        with patch("app.mail.send_risk_email", mock_send):
            summary = self.drive(40, "MEDIUM")   # must not raise
        rows = self.rows("medium_warning")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "failed")
        self.assertIn("SMTP down", rows[0].error)
        self.assertEqual(summary[MAC]["total"], 40)

    def test_min_windows_two_needs_two_consecutive(self):
        cfg.NOTIFY_MIN_WINDOWS = 2
        self.seed_device()
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")           # streak 1 -> nothing
            self.assertEqual(len(self.rows("medium_warning")), 0)
            self.drive(40, "MEDIUM")           # streak 2 -> warn
        self.assertEqual(len(self.rows("medium_warning")), 1)
        self.assertEqual(mock_send.call_count, 1)

    def test_notify_disabled_runs_nothing(self):
        cfg.NOTIFY = False
        self.seed_device()
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")
        self.assertEqual(len(self.rows()), 0)
        mock_send.assert_not_called()


class BanNoticeTests(NotifyTestBase):
    def test_medium_to_high_sends_ban_notice_only(self):
        self.seed_device(risk_level="MEDIUM")
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(90, "HIGH")
        self.assertEqual(len(self.rows("medium_warning")), 0)
        bans = self.rows("ban_notice")
        self.assertEqual(len(bans), 1)
        self.assertEqual(bans[0].status, "sent")
        self.assertEqual(mock_send.call_count, 1)

    def test_low_straight_to_high_sends_only_ban_notice(self):
        self.seed_device(risk_level="LOW")
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(90, "HIGH")
        self.assertEqual(len(self.rows("medium_warning")), 0)
        self.assertEqual(len(self.rows("ban_notice")), 1)

    def test_ban_notice_disabled(self):
        cfg.NOTIFY_BAN_NOTICE = False
        self.seed_device(risk_level="MEDIUM")
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(90, "HIGH")
        self.assertEqual(len(self.rows()), 0)
        mock_send.assert_not_called()


class UnitHelperTests(NotifyTestBase):
    def test_resolve_recipient_prefers_signed_in_user(self):
        from app.models import User
        from werkzeug.security import generate_password_hash
        u = User(username="alice", email="alice@example.com",
                 password_hash=generate_password_hash("x"),
                 status="approved", email_verified=True)
        db.session.add(u)
        db.session.commit()
        d = self.seed_device(notify_email="fallback@example.com")
        d.user_id = u.id
        db.session.commit()
        self.assertEqual(resolve_recipient(d), "alice@example.com")

    def test_resolve_recipient_falls_back_to_admin_contact(self):
        d = self.seed_device(notify_email="fallback@example.com")
        self.assertEqual(resolve_recipient(d), "fallback@example.com")

    def test_resolve_recipient_none(self):
        d = self.seed_device(notify_email=None)
        self.assertIsNone(resolve_recipient(d))

    def test_describe_reason_prefers_blocklist(self):
        r = describe_reason(fake_result(60, flagged=["bad.example"]))
        self.assertIn("blocklist", r)

    def test_describe_reason_never_lists_domains(self):
        r = describe_reason(fake_result(60, behavior=80, flagged=["evil.test"]))
        self.assertNotIn("evil.test", r)

    def test_admin_copy_receives_every_notice(self):
        cfg.NOTIFY_ADMIN_COPY = "admin@example.com"
        self.seed_device()
        mock_send = MagicMock(return_value="smtp")
        with patch("app.mail.send_risk_email", mock_send):
            self.drive(40, "MEDIUM")
        # owner + admin copy
        self.assertEqual(mock_send.call_count, 2)
        recipients = {c.args[1] for c in mock_send.call_args_list}
        self.assertEqual(recipients,
                         {"owner@example.com", "admin@example.com"})


class ContactRouteTests(NotifyTestBase):
    """Item 1 + Item 8: admin contact form and the dashboard views."""

    def setUp(self):
        super().setUp()
        self.client = self.app.test_client()

    def _login_admin(self):
        return self.client.post("/login",
                                data={"username": "admin",
                                      "password": "admin123"})

    def _login_alice(self):
        from app.models import User
        from werkzeug.security import generate_password_hash
        u = User(username="alice", email="alice@example.com",
                 password_hash=generate_password_hash("pw12345"),
                 status="approved", email_verified=True, is_admin=False)
        db.session.add(u)
        db.session.commit()
        return self.client.post("/login",
                                data={"username": "alice",
                                      "password": "pw12345"})

    def test_admin_sets_contact_and_it_shows_in_table(self):
        self.seed_device(notify_email=None)
        self._login_admin()
        r = self.client.post(f"/admin/device/{MAC}/contact",
                             data={"notify_email": "new@example.com"})
        self.assertEqual(r.status_code, 302)      # PRG
        self.assertEqual(Device.query.filter_by(mac=MAC).first().notify_email,
                         "new@example.com")
        page = self.client.get("/admin").get_data(as_text=True)
        self.assertIn("new@example.com", page)

    def test_non_admin_gets_403(self):
        self.seed_device(notify_email=None)
        self._login_alice()
        r = self.client.post(f"/admin/device/{MAC}/contact",
                             data={"notify_email": "nope@example.com"})
        self.assertEqual(r.status_code, 403)

    def test_invalid_address_rejected(self):
        self.seed_device(notify_email="keep@example.com")
        self._login_admin()
        self.client.post(f"/admin/device/{MAC}/contact",
                         data={"notify_email": "not-an-email"})
        self.assertEqual(Device.query.filter_by(mac=MAC).first().notify_email,
                         "keep@example.com")

    def test_clearing_contact_works(self):
        self.seed_device(notify_email="x@example.com")
        self._login_admin()
        self.client.post(f"/admin/device/{MAC}/contact",
                         data={"notify_email": ""})
        self.assertIsNone(Device.query.filter_by(mac=MAC).first().notify_email)

    def test_dashboard_shows_recent_notification(self):
        self.seed_device()
        db.session.add(Notification(
            mac=MAC, recipient="owner@example.com", kind="medium_warning",
            score=40, reason="a sudden burst of connection attempts",
            status="sent"))
        db.session.commit()
        self._login_admin()
        page = self.client.get("/admin").get_data(as_text=True)
        self.assertIn("Recent Notifications", page)
        self.assertIn("medium_warning", page)
        self.assertIn("Warned", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
