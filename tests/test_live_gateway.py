"""Batch 2 (fix/live-gateway): F2 restart, F3 typed code, F4 sign-in hardening.

Covers:
  F3.5  typed 6-digit verification code (register/verify/lock/expiry), admin
        "mark verified" fallback, and the link flow still working;
  F3.7  additive SQLite migration for an existing db/zta.db;
  F4.1  ARP-retry MAC lookup;
  F4.2/3 distinct login status pages ("verify first", "waiting for approval");
  F4.5  ZTA_INFRA_MACS bypass the gate and are never auto-banned;
  F2    restart reconciliation restores bans/grants but not expired sessions.

Mock strategy: like test_portal, patch app.enforcement.portal._run with a
stateful fake so -C checks behave like real iptables.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

# Must set ZTA_DB before importing app modules.
_db_abs = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "db", "zta_test.db"
))
os.environ["ZTA_DB"] = f"sqlite:///{_db_abs}"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if os.path.exists(_db_abs):
    os.remove(_db_abs)

from app import create_app, config as cfg
from app.models import db, Ban, Device, PortalSession, User


def _make_stateful_mock():
    """Stateful fake iptables: tracks rules so -C behaves like the real thing."""
    state = {"rules": set()}
    calls = []

    def _normalize(args):
        for flag in ("-A", "-I", "-C", "-D"):
            if flag in args:
                idx = args.index(flag)
                return tuple(args[:idx] + args[idx + 1:])
        return tuple(args)

    def _fake_run(args):
        args = list(args)
        calls.append(tuple(args))
        if "-F" in args:
            state["rules"].clear()
            return (True, "")
        if "-S" in args:
            return (True, "\n".join(
                " ".join(("-A",) + r) for r in state["rules"]))
        if "-C" in args:
            return (_normalize(args) in state["rules"], "")
        if "-A" in args or "-I" in args:
            state["rules"].add(_normalize(args))
        if "-D" in args:
            state["rules"].discard(_normalize(args))
        return (True, "")

    return _fake_run, calls, state


class _Base(unittest.TestCase):
    def setUp(self):
        cfg.PORTAL_GATE = False
        cfg.INFRA_MACS = ()
        self.codes = {}
        self.app = create_app()
        self.app.config["TESTING"] = True
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        cfg.PORTAL_GATE = False
        cfg.INFRA_MACS = ()
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _capture_mail(self):
        """Patch the mailer so the plaintext verification code is captured."""
        def fake_send(_app, _email, username, _url, code=None):
            self.codes[username] = code
            return "console"
        return patch("app.routes.send_verification_email",
                     side_effect=fake_send)

    def _register(self, username="alice", email="alice@lab.local",
                  password="pw12345"):
        c = self.app.test_client()
        with self._capture_mail():
            r = c.post("/register", data={"username": username, "email": email,
                                          "password": password,
                                          "confirm": password})
        return c, r


class VerifyCodeTests(_Base):
    """F3.5: typed 6-digit code, lockout and expiry."""

    def test_register_creates_hashed_code_and_redirects_to_form(self):
        _, r = self._register()
        self.assertEqual(r.status_code, 302)
        self.assertIn("/verify-code", r.headers["Location"])
        self.assertRegex(self.codes.get("alice") or "", r"^\d{6}$")
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertFalse(u.email_verified)
            self.assertTrue(u.verification_code_hash)
            # stored hashed, never in the clear
            self.assertNotIn(self.codes["alice"], u.verification_code_hash)
            self.assertIsNotNone(u.verification_code_expires)
            self.assertTrue(u.verification_token, "link flow must still work")

    def test_correct_code_verifies_and_clears_everything(self):
        c, _ = self._register()
        code = self.codes["alice"]
        r = c.post("/verify-code", data={"username": "alice", "code": code})
        self.assertEqual(r.status_code, 200)
        self.assertIn("verified", r.get_data(as_text=True).lower())
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertTrue(u.email_verified)
            self.assertIsNone(u.verification_code_hash)
            self.assertIsNone(u.verification_token)
            self.assertEqual(u.verification_attempts, 0)

    def test_wrong_code_counts_attempts_then_locks(self):
        c, _ = self._register()
        for i in range(cfg.VERIFY_CODE_MAX_TRIES - 1):
            r = c.post("/verify-code",
                       data={"username": "alice", "code": "999999"})
            self.assertEqual(r.status_code, 400, f"attempt {i}")
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertEqual(u.verification_attempts,
                             cfg.VERIFY_CODE_MAX_TRIES - 1)
        # the next wrong try locks the account
        r = c.post("/verify-code", data={"username": "alice", "code": "999999"})
        self.assertEqual(r.status_code, 429)
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertIsNotNone(u.verification_locked_until)
            self.assertGreater(u.verification_locked_until, datetime.utcnow())
        # even the right code is refused while locked
        r = c.post("/verify-code",
                   data={"username": "alice", "code": self.codes["alice"]})
        self.assertEqual(r.status_code, 429)

    def test_expired_code_refused(self):
        c, _ = self._register()
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            u.verification_code_expires = datetime.utcnow() - timedelta(minutes=1)
            db.session.commit()
        r = c.post("/verify-code",
                   data={"username": "alice", "code": self.codes["alice"]})
        self.assertEqual(r.status_code, 410)

    def test_link_flow_still_verifies(self):
        c, _ = self._register()
        with self.app.app_context():
            token = User.query.filter_by(username="alice").first() \
                .verification_token
        r = c.get(f"/verify/{token}")
        self.assertEqual(r.status_code, 200)
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertTrue(u.email_verified)
            self.assertIsNone(u.verification_code_hash)

    def test_admin_mark_verified_fallback(self):
        self._register()
        admin = self.app.test_client()
        admin.post("/login", data={"username": "admin", "password": "admin123"})
        with self.app.app_context():
            uid = User.query.filter_by(username="alice").first().id
        r = admin.post(f"/admin/mark-verified/{uid}")
        self.assertEqual(r.status_code, 302)
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            self.assertTrue(u.email_verified)
            # the fallback must NOT bypass the separate admin approval
            self.assertEqual(u.status, "pending")


class LoginStatusPageTests(_Base):
    """F4.2/3: distinct pages instead of generic 403 strings."""

    def test_unverified_login_shows_verify_page(self):
        self._register()
        c = self.app.test_client()
        r = c.post("/login", data={"username": "alice", "password": "pw12345"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("verify your email", r.get_data(as_text=True).lower())

    def test_verified_but_unapproved_shows_waiting_page(self):
        self._register()
        with self.app.app_context():
            u = User.query.filter_by(username="alice").first()
            u.email_verified = True
            db.session.commit()
        c = self.app.test_client()
        r = c.post("/login", data={"username": "alice", "password": "pw12345"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("admin approval", r.get_data(as_text=True).lower())


class MacLookupTests(_Base):
    """F4.1: ARP retry when the neighbour cache has no entry yet."""

    def test_wait_helper_retries_until_mac_appears(self):
        from app.capture import resolve
        calls = {"n": 0}

        def fake_get(ip):
            calls["n"] += 1
            return "aa:bb:cc:dd:ee:ff" if calls["n"] >= 3 else None

        with patch.object(resolve, "get_mac_for_ip", side_effect=fake_get), \
             patch.object(resolve, "probe_arp", return_value=None), \
             patch.object(resolve, "invalidate_cache"), \
             patch.object(resolve.time, "sleep", lambda _s: None):
            mac = resolve.get_mac_for_ip_wait("192.168.50.98", timeout=2.0)
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
        self.assertGreaterEqual(calls["n"], 3)

    def test_wait_helper_returns_none_on_timeout(self):
        from app.capture import resolve
        with patch.object(resolve, "get_mac_for_ip", return_value=None), \
             patch.object(resolve, "probe_arp", return_value=None), \
             patch.object(resolve, "invalidate_cache"), \
             patch.object(resolve.time, "sleep", lambda _s: None), \
             patch.object(resolve.time, "time", side_effect=[0, 0, 3, 3]):
            mac = resolve.get_mac_for_ip_wait("192.168.50.99", timeout=1.0)
        self.assertIsNone(mac)


class InfraMacTests(_Base):
    """F4.5: ZTA_INFRA_MACS are never gated and never auto-banned."""

    @patch("app.enforcement.portal._run")
    def test_infra_accept_precedes_default_drop(self, mock_run):
        cfg.PORTAL_GATE = True
        cfg.INFRA_MACS = ("aa:bb:cc:dd:ee:01",)
        fake, calls, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate
        setup_gate()
        acc = next(i for i, c in enumerate(calls)
                   if "ACCEPT" in c and "aa:bb:cc:dd:ee:01" in c)
        drp = next(i for i, c in enumerate(calls)
                   if "-j" in c and "DROP" in c and "mac-source" not in c)
        self.assertLess(acc, drp,
                        "infra ACCEPT must precede the default DROP")
        nat_ret = [c for c in calls
                   if "-t" in c and "nat" in c and "RETURN" in c
                   and "aa:bb:cc:dd:ee:01" in c]
        self.assertTrue(nat_ret, "infra MAC must be exempt from the redirect")

    def test_infra_mac_not_quarantined(self):
        cfg.INFRA_MACS = ("aa:bb:cc:dd:ee:01",)
        from app.enforcement import quarantine
        with patch.object(quarantine, "_iptables_add") as add, \
             patch.object(quarantine, "_spoof_loop"):
            before = dict(quarantine._active_quarantines)
            try:
                result = quarantine.quarantine_device(
                    "192.168.50.5", "aa:bb:cc:dd:ee:01")
                in_table = "aa:bb:cc:dd:ee:01" in quarantine._active_quarantines
            finally:
                quarantine._active_quarantines.clear()
                quarantine._active_quarantines.update(before)
        self.assertFalse(result)
        add.assert_not_called()
        self.assertFalse(in_table)


class RestartReconciliationTests(_Base):
    """F2: reboot/restart replays bans and live grants, not expired sessions."""

    @patch("app.enforcement.portal._run")
    def test_restore_replays_grants_and_bans_not_expired(self, mock_run):
        cfg.PORTAL_GATE = True
        fake, calls, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import (
            setup_gate, restore_from_db, is_granted,
        )

        live_mac = "aa:bb:cc:dd:ee:10"      # signed in, session still valid
        dead_mac = "aa:bb:cc:dd:ee:11"      # session already expired
        ban_mac = "aa:bb:cc:dd:ee:12"       # banned before the restart

        with self.app.app_context():
            for m in (live_mac, dead_mac, ban_mac):
                db.session.add(Device(mac=m, ip="192.168.50.2"))
            db.session.add(Ban(mac=ban_mac, reason="test", active=True))
            db.session.add(PortalSession(
                mac=live_mac, username="alice", state="granted",
                expires_at=datetime.utcnow() + timedelta(minutes=20)))
            db.session.add(PortalSession(
                mac=dead_mac, username="bob", state="granted",
                expires_at=datetime.utcnow() - timedelta(minutes=1)))
            db.session.commit()

        # simulate restart: build chains, then replay state from the DB
        setup_gate()
        bans, sessions = restore_from_db(self.app)

        self.assertEqual(bans, 1)
        self.assertEqual(sessions, 1)
        self.assertTrue(is_granted(live_mac), "live session must be re-granted")
        self.assertFalse(is_granted(dead_mac), "expired session must NOT return")
        self.assertFalse(is_granted(ban_mac), "banned MAC must stay ungranted")

        with self.app.app_context():
            dead = PortalSession.query.filter_by(mac=dead_mac).first()
            self.assertEqual(dead.state, "expired")

        # the default DROP must be the very last DROP rule added
        drops = [c for c in calls if "-j" in c and "DROP" in c]
        self.assertTrue(drops)
        self.assertNotIn("mac-source", drops[-1])
        self.assertIn("-A", drops[-1])


class MigrationTests(_Base):
    """F3.7: an existing db/zta.db gets the new columns added, not recreated."""

    def test_ensure_columns_upgrades_legacy_table(self):
        legacy = os.path.join(tempfile.mkdtemp(), "legacy.db")
        con = sqlite3.connect(legacy)
        con.execute(
            "CREATE TABLE user ("
            " id INTEGER PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL,"
            " email VARCHAR(120), password_hash VARCHAR(200) NOT NULL,"
            " status VARCHAR(20), registered_at DATETIME, is_admin BOOLEAN,"
            " email_verified BOOLEAN, verification_token VARCHAR(64))")
        con.commit()
        con.close()

        prev = os.environ.get("ZTA_DB")
        os.environ["ZTA_DB"] = f"sqlite:///{legacy}"
        try:
            app2 = create_app()
            from sqlalchemy import inspect
            with app2.app_context():
                cols = {c["name"] for c in inspect(db.engine).get_columns("user")}
            for name in ("verification_code_hash", "verification_code_expires",
                         "verification_attempts", "verification_locked_until"):
                self.assertIn(name, cols, f"{name} should be migrated in")
        finally:
            if prev is None:
                os.environ.pop("ZTA_DB", None)
            else:
                os.environ["ZTA_DB"] = prev


if __name__ == "__main__":
    unittest.main()
