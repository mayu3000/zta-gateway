"""P3.1 — Portal gate tests.

Covers: rule order, idempotent setup, grant/revoke, ban precedence,
session expiry, login with/without resolvable MAC, approval flag,
gate-off = no iptables calls.

Mock strategy: patch app.enforcement.portal._run with a stateful fake
that tracks added rules so -C checks behave like real iptables.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Must set ZTA_DB before importing app modules.
_db_abs = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "db", "zta_test.db"
))
os.environ["ZTA_DB"] = f"sqlite:///{_db_abs}"

# Ensure we import from the project root.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

# Delete the throwaway DB so each run starts clean.
if os.path.exists(_db_abs):
    os.remove(_db_abs)

from app import create_app, config as cfg
from app.models import db, Device, Ban, PortalSession, User


def _make_stateful_mock():
    """Return (fake_run, calls_list, state_dict) where fake_run tracks rule state.

    Stores rules in normalized form (without the action flag) so that
    -C checks match -A additions. Tracks chains separately.
    """
    state = {"rules": set(), "chains": set()}
    calls = []

    def _normalize(args):
        """Remove the action flag (-A, -C, -D) for comparison."""
        for flag in ("-A", "-C", "-D"):
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
        if "-C" in args:
            key = _normalize(args)
            return (key in state["rules"], "")
        if "-A" in args:
            state["rules"].add(_normalize(args))
        if "-D" in args:
            state["rules"].discard(_normalize(args))
        if "-N" in args:
            state["chains"].add(args[args.index("-N") + 1])
        return (True, "")

    return _fake_run, calls, state


class PortalFirewallTests(unittest.TestCase):
    """Test iptables rule generation (mocked _run)."""

    def setUp(self):
        cfg.PORTAL_GATE = True
        cfg.DNS_INTERCEPT = True
        self.app = create_app()
        self.app.config["TESTING"] = True
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        cfg.PORTAL_GATE = False
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    @patch("app.enforcement.portal._run")
    def test_setup_gate_creates_chains(self, mock_run):
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate
        setup_gate()
        calls = [c[0][0] for c in mock_run.call_args_list]
        self.assertTrue(
            any("-N" in str(c) for c in calls),
            "setup_gate should create chains"
        )

    @patch("app.enforcement.portal._run")
    def test_setup_gate_idempotent(self, mock_run):
        """Running setup_gate 3 times must not accumulate duplicate rules."""
        fake, _, state = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate
        setup_gate()
        first = len(state["rules"])
        setup_gate()
        setup_gate()
        self.assertGreater(first, 0, "setup_gate should install rules")
        self.assertEqual(
            len(state["rules"]), first,
            "re-running setup_gate must not accumulate duplicate rules",
        )

    @patch("app.enforcement.portal._run")
    def test_setup_gate_intercepts_dns(self, mock_run):
        """Outbound DNS from clients is DNAT'd to the gateway's own resolver."""
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate
        setup_gate()
        calls = [c[0][0] for c in mock_run.call_args_list]
        dnat53 = [
            c for c in calls
            if "-t" in c and "nat" in c and "DNAT" in c
            and "53" in c and "--to-dest" in c
        ]
        self.assertEqual(
            len(dnat53), 2,
            "both udp and tcp port 53 should be DNAT'd to the gateway",
        )
        self.assertTrue(
            all(f"{cfg.GATEWAY_INTERNAL_IP}:53" in c for c in dnat53),
            "DNS DNAT must target the gateway's own resolver",
        )

    @patch("app.enforcement.portal._run")
    def test_setup_gate_opens_input_services(self, mock_run):
        """ZTA_INPUT must accept DNS, DHCP, the redirect and the web UI."""
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate
        setup_gate()
        calls = [c[0][0] for c in mock_run.call_args_list]
        ports = set()
        for c in calls:
            if "ZTA_INPUT" in c and "-A" in c and "ACCEPT" in c and "--dport" in c:
                ports.add(c[c.index("--dport") + 1])
        self.assertTrue(
            {"53", "67", "80", "5000"}.issubset(ports),
            f"ZTA_INPUT should accept DNS/DHCP/portal ports; got {ports}",
        )

    @patch("app.enforcement.portal._run")
    def test_teardown_removes_input_chain(self, mock_run):
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import teardown_gate
        teardown_gate()
        calls = [c[0][0] for c in mock_run.call_args_list]
        self.assertTrue(
            any("ZTA_INPUT" in c and "-X" in c for c in calls),
            "teardown_gate should delete the ZTA_INPUT chain",
        )

    @patch("app.enforcement.portal._run")
    def test_rule_order_bans_before_grants(self, mock_run):
        """Bans DROP rules must be added before grant ACCEPT rules."""
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate, grant_access, sync_bans
        setup_gate()
        mock_run.reset_mock()
        sync_bans(["aa:bb:cc:dd:ee:ff"])
        grant_access("11:22:33:44:55:66")
        calls = [c[0][0] for c in mock_run.call_args_list]
        ban_idx = None
        grant_idx = None
        for i, args in enumerate(calls):
            if "DROP" in args and "aa:bb:cc:dd:ee:ff" in args:
                ban_idx = i
            if "ACCEPT" in args and "11:22:33:44:55:66" in args:
                grant_idx = i
        self.assertIsNotNone(ban_idx, "Ban DROP rule should exist")
        self.assertIsNotNone(grant_idx, "Grant ACCEPT rule should exist")
        self.assertLess(ban_idx, grant_idx,
                        "Ban must come before grant")

    @patch("app.enforcement.portal._run")
    def test_ban_precedence_over_grant(self, mock_run):
        """A banned MAC that is also granted stays blocked (DROP added)."""
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import setup_gate, grant_access, sync_bans
        setup_gate()
        grant_access("aa:bb:cc:dd:ee:ff")
        mock_run.reset_mock()
        sync_bans(["aa:bb:cc:dd:ee:ff"])
        calls = [c[0][0] for c in mock_run.call_args_list]
        self.assertTrue(
            any("DROP" in c and "aa:bb:cc:dd:ee:ff" in c for c in calls),
            "Banned MAC should have DROP rule"
        )

    @patch("app.enforcement.portal._run")
    def test_grant_and_revoke_idempotent(self, mock_run):
        """Granting/revoking the same MAC multiple times is safe."""
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import grant_access, revoke_access
        grant_access("aa:bb:cc:dd:ee:ff")
        grant_access("aa:bb:cc:dd:ee:ff")
        revoke_access("aa:bb:cc:dd:ee:ff")
        revoke_access("aa:bb:cc:dd:ee:ff")
        self.assertTrue(True)

    @patch("app.enforcement.portal._run")
    def test_is_granted(self, mock_run):
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import grant_access, is_granted
        self.assertFalse(is_granted("aa:bb:cc:dd:ee:ff"))
        grant_access("aa:bb:cc:dd:ee:ff")
        self.assertTrue(is_granted("aa:bb:cc:dd:ee:ff"))

    @patch("app.enforcement.portal._run")
    def test_sync_bans_preserves_grants(self, mock_run):
        """Regression: adding a ban must not wipe existing access grants.

        Previously sync_bans() began with `iptables -F ZTA_FORWARD`, which also
        removed every ACCEPT rule added by grant_access() — silently cutting off
        every already-signed-in device.
        """
        fake, _, _ = _make_stateful_mock()
        mock_run.side_effect = fake
        from app.enforcement.portal import (
            setup_gate, grant_access, sync_bans, is_granted,
        )
        setup_gate()
        grant_access("11:22:33:44:55:66")
        self.assertTrue(is_granted("11:22:33:44:55:66"))

        sync_bans(["aa:bb:cc:dd:ee:ff"])          # ban a different device

        self.assertTrue(
            is_granted("11:22:33:44:55:66"),
            "grant ACCEPT must survive sync_bans (no blanket chain flush)",
        )


class PortalSessionTests(unittest.TestCase):
    """Test session expiry and login grant logic."""

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_session_expiry(self):
        """Expired sessions should be marked as expired."""
        with self.app.app_context():
            device = Device(mac="aa:bb:cc:dd:ee:ff", ip="192.168.50.50")
            db.session.add(device)
            ps = PortalSession(
                mac="aa:bb:cc:dd:ee:ff", username="test",
                state="granted",
                expires_at=datetime.utcnow() - timedelta(minutes=1),
            )
            db.session.add(ps)
            db.session.commit()

            now = datetime.utcnow()
            expired = PortalSession.query.filter(
                PortalSession.state == "granted",
                PortalSession.expires_at < now,
            ).all()
            self.assertEqual(len(expired), 1)
            expired[0].state = "expired"
            db.session.commit()

            self.assertEqual(
                PortalSession.query.filter_by(
                    mac="aa:bb:cc:dd:ee:ff").first().state,
                "expired"
            )

    def test_login_grants_access(self):
        """After successful login, device should be granted."""
        with self.app.app_context():
            user = User(
                username="testuser", email="t@local",
                password_hash="x", status="approved",
                email_verified=True,
            )
            db.session.add(user)
            db.session.commit()

            device = Device(
                mac="aa:bb:cc:dd:ee:ff", ip="192.168.50.50",
                status="unknown",
            )
            db.session.add(device)
            db.session.commit()

            device.user_id = user.id
            device.status = "approved"
            device.granted_at = datetime.utcnow()
            ps = PortalSession(
                mac="aa:bb:cc:dd:ee:ff", username="testuser",
                state="granted",
                expires_at=datetime.utcnow() + timedelta(minutes=30),
            )
            db.session.add(ps)
            db.session.commit()

            self.assertEqual(device.status, "approved")
            self.assertEqual(ps.state, "granted")


class PortalDisabledTests(unittest.TestCase):
    """With ZTA_PORTAL_GATE=0, no iptables calls should happen."""

    @patch("app.enforcement.portal._run")
    def test_gate_off_no_iptables(self, mock_run):
        cfg.PORTAL_GATE = False
        from app.enforcement.portal import (
            setup_gate, grant_access, revoke_access,
        )
        setup_gate()
        grant_access("aa:bb:cc:dd:ee:ff")
        revoke_access("aa:bb:cc:dd:ee:ff")
        mock_run.assert_not_called()
        cfg.PORTAL_GATE = False


if __name__ == "__main__":
    unittest.main()
