"""Phase 7 smoke test — email verification, admin roles, captive portal, escalation, DNS/bandwidth logging.

Run from anywhere:  ./venv/bin/python tests/test_phase7.py
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

# Throwaway DB — never the live server's zta.db (which a soak-testing run.py
# may hold open), so this suite is self-contained and re-runnable. A stale
# temp DB from an earlier run would otherwise fail duplicate alice / duplicate
# portal device (aa:bb:cc:dd:ee:f2) AND leave get_last_verification_url()
# returning None, which crashes sum(ok) below.
os.environ["ZTA_DB"] = "sqlite:///../db/zta_test.db"
os.environ.setdefault("ZTA_ENFORCE", "recorded")  # no iptables under tests
_db = os.path.join(_ROOT, "db", "zta_test.db")
if os.path.exists(_db):
    os.remove(_db)

from app import create_app
from app.models import db, User, AuthEvent, Ban, Device, DNSLog, BandwidthLog
from app.enforcement.escalation import get_escalation_multiplier, effective_ban_threshold
from app.mail import get_last_verification_url

app = create_app()
app.config["TESTING"] = True

def check(label, cond):
    print(("PASS" if cond else "FAIL"), "-", label)
    return cond

ok = []

# --- 1. Admin seeded correctly -----------------------------------------------
with app.app_context():
    admin = User.query.filter_by(username="admin").first()
    ok.append(check("admin seeded with is_admin=True",
                    admin and admin.is_admin and admin.status == "approved"))

# --- 2. Unauthenticated /admin redirects to login ----------------------------
c = app.test_client()
r = c.get("/admin")
ok.append(check("/admin redirects when logged out",
                r.status_code == 302 and "/login" in r.headers["Location"]))

# --- 3. Admin login -> dashboard with tiles -----------------------------------
r = c.post("/login", data={"username": "admin", "password": "admin123"})
ok.append(check("admin login -> 302", r.status_code == 302))
r = c.get("/admin")
body = r.get_data(as_text=True)
ok.append(check("/admin renders tiles", "Connected Devices" in body and "Active Bans" in body))
ok.append(check("admin nav bar", "Pending Users" in body))

# --- 4. Register alice -> verification token generated + console URL logged ----
c.get("/logout")
r = c.post("/register", data={"username": "alice", "email": "alice@lab.local",
                              "password": "pw12345", "confirm": "pw12345"})
ok.append(check("register alice -> redirect", r.status_code == 302))
verify_url = get_last_verification_url()
ok.append(check("verification URL generated (LAB MODE)",
                verify_url and "verify" in verify_url))

with app.app_context():
    alice = User.query.filter_by(username="alice").first()
    ok.append(check("alice created with email_verified=False and token",
                    bool(alice and not alice.email_verified and alice.verification_token)))

# --- 5. Alice login BEFORE verify -> blocked -----------------------------------
c.get("/logout")
r = c.post("/login", data={"username": "alice", "password": "pw12345"})
ok.append(check("alice login blocked pre-verify (403)", r.status_code == 403))

# --- 6. Verify alice's token -> email_verified = True -------------------------
with app.app_context():
    token = User.query.filter_by(username="alice").first().verification_token
r = c.get(f"/verify/{token}")
ok.append(check("verify endpoint 200", r.status_code == 200))
ok.append(check("verify page shows success message",
                "verified" in r.get_data(as_text=True).lower()))
with app.app_context():
    alice = User.query.filter_by(username="alice").first()
    ok.append(check("alice.email_verified = True", alice.email_verified))
    ok.append(check("verification token cleared after use", not alice.verification_token))

# --- 7. Alice login BEFORE approval -> 403 pending -----------------------------
r = c.post("/login", data={"username": "alice", "password": "pw12345"})
ok.append(check("alice login blocked pre-approval (403)", r.status_code == 403))

# --- 8. Admin approves alice --------------------------------------------------
c.post("/login", data={"username": "admin", "password": "admin123"})
with app.app_context():
    alice_id = User.query.filter_by(username="alice").first().id
r = c.post(f"/admin/approve/{alice_id}")
ok.append(check("admin approves alice -> 302", r.status_code == 302))

# --- 9. Alice login -> success ------------------------------------------------
c.get("/logout")
r = c.post("/login", data={"username": "alice", "password": "pw12345"})
ok.append(check("alice login succeeds post-approval", r.status_code == 302))

# --- 10. Alice hits /admin -> 403 (not admin) ---------------------------------
r = c.get("/admin")
ok.append(check("alice /admin blocked (403)", r.status_code == 403))
r = c.get("/admin/pending")
ok.append(check("alice /admin/pending blocked (403)", r.status_code == 403))

# --- 11. Captive portal: unknown device with known IP -> redirected -----------
c.get("/logout")
c.post("/login", data={"username": "admin", "password": "admin123"})
with app.app_context():
    db.session.add(Device(mac="aa:bb:cc:dd:ee:f2", ip="192.168.1.99",
                          hostname="portal-test", status="unknown"))
    db.session.commit()
# Request from that IP to a non-whitelisted path should be redirected
r = c.get("/", environ_overrides={"REMOTE_ADDR": "192.168.1.99"})
ok.append(check("captive portal redirects unknown device",
                r.status_code == 302 and "/login" in r.headers["Location"]))
# Request to /admin should still pass (whitelisted)
r = c.get("/admin", environ_overrides={"REMOTE_ADDR": "192.168.1.99"})
ok.append(check("captive portal whitelists /admin", r.status_code == 200))

# --- 12. Captive portal: approved device -> allowed ----------------------------
with app.app_context():
    dev = Device.query.filter_by(mac="aa:bb:cc:dd:ee:f2").first()
    dev.status = "approved"
    db.session.commit()
# No "/" route exists, so pass-through gives 404 — the important thing is the
# portal did NOT redirect to login.
r = c.get("/", environ_overrides={"REMOTE_ADDR": "192.168.1.99"})
ok.append(check("captive portal allows approved device (no redirect)",
                r.status_code != 302))

# --- 13. Captive portal: unknown IP not in Device DB -> allowed ---------------
r = c.get("/", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
ok.append(check("captive portal allows unknown IP (no redirect)",
                r.status_code != 302))

# --- 14. Escalation multiplier ------------------------------------------------
with app.app_context():
    ok.append(check("escalation 0 prior bans = 1.0", get_escalation_multiplier("xx:xx") == 1.0))
    db.session.add(Ban(mac="xx:xx", reason="test1", risk_score_at_ban=75))
    db.session.commit()
    ok.append(check("escalation 1 prior ban = 0.75",
                    get_escalation_multiplier("xx:xx") == 0.75))
    db.session.add(Ban(mac="xx:xx", reason="test2", risk_score_at_ban=60))
    db.session.commit()
    ok.append(check("escalation 2 prior bans = 0.5",
                    get_escalation_multiplier("xx:xx") == 0.5))
    ok.append(check("effective threshold 70 * 0.5 = 35.0 (2 prior bans)",
                    effective_ban_threshold(70, "xx:xx") == 35.0))
    ok.append(check("effective threshold 70 * 1.0 = 70.0 (0 prior bans)",
                    effective_ban_threshold(70, "zz:zz") == 70.0))

# --- 15. DNSLog writes ---------------------------------------------------------
with app.app_context():
    db.session.add(DNSLog(mac="aa:bb:cc:dd:ee:ee", domain="example.com", flagged=False))
    db.session.add(DNSLog(mac="aa:bb:cc:dd:ee:ee",
                          domain="ads.doubleclick.net", flagged=True))
    db.session.commit()
    logs = DNSLog.query.filter_by(mac="aa:bb:cc:dd:ee:ee").all()
    ok.append(check("DNSLog rows written", len(logs) == 2))
    ok.append(check("DNSLog flagged domain", any(l.flagged for l in logs)))

# --- 16. BandwidthLog writes --------------------------------------------------
with app.app_context():
    db.session.add(BandwidthLog(mac="aa:bb:cc:dd:ee:ee", bytes_sent=50000))
    db.session.commit()
    bw = BandwidthLog.query.filter_by(mac="aa:bb:cc:dd:ee:ee").first()
    ok.append(check("BandwidthLog written", bw and bw.bytes_sent == 50000))

# --- 17. Unauthenticated /admin/pending redirect + non-admin 403 ---------------
c.get("/logout")
r = c.get("/admin/pending")
ok.append(check("/admin/pending redirects when logged out",
                r.status_code == 302))
c.post("/login", data={"username": "alice", "password": "pw12345"})
r = c.get("/admin/pending")
ok.append(check("alice GET /admin/pending blocked (403)", r.status_code == 403))

# --- 18. Duplicate registration handling still works --------------------------
c.get("/logout")
c.post("/login", data={"username": "admin", "password": "admin123"})
r = c.post("/register", data={"username": "alice", "email": "new@x.com",
                              "password": "pw", "confirm": "pw"})
ok.append(check("duplicate username rejected (400)", r.status_code == 400))
r = c.post("/register", data={"username": "bob", "email": "alice@lab.local",
                              "password": "pw", "confirm": "pw"})
ok.append(check("duplicate email rejected (400)", r.status_code == 400))

print()
print("TOTAL:", sum(ok), "/", len(ok), "passed")
print("ALL PASS" if all(ok) else "SOME FAILED")