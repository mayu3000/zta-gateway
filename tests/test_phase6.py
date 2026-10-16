"""Phase 6 smoke test — registration, approval queue, admin dashboard, auth events.

Run from anywhere:  ./venv/bin/python tests/test_phase6.py
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

# Throwaway DB — never the live server's zta.db (which a soak-testing run.py
# may hold open), so this suite is self-contained and re-runnable. A stale
# temp DB from an earlier run would otherwise fail duplicate-user (alice) checks.
os.environ["ZTA_DB"] = "sqlite:///../db/zta_test.db"
os.environ.setdefault("ZTA_ENFORCE", "recorded")  # no iptables under tests
_db = os.path.join(_ROOT, "db", "zta_test.db")
if os.path.exists(_db):
    os.remove(_db)

from app import create_app
from app.models import db, User, AuthEvent, Ban, Device

app = create_app()
app.config["TESTING"] = True
c = app.test_client()


def check(label, cond):
    print(("PASS" if cond else "FAIL"), "-", label)
    return bool(cond)


ok = []

# 1. Admin auto-seeded with status=approved, is_admin=True
with app.app_context():
    admin = User.query.filter_by(username="admin").first()
    ok.append(check("admin seeded & approved",
                    admin and admin.status == "approved" and admin.is_admin))

# 2. Unauthenticated /admin redirects to login
r = c.get("/admin")
ok.append(check("/admin redirects to login when logged out",
                r.status_code == 302 and "/login" in r.headers["Location"]))

# 3. Admin login redirects to /admin
r = c.post("/login", data={"username": "admin", "password": "admin123"})
ok.append(check("admin login -> 302", r.status_code == 302))
ok.append(check("redirect to admin_dashboard",
                r.headers["Location"].endswith("/admin")))

# 4. /admin renders tiles + tables
r = c.get("/admin")
body = r.get_data(as_text=True)
ok.append(check("/admin 200", r.status_code == 200))
ok.append(check("tile: Connected Devices", "Connected Devices" in body))
ok.append(check("tile: Pending Approvals", "Pending Approvals" in body))
ok.append(check("tile: Active Bans", "Active Bans" in body))
ok.append(check("devices table", "<th>Total</th>" in body))
ok.append(check("auth events table", "Recent Authentication Events" in body))
ok.append(check("auto-refresh 10s", 'refresh" content="10"' in body))
ok.append(check("nav bar", "Pending Users" in body and "Logout" in body))

# 5. /dashboard backward-compat redirect
r = c.get("/dashboard")
ok.append(check("/dashboard redirects to /admin",
                r.status_code == 302 and r.headers["Location"].endswith("/admin")))

# 6. Register a new user -> pending
r = c.post("/register", data={"username": "alice",
                              "email": "alice@example.com",
                              "password": "pw12345",
                              "confirm": "pw12345"})
ok.append(check("register alice -> redirect", r.status_code == 302))

with app.app_context():
    alice = User.query.filter_by(username="alice").first()
    ok.append(check("alice created pending",
                    alice and alice.status == "pending" and not alice.is_admin))

# 7. Pending login blocked (Phase 7 also requires email verify, so this is 403)
c.get("/logout")
r = c.post("/login", data={"username": "alice", "password": "pw12345"})
ok.append(check("pending user login blocked (403)", r.status_code == 403))

# 8. Admin sees pending list
c.post("/login", data={"username": "admin", "password": "admin123"})
r = c.get("/admin/pending")
body = r.get_data(as_text=True)
ok.append(check("pending page shows alice", "alice" in body))

# 9. Approve alice
with app.app_context():
    alice_id = User.query.filter_by(username="alice").first().id
c.post(f"/admin/approve/{alice_id}")
r = c.get("/admin/pending")
body = r.get_data(as_text=True)
ok.append(check("alice approved (no longer pending)", "alice" not in body))

# 10. Register second user then reject -> blocked forever
c.get("/logout")
c.post("/login", data={"username": "admin", "password": "admin123"})
c.post("/register", data={"username": "mallory",
                          "email": "mallory@example.com",
                          "password": "pw12345",
                          "confirm": "pw12345"})
with app.app_context():
    mallory_id = User.query.filter_by(username="mallory").first().id
c.post(f"/admin/reject/{mallory_id}")
c.get("/logout")
r = c.post("/login", data={"username": "mallory", "password": "pw12345"})
ok.append(check("rejected user login blocked (403)", r.status_code == 403))

# 11. Duplicate / mismatched registration handling
c.get("/logout")
c.post("/login", data={"username": "admin", "password": "admin123"})
r = c.post("/register", data={"username": "alice", "email": "x@y.com",
                              "password": "pw", "confirm": "pw"})
ok.append(check("duplicate username rejected (400)", r.status_code == 400))
r = c.post("/register", data={"username": "bob", "email": "alice@example.com",
                              "password": "pw", "confirm": "pw"})
ok.append(check("duplicate email rejected (400)", r.status_code == 400))
r = c.post("/register", data={"username": "carol", "email": "c@y.com",
                              "password": "pw1", "confirm": "pw2"})
ok.append(check("mismatched passwords rejected (400)", r.status_code == 400))

# 12. Auth events recorded + rendered (color classes present)
c.get("/logout")
c.post("/login", data={"username": "admin", "password": "WRONG"})    # Failed
c.post("/login", data={"username": "admin", "password": "admin123"})  # Success
r = c.get("/admin")
body = r.get_data(as_text=True)
ok.append(check("auth event row success class", 'class="success"' in body))
ok.append(check("auth event row failed class", 'class="failed"' in body))

# 13. Traceback page — seed a device deterministically so these two checks
# always run (Device.query.first() on a leftover DB made the count 26, on an
# empty DB it skipped to 24 — the reported total must not depend on ambient
# DB state).
with app.app_context():
    db.session.add(Device(mac="de:ad:be:ef:00:99", ip="192.168.1.99",
                          hostname="trace-test", status="unknown"))
    db.session.commit()
r = c.get("/admin/traceback/de:ad:be:ef:00:99")
ok.append(check("traceback page 200", r.status_code == 200))
ok.append(check("traceback nav bar",
                "Pending Users" in r.get_data(as_text=True)))

print()
print("TOTAL:", sum(ok), "/", len(ok), "passed")
print("ALL PASS" if all(ok) else "SOME FAILED")