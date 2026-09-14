"""Phase 8 — Full system integration test (10-step end-to-end checklist).

Drives the REAL assembled pipeline — feature extraction, adaptive baseline,
composite risk (identity/device/network/behavior), enforcement, traceback,
unban and Phase 7 escalation — via the same `run_scoring_window()` function
the daemon thread calls, feeding it synthetic per-window packet data.

Run:  ./venv/bin/python tests/test_integration.py
"""
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

# Throwaway DB (schema is current; rebuild so the scenario starts clean).
# Never the live server's zta.db — a soak-testing run.py may hold it open.
os.environ["ZTA_DB"] = "sqlite:///../db/zta_test.db"
_db = os.path.join(_ROOT, "db", "zta_test.db")
if os.path.exists(_db):
    os.remove(_db)

from datetime import datetime
from app import create_app
from app.capture.buffer import packet_queue, queue_lock
from app.models import db, Device, User, AuthEvent, Ban, RiskHistory, DNSLog, \
    BandwidthLog, DeviceBaseline
from app.enforcement.escalation import effective_ban_threshold
from app.enforcement.quarantine import active_quarantines
from app.policy.identity_risk import compute_identity_risk
from run import run_scoring_window
from app.baseline.config import MIN_SAMPLES_FOR_BASELINE

app = create_app()
app.config["TESTING"] = True
c = app.test_client()

MAC = "de:ad:be:ef:00:01"; IP = "192.168.1.50"     # the "bad" laptop
GOOD_MAC = "ca:fe:00:00:00:02"; GOOD_IP = "192.168.1.60"

GATEWAY_IP = "192.168.1.1"


def check(label, cond):
    print(("PASS" if cond else "FAIL"), "-", label)
    return bool(cond)


ok = []


def seed_device(mac, ip, status="unknown"):
    with app.app_context():
        d = Device(mac=mac, ip=ip, hostname=f"dev-{mac[-2:]}", status=status)
        db.session.add(d)
        db.session.commit()
        return d


def clear_and_inject(records):
    with queue_lock:
        packet_queue.clear()
        packet_queue.extend(records)


def pkt(mac, ip, dst="1.1.1.1", dport=443, proto=6, size=300, dns=None):
    return {"timestamp": datetime.utcnow(), "src_ip": ip, "dst_ip": dst,
            "proto": proto, "size": size, "dns_query": dns, "src_mac": mac,
            "dst_port": dport}


def idle_traffic(mac, ip):
    """Benign browsing-ish window: ~14 pkts, 4 flows, 3 dns queries."""
    recs = []
    for d in ("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"):
        recs.append(pkt(mac, ip, dst=d, dport=443, size=300))
    for dom in ("example.com", "cdn.example.com", "api.example.com"):
        recs.append(pkt(mac, ip, dst="8.8.8.8", dport=53, proto=17,
                        size=120, dns=dom))
    for _ in range(8):
        recs.append(pkt(mac, ip, dst="1.1.1.1", dport=443, size=200))
    return recs


def sweep_traffic(mac, ip, ports=range(400)):
    """Port-sweep-like fan-out blast to trip the behavior dimension."""
    recs = []
    for p in ports:
        recs.append(pkt(mac, ip, dst="10.0.0.9", dport=p, proto=6, size=120))
    return recs


# ---------------------------------------------------------------------------
# STEP 1 — fresh device connects: unknown / LOW / baseline learning
# ---------------------------------------------------------------------------
seed_device(MAC, IP)
seed_device(GOOD_MAC, GOOD_IP)
with app.app_context():
    d = Device.query.filter_by(mac=MAC).first()
    ok.append(check("1. fresh device discovered as 'unknown'",
                    d and d.status == "unknown" and d.risk_level == "LOW"))
    ok.append(check("1. baseline not yet learned (no data / still learning)",
                    d.baseline is None or not d.baseline.learning_complete))

# ---------------------------------------------------------------------------
# STEP 2 — register a user on that device -> pending -> verify -> approve -> login
# ---------------------------------------------------------------------------
r = c.post("/register", data={"username": "laptop1",
                              "email": "laptop1@lab.local",
                              "password": "pw12345", "confirm": "pw12345"})
ok.append(check("2. new user registered (pending)", r.status_code == 302))
with app.app_context():
    u = User.query.filter_by(username="laptop1").first()
    tok = u.verification_token
    ok.append(check("2. user status pending", u.status == "pending"))
r = c.get(f"/verify/{tok}")
ok.append(check("2. email verified", r.status_code == 200))
c.post("/login", data={"username": "admin", "password": "admin123"})
with app.app_context():
    uid = User.query.filter_by(username="laptop1").first().id
c.post(f"/admin/approve/{uid}")
c.get("/logout")
r = c.post("/login", data={"username": "laptop1", "password": "pw12345"})
ok.append(check("2. approved+verified user can log in", r.status_code == 302))

# ---------------------------------------------------------------------------
# STEP 3 — normal browsing for ~10 min: baseline learned, stays LOW
# ---------------------------------------------------------------------------
for _ in range(MIN_SAMPLES_FOR_BASELINE):
    with app.app_context():
        clear_and_inject(idle_traffic(MAC, IP) + idle_traffic(GOOD_MAC, GOOD_IP))
        run_scoring_window(app)
with app.app_context():
    b = DeviceBaseline.query.filter_by(mac=MAC).first()
    g = Device.query.filter_by(mac=GOOD_MAC).first()
    ok.append(check("3. baseline learned after 20 windows", b.learning_complete))
    ok.append(check("3. bad device stayed LOW during learning",
                    Device.query.filter_by(mac=MAC).first().risk_level == "LOW"))
    ok.append(check("3. good device stayed LOW during learning", g.risk_level == "LOW"))

# ---------------------------------------------------------------------------
# STEP 4 — nmap-style sweep + flagged DNS + failed logins -> HIGH -> auto-ban
# ---------------------------------------------------------------------------
with app.app_context():
    for _ in range(6):   # 6 real failed logins from the laptop IP
        db.session.add(AuthEvent(username="laptop1", ip=IP,
                                 result="Failed"))
    db.session.commit()
# One window: sweep + blocklisted domains + a suspicious port
attack = (sweep_traffic(MAC, IP) +
          [pkt(MAC, IP, dns="probe-1.doubleclick.net", dport=53, proto=17, size=100),
           pkt(MAC, IP, dns="probe-2.doubleclick.net", dport=53, proto=17, size=100),
           pkt(MAC, IP, dport=3389, size=200)] +
          idle_traffic(GOOD_MAC, GOOD_IP))
with app.app_context():
    clear_and_inject(attack)
    res = run_scoring_window(app)
    d = Device.query.filter_by(mac=MAC).first()
    g = Device.query.filter_by(mac=GOOD_MAC).first()
    ok.append(check("4. sweep window scored (bad device)", MAC in res))
    ok.append(check("4. composite crossed HIGH", d.total_risk >= 70 and d.risk_level == "HIGH"))
    ban = Ban.query.filter_by(mac=MAC, active=True).first()
    ok.append(check("4. auto-quarantine fired (active Ban row)", ban is not None))
    ok.append(check("4. device status -> banned", d.status == "banned"))
    ok.append(check("4. quarantine registered (recorded-only on Windows)",
                    MAC in active_quarantines()))
    ok.append(check("4. good device unaffected by attack window",
                    g.status != "banned" and g.risk_level == "LOW"))

# ---------------------------------------------------------------------------
# STEP 5 — traceback shows the full escalation
# ---------------------------------------------------------------------------
c.post("/login", data={"username": "admin", "password": "admin123"})
r = c.get(f"/admin/traceback/{MAC}")
tb = r.get_data(as_text=True)
ok.append(check("5. traceback page 200", r.status_code == 200))
ok.append(check("5. traceback shows escalation path", "Escalation path" in tb))
with app.app_context():
    n_hist = RiskHistory.query.filter_by(mac=MAC).count()
    ok.append(check("5. RiskHistory rows persisted for timeline", n_hist >= MIN_SAMPLES_FOR_BASELINE))

# ---------------------------------------------------------------------------
# STEP 6 — unban -> back to unknown, active ban cleared, quarantine released
# ---------------------------------------------------------------------------
r = c.post(f"/admin/unban/{MAC}")
ok.append(check("6. unban POST accepted", r.status_code == 302))
with app.app_context():
    d = Device.query.filter_by(mac=MAC).first()
    ban = Ban.query.filter_by(mac=MAC, active=True).first()
    ok.append(check("6. device reset to unknown (zero-trust)", d.status == "unknown"))
    ok.append(check("6. active ban closed", ban is None))
    ok.append(check("6. quarantine released",
                    MAC not in active_quarantines()))

# ---------------------------------------------------------------------------
# STEP 7 — repeat attack on the SAME device bans FASTER (escalation)
# ---------------------------------------------------------------------------
with app.app_context():
    n_prior = Ban.query.filter_by(mac=MAC).count()
    ok.append(check("7. one prior ban exists now", n_prior == 1))
    thr = effective_ban_threshold(70, MAC)
    ok.append(check("7. effective threshold lowered to 0.75x (=52.5)", thr == 52.5))
# Second "attack": identity + network risk only (no behavior spike). Total
# lands between the escalated 52.5 and the base 70 — so a first-timer at the
# base threshold would NOT be banned, but this repeat offender IS. (No sweep:
# after step 4 the sweep got folded into the baseline, the documented
# boiling-frog effect, so behavior is intentionally not the driver here.)
moderate = (idle_traffic(MAC, IP) +
            [pkt(MAC, IP, dns="q1.doubleclick.net", dport=53, proto=17, size=100),
             pkt(MAC, IP, dns="q2.doubleclick.net", dport=53, proto=17, size=100),
             pkt(MAC, IP, dport=3389, size=200)])
with app.app_context():
    # extra failed logins keep identity elevated for this window
    db.session.add(AuthEvent(username="laptop1", ip=IP, result="Failed"))
    db.session.add(AuthEvent(username="laptop1", ip=IP, result="Failed"))
    db.session.commit()
    clear_and_inject(moderate)
    res = run_scoring_window(app)
    d = Device.query.filter_by(mac=MAC).first()
    ban = Ban.query.filter_by(mac=MAC, active=True).first()
    total = res[MAC]["total"]
    ok.append(check("7. second attack total between 52.5 and 70",
                    52.5 <= total < 70))
    ok.append(check("7. repeat offender auto-banned below base threshold",
                    d.status == "banned" and ban is not None))
    ok.append(check("7. ban reason cites escalation threshold",
                    ban and "prior bans" in ban.reason))

# ---------------------------------------------------------------------------
# STEP 8 — brute-force vs /login spikes identity independently of behavior
# ---------------------------------------------------------------------------
for _ in range(3):
    c.post("/login", data={"username": "admin", "password": "nope"},
           environ_overrides={"REMOTE_ADDR": IP})
with app.app_context():
    id_risk = compute_identity_risk(IP)
    ok.append(check("8. identity risk climbed from failed logins", id_risk >= 15))
    clear_and_inject(idle_traffic(MAC, IP) + idle_traffic(GOOD_MAC, GOOD_IP))
    res = run_scoring_window(app)
    d = Device.query.filter_by(mac=MAC).first()
    # device is banned at this point (step 7); still scored, slight rise from baseline
    ok.append(check("8. identity dimension reflected in score", d.identity_risk >= 5))

# ---------------------------------------------------------------------------
# STEP 9 — blocklisted DNS query persisted + flagged
# ---------------------------------------------------------------------------
with app.app_context():
    flagged = DNSLog.query.filter_by(mac=MAC, flagged=True).all()
    ok.append(check("9. DNSLog persisted flagged queries", len(flagged) >= 2))
    flagged_domains_set = {r.domain for r in flagged}
    ok.append(check("9. blocklisted domains appear in DNS audit trail",
                    any("doubleclick.net" in dom for dom in flagged_domains_set)))
    # Device.flagged_domains is the live snapshot of the *latest* window (later
    # idle windows overwrite it) — the durable record is the RiskHistory trail.
    hist_flags = [r.flagged_domains for r in
                  RiskHistory.query.filter_by(mac=MAC).all() if r.flagged_domains]
    ok.append(check("9. flagged domains recorded in risk history",
                    any("doubleclick.net" in f for f in hist_flags)))

# ---------------------------------------------------------------------------
# STEP 10 — the well-behaved device never left LOW the entire run
# ---------------------------------------------------------------------------
with app.app_context():
    good = Device.query.filter_by(mac=GOOD_MAC).first()
    ok.append(check("10. good device status never changed", good.status == "unknown"))
    ok.append(check("10. good device final level LOW", good.risk_level == "LOW"))
    ok.append(check("10. good device never banned",
                    Ban.query.filter_by(mac=GOOD_MAC).count() == 0))

# ---------------------------------------------------------------------------
# Performance / resource proxy (lightweight claims for the report)
# ---------------------------------------------------------------------------
with app.app_context():
    t0 = time.perf_counter()
    clear_and_inject(attack)
    run_scoring_window(app)
    dt_ms = (time.perf_counter() - t0) * 1000
    db_size = os.path.getsize(_db)
    hist = RiskHistory.query.count()
    n_dns = DNSLog.query.count()
    n_bw = BandwidthLog.query.count()
print(f"[perf] scoring window (400-packet sweep, 2 devices, all persistence): "
      f"{dt_ms:.0f} ms")
print(f"[perf] db size: {db_size/1024:.0f} KiB; "
      f"RiskHistory rows: {hist}; DNSLog rows: {n_dns}; "
      f"BandwidthLog rows: {n_bw}")

print()
print("TOTAL:", sum(ok), "/", len(ok), "passed")
print("ALL PASS" if all(ok) else "SOME FAILED")