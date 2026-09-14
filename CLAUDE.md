# ZTA Gateway

Zero Trust Architecture gateway for the home LAN: discovers devices via ARP
and (in later phases) scores them for risk. Phase 1 = login + live device
inventory dashboard. This is a defensive/security-monitoring tool for the
user's own network.

## Environment / platform constraints (Windows 11)

- This machine has **no Windows-native CPython** (`py` launcher absent, no
  `C:\Python*`, no AppData Python). The only interpreter is the MSYS2/MinGW
  build at `C:\msys64\mingw64\bin\python.exe`, which has **no system pip**.
- All project work runs inside the **venv**: `venv/bin/python` (MinGW-style
  venv, `bin/` not `Scripts/`). Use it for everything:
  `./venv/bin/python -m pip ...`, `./venv/bin/python run.py`.
- Do NOT recreate the venv with a system Python; it cannot install pip.
- Scapy raw sockets depend on **Npcap** (currently installed + service
  RUNNING). No `sudo` needed on Windows.
- GitHub Desktop workflows / `git` come from Git for Windows; the shell is
  Git Bash (POSIX paths).

## Run / verify

- Server: `./venv/bin/python run.py` → http://127.0.0.1:5000/login
- Default login: `admin` / `admin123`.
- Live scan only: `./venv/bin/python app/discovery.py`
- DB: SQLite at `db/zta.db` (relative URI `sqlite:///../db/zta.db` resolves
  from the `app/` package dir up to `db/`).

## Operating notes for Claude

- Scapy ARP broadcast on this box only captures the host itself (MinGW
  Python + Npcap quirk). The working sensor is OS-native: broadcast ping
  + `arp -a` parse, ~2s, reliable. See `app/discovery.py`.
- Devices with `status="unknown"` are auto-approved for Phase 1; risk scoring
  comes in Phase 2+. Keep Phase 1 minimal and working.
- After any pip change, refresh `requirements.txt` (`pip freeze > requirements.txt`).

## Phase 2 (traffic capture + risk scoring)

- **Passive sniffing works** on this Npcap stack (unlike active ARP). Only the
  machine's own traffic is visible; scoring attributes outbound src IPs →
  Device MACs (with L2 src_mac fallback). Remote/inbound srcs are skipped.
- `app/capture/sniffer.py` auto-picks the Wi-Fi iface; `filter="ip"` BPF set.
- Scan signal = **unique_flow_count** (dst ip:port pairs). Tuned so browsing
  ~LOW (~14) but a 500-port sweep → HIGH (82). Thresholds in
  `app/baseline/thresholds.py`; weights in `app/policy/scoring.py`.
- Scores use rolling 30s windows → decay naturally once activity stops.
- Schema changed (risk_score/risk_level on Device). No migrations: to upgrade,
  delete `db/zta.db` and let `create_all()` rebuild (loses rows + reseeds admin).
- Testing: nmap is NOT installed; the scan simulation uses a Python socket
  port-probe sweep, which the detector catches the same way.

## Phase 3 (adaptive per-device baseline)

- `DeviceBaseline` (one row/device) holds Welford online mean/m2 for
  packet_count, byte_count, unique_flow_count, dns_query_count — O(1) memory,
  no raw history. Learn period = 20 windows (~10 min, `baseline/config.py`).
- Scoring is **z-score vs the device's own baseline** (`policy/scoring.py`):
  during learning → (5, {"status": "learning"}), non-punitive. Post-learning a
  window's deviation in std devs drives the score; z >= 3.5 contributes full
  weight per feature.
- **P3 beats P2 (verified):** a legitimately heavy device (streaming-like)
  scores P3 32/LOW vs P2 43/MEDIUM (P2 false-positived); an anomalous jump on a
  light device scores P3 98/HIGH vs P2 43/MEDIUM.
- Gotcha: a new `DeviceBaseline(...)` object has `None` for defaulted columns
  (SQLAlchemy defaults apply at INSERT) — `update_baseline` initializes them
  explicitly, else the first Welford update crashes on `None + 1`.
- **Known limitation (document for report):** the baseline updates every
  window, *including anomalous ones*, so a slow sustained attack can gradually
  "train itself in" ("boiling frog"). Future work: freeze baseline updates
  during HIGH-risk windows / use a trimmed or exponentially-weighted estimate.
- Schema changed again (device_baseline table) → delete `db/zta.db` to rebuild.

## Phase 4 (composite risk engine)

- `Device` carries four sub-scores + composite: `identity_risk`, `device_risk`,
  `network_risk`, `behavior_risk`, `total_risk` (= weighted sum of the four),
  plus `flagged_domains` (csv) and `fan_out` (unique flows). Dashboard table is
  the Fig.5 layout: Identity | Device | Network | Behavior | Total | Level |
  Flagged Domains | Fan-out | Baseline, colored salmon/khaki/lightgreen by level.
- Weights: identity .20, device .20, network .25, behavior .35
  (`app/policy/composite.py`).
- **Identity** (`policy/identity_risk.py`): count of `AuthEvent` Failed rows for
  the device's IP in the last 15 min × 15, capped 100. Login route records every
  attempt from `request.remote_addr` (a real wrong-password burst → 75).
- **Device** (`policy/device_risk.py`): unknown=60, banned=100, approved+age<24h
  =30, approved+older=0. Router row marked approved in the DB to demo.
- **Network** (`policy/network_risk.py`): blocklist = `app/policy/blocklist.txt`
  (StevenBlack hosts, gitignored) with a small `_BUILTIN` seed if the file is
  absent; parent-domain suffix matching (block `doubleclick.net` matches
  `x.doubleclick.net`). Suspicious ports {23,445,3389,6667} add 20.
  Scored `min(flagged*40,80) + min(port_hits*20,20)`.
- **Behavior** = Phase 3 z-score engine, now keyed per-feature weights
  {flow 40, packet 20, byte 20, dns 20} — see Phase 3 section.
- **Live verification (all 4 dimensions, uncommitted-at-write-time):**
  - Identity: 8 real failed logins + 5 injected → laptop I=75.
  - Device: unknown devices=60, router (approved)=30.
  - Network: MUST force an **uncached** blocklisted query or the OS DNS cache
    serves it with no packet → sniffer never sees it. Random subdomain
    `probe-<rand>.doubleclick.net` (NXDOMAIN) got captured → N=80, flags
    `['ncc.avast.com.', 'probe-….doubleclick.net.']`. Avast AV telemetry
    (ncc.avast.com) is a live noise source — it flags every window it appears.
  - Behavior: locked at 5 until baseline LEARNED (20 samples ≈ 10 min). After
    learning, a 300-port sweep → fan_out 15→144, B spiked 18→37 (single window)
    → settled 27; total went LOW→MEDIUM. Sweep may straddle a window boundary
    (300 ports × 0.1s timeout ≈ 30s) — peak coupling to the sweep is capture-timing
    dependent; the previous window's leftovers also feed the next scoring run.
- **Learning-period gotcha:** during learning behavior contributes only 5, so a
  device mid-baseline can look LOW even under attack (by design, non-punitive).
  Once total composes four live dimensions, MEDIUM at idle is normal when
  identity is elevated (75×.2 + 60×.2 + 35×.25 → ≈ 36).
- Blocklist is regenerable: `curl
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` drops it
  in `app/policy/blocklist.txt` (parse the `0.0.0.0` lines). Gitignored.
- Schema changed again (four risk cols + flagged_domains + fan_out + auth_event
  table) → delete `db/zta.db` to rebuild.

## Phase 5 (enforcement: quarantine/block + threat traceback)

- **Ban tracking** (`app/models.py`): `Ban` (mac, reason, risk_score_at_ban,
  since, active, unbanned_at) powers the Fig.6 "Active Bans" table; `RiskHistory`
  (one row/device/30s window of the four sub-scores + total + flagged domains)
  is the traceback audit trail.
- **ARP quarantine** (`app/enforcement/quarantine.py`): Option B — a daemon
  thread spoofs ARP replies (gateway → bogus MAC) at the target every 2s to
  cut it off from routing. Windows/MinGW active injection is unreliable, so
  `INJECTION_AVAILABLE` is False here: quarantine is still recorded (DB Ban +
  forensic log + status=banned), spoofing is skipped, and the log says which
  mode ran. True wire isolation is demoable on a Linux VM.
- **Scoring loop** (`run.py`): `HIGH_RISK_BAN_THRESHOLD = 70`. Each window
  writes a `RiskHistory` row, logs risk-level transitions (LOW→MEDIUM, …), and
  on first cross of 70 inserts a `Ban` + sets `device.status='banned'`.
- **Unban** (`app/routes.py` POST `/admin/unban/<mac>`): zero-trust reset —
  does NOT restore approval, sets status back to `unknown` so the device
  re-earns trust. Logs `UNBAN`.
- **Traceback** (`app/traceback/tracer.py` + `/admin/traceback/<mac>`):
  timeline of RiskHistory rows, `first_seen_anomaly` (first total≥35),
  `escalation_path` (totals in order), `final_action` (latest ban).
- **Forensic log** (`app/logging/forensic.py`): JSON lines → `logs/forensic.log`
  at QUARANTINE / UNBAN / RISK_TRANSITION / STATUS_CHANGE. Independent of DB.
- Schema changed again (ban + risk_history tables) → delete `db/zta.db` to
  rebuild.

## Phase 6 (admin dashboard polish & live monitoring)

- **User model extended** (`app/models.py`): `email`, `status` (pending/
  approved/rejected), `registered_at`, `is_admin` added to `User`. New
  registrations default to `status="pending"` until an admin approves.
- **Self-registration** (`POST /register` + `register.html`): username + email
  + password (with confirm). Creates a pending user, flashes confirmation,
  redirects to login. Uniqueness enforced on both username and email.
- **Admin approval queue** (`/admin/pending` + `pending_users.html`, Fig.4):
  pending users with Approve / Reject buttons; both log forensic events
  (`USER_APPROVED` / `USER_REJECTED`).
- **Login blocks non-approved users**: correct password but `status !=
  "approved"` → HTTP 403 "Your account is pending admin approval."
- **Admin dashboard** (`/admin` + `admin.html`, Fig.5 + Fig.6):
  - Summary tile cards: Total Devices, High Risk, Medium Risk, Active Bans,
    Pending Approvals (links to pending page).
  - Full connected-devices table (all risk columns + traceback links).
  - Active Bans table with Unban buttons.
  - Recent Authentication Events (last 20) with `.success`/`.failed` row
    classes (green/red).
  - 10-second auto-refresh via `<meta http-equiv="refresh" content="10">`.
- **Consistent nav bar** on every page: Dashboard | Pending Users (red badge
  = pending count) | Logout.
- **Backwards compat**: `/dashboard` 302-redirects to `/admin`; old
  `dashboard.html` removed — `admin.html` is the single source of truth.
- **Admin seed updated** (`app/__init__.py`): default admin now has
  `email="admin@local"`, `status="approved"`, `is_admin=True`.
- Schema changed again (new User columns) → delete `db/zta.db` to rebuild.
- Verified: 26-test smoke run (register → pending → approve → login → tiles
  → bans → events) all passing.

## Phase 7 (auth upgrade, captive portal, network risk extension)

- **Email verification** (`app/mail.py`): `User.email_verified`,
  `verification_token` (one-time). Registration generates a `secrets`
  token and calls `send_verification_email(...)`.
  - **LAB MODE delivery**: real SMTP (Flask-Mail) only when installed AND
    `MAIL_SERVER` is configured. Otherwise the link is printed to the server
    console and written to the forensic log (`EMAIL_VERIFY`) — the full
    flow works without a live mail server. `get_last_verification_url()`
    exposes the latest link for tests/demos.
  - `/verify/<token>` sets `email_verified=True` and clears the token (use
    once). Login now requires `email_verified` AND `status == "approved"`.
  - Admin seed now also sets `email_verified=True`.
- **Admin roles** (`app/routes.py`): `@admin_required` decorator on every
  `/admin/*` route — any logged-in non-admin gets 403. Closes the Phase 6
  gap where any user could hit pending/unban/traceback endpoints.
- **Captive portal** (`app/middleware.py`): `before_request` hook gates
  *known* unapproved devices (matched by `request.remote_addr` → Device.ip)
  → redirect to `/login`. Whitelist: `/login /register /verify /logout
  /admin /static`. Admins and unknown IPs pass through. True network-level
  DNS-hijack captive portal documented as future work.
- **DNS audit trail** (`DNSLog` model): every domain each device queries per
  30s window is persisted, tagged `flagged` via
  `network_risk.is_blocked_domain`. Powers a "Top domains" report:
  `GROUP BY domain ORDER BY COUNT(*) DESC`.
- **Bandwidth tracking** (`BandwidthLog` model): per-device byte totals per
  window (daily/hourly rollups derivable).
- **Escalation rules** (`app/enforcement/escalation.py`): prior bans 0→1.0,
  1→0.75, 2+→0.5 multiplier on the ban threshold. `effective_ban_threshold(
  base, mac)` in run.py; repeat offenders get quarantined at a lower score.
- Schema changed again (User verify cols + dns_log + bandwidth_log tables) →
  delete `db/zta.db` to rebuild.
- Verified: 34-test smoke run — email verify flow (blocked → verify →
  allowed), admin-only 403s for non-admin, captive-portal redirect/whitelist,
  escalation multipliers, DNSLog + BandwidthLog writes.

## Phase 8 (integration testing, documentation, final review)

- **Test suite** (`tests/`): `test_phase6.py` (26 checks), `test_phase7.py`
  (34 checks), `test_integration.py` (35 checks — the full 10-step E2E).
  All run standalone with `./venv/bin/python tests/<file>.py`, deleting and
  rebuilding `db/zta.db` on each run.
- **Testability refactor** (`run.py`): the scoring-loop body moved into
  `run_scoring_window(app)` — the same function the daemon thread calls — so
  tests drive the *real* pipeline with synthetic per-window packet buffers
  (`packet_queue`) instead of waiting on wall-clock 30s windows or real
  traffic.
- **Integration scenario** drives detection → baseline learning (20 windows)
  → composite scoring → auto-ban (total 90 HIGH) → traceback → unban →
  repeat attack (total 65) **banned at the escalated 0.75× threshold** —
  directly proving escalation matters. An idle control device never left LOW.
- **Performance evidence**: one scoring window (400-packet sweep, 2 devices,
  all persistence) ≈ 69 ms; entire scenario ≈ 68 KiB SQLite. Welford keeps
  zero raw history → O(1) memory per device.
- **Black Book** (`docs/BLACKBOOK.md`): full report mapped to the Review-1
  sections — problem statement, literature (Welford, StevenBlack, NIST
  800-207, UEBA), system architecture (laptop not Pi; Option A/B), per-phase
  implementation, integration + per-dimension test tables, adaptive-vs-fixed
  results, honest limitations (boiling frog, DNS-cache blind spot, ARP
  recorded-only on Windows, Wi-Fi AP passthrough), future scope, conclusion,
  references.
- **Optional SMTP** (real email delivery): `Flask-Mail` install was flaky on
  this MinGW venv (`pip install flask-mail` → distribution not found);
  `app/mail.py` detects it at import and falls back to console + forensic-log
  delivery. Install `Flask-Mail` + set `MAIL_SERVER` to enable it.
- Tagged `v1.0-final`.