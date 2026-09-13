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