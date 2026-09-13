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