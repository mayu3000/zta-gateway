# HANDOFF — ZTA Gateway (resume notes)

_Saved 2026-10-16. This file lives on `feature/demo-monitoring`; `git log -1`
on each branch shows its head commit._

## Branch map

| Branch | Contents | Head |
|---|---|---|
| `main` (tag `v1.0-final`) | Option **B** submission — ARP quarantine, recorded-only on Windows | `1f9399a` |
| `feature/option-a-inline` | Option **A** inline gateway — iptables DROP, Scapy ARP discovery, Linux neighbour table, Kali dual-NIC constants | `6fdc1d9` |
| `feature/wifi-ap` | Wi-Fi AP (hostapd) mode for the inline gateway | `8f732c1` |
| `feature/portal-gate` | Network-level captive portal: access only after register + verify + approve + sign-in (P0–P3) | `f053bbf` |
| `feature/email-warning` | Email warning on LOW→MEDIUM risk + ban notice (built on `feature/portal-gate`) | `f12779c` |
| `feature/demo-monitoring` | Live Event Feed + ban-toast notification (built on `feature/option-a-inline`) | `3146a42` |

**Two divergent lines.** `portal-gate` → `email-warning` is one stack;
`option-a-inline` → `demo-monitoring` is another. The demo feed/toast are **not**
on the portal/email branches, and the portal is **not** on the demo branch. If a
single box is needed with everything, merge them into a combined branch.

## Decisions already taken
- Email delivery: **real Gmail SMTP** (details in local `.env`, gitignored — not in git).
- Warning cooldown: **10 minutes**; trigger on the **first** MEDIUM window (`ZTA_NOTIFY_MIN_WINDOWS=1`); **admin copy on**.
- Portal over plain HTTP; portal **requires admin approval**; session TTL 30 min.
- Portal-session restart behaviour: still open (currently re-grants non-expired sessions).

## Open items
- **Portal gate (P3.2):** live test matrix on the Pi/Kali gateway + a spare device.
- **Email warning (Item 9):** live test on the gateway (email only reaches the owner, not the device).
- **Demo monitoring:** live test of the feed + toast on the inline gateway.
- Decide whether to merge `portal-gate` + `email-warning` + `demo-monitoring` into one branch.
- Bug fixed during `demo-monitoring`: in `app/routes.py` the view `revoke_access`
  shadowed the imported portal function → infinite recursion on unban (looked like a
  Windows C-stack crash). Fixed via `portal_revoke_access` alias.

## Inline gateway (Kali / Option A) — current lab state
- Run as root: `sudo venv/bin/python run.py`. Good banner:
  `[enforcement] iptables DROP active (Linux, root)` + `[sniffer] listening on eth1`.
- Internal side is `192.168.50.0/24`, gateway `192.168.50.1` (eth1); uplink eth0.
- `app/policy/blocklist.txt` is gitignored and was **missing** on the Kali box →
  regenerate: `curl -sL -o app/policy/blocklist.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
- **Captive-portal popup only appears on `feature/portal-gate`.** On
  `option-a-inline`/`demo-monitoring` the portal is app-layer only: it redirects
  only if the device opens the gateway's own web app (`http://192.168.50.1:5000/`).
  No DNS hijack / port-80 capture → no automatic OS "Sign in" popup.
- Full live runbook: `docs/RUNBOOK-KALI-OPTIONA.md`.

## How to run
- Windows dev box: `./venv/bin/python run.py` → http://127.0.0.1:5000/login  (`admin` / `admin123`), MinGW venv (`bin/`, not `Scripts/`).
- Kali inline: `sudo venv/bin/python run.py`.
- Tests (run **sequentially**, they share `db/zta_test.db`):
  `tests/test_phase6.py` (26) · `tests/test_phase7.py` (34) · `tests/test_integration.py` (35) = **95**, plus `tests/test_portal.py` (9) and `tests/test_notify.py` (20) on their branches.
  They are standalone scripts, not pytest — run `./venv/bin/python tests/<file>.py`.

## Not stored in git (recreate/clone separately)
- `.env` — real SMTP credentials (Gmail app password). Recreate on any new machine
  for real email; without it the app falls back to lab mode (console + forensic log).
- `db/*.db`, `logs/` — runtime state (gitignored). Tests use a throwaway `db/zta_test.db`.
