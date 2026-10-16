# PORTAL_GATE_PLAN.md — Network access only after register + sign-in

Feature: any device that joins the gateway, wireless (`wlan0`) or wired (`eth1`), gets an IP
address but **no internet** until its user registers, verifies, is approved, and signs in at the
portal. Access is removed on logout, expiry, ban, or when the device leaves.

Branch: `feature/portal-gate`, created from `feature/wifi-ap`. `main` and `v1.0-final` stay untouched.
Platform: Linux gateway (Raspberry Pi or Kali VM), run as root. Windows keeps working with the gate **off**.

Legend: `[ ]` todo, `[x]` done and tested. Do not tick an item until its acceptance test passes.

---

## P0 — Prerequisites (do first)

### 0.1 Remove the blanket FORWARD allow `[ ]`
**Why:** `deploy/setup_ap.sh` adds `FORWARD -i wlan0 -o eth0 -j ACCEPT` and the Option A runbook adds a similar
internal-to-uplink ACCEPT (persisted with iptables-persistent). Either one lets every device out, so the gate is bypassed.
**Files:** `deploy/setup_ap.sh`, `docs/RUNBOOK-KALI-OPTIONA.md`, live iptables, `/etc/iptables/rules.v4`
**Steps:**
1. `sudo iptables -S FORWARD` and `sudo iptables -t nat -S`; list every permissive rule.
2. Remove the internal-to-uplink ACCEPT lines from `setup_ap.sh` (keep MASQUERADE and the established/related return rule).
3. Delete the same rule live and regenerate `/etc/iptables/rules.v4`.
**Accept:** with the gate rules from item 1.1 in place, a fresh device gets an IP and `ping 8.8.8.8` fails.

### 0.2 Settings `[ ]`
**Files:** `app/config.py`
**Add (all env-overridable, defaults keep today's behaviour):**
- `ZTA_PORTAL_GATE` (default `0`): master switch. Off on Windows and during the existing 95 tests.
- `ZTA_INTERNAL_IFACES` (default = `ZTA_INTERNAL_IFACE`): comma list, e.g. `wlan0,eth1`.
- `ZTA_PORTAL_REQUIRE_APPROVAL` (default `1`): admin approval needed. `0` = email verification is enough.
- `ZTA_SESSION_TTL_MINUTES` (default `30`): idle timeout.
- `ZTA_PORTAL_URL` (default `http://192.168.50.1:5000/login`).
**Accept:** with `ZTA_PORTAL_GATE=0` all 95 existing tests pass unchanged.

---

## P1 — Core gate

### 1.1 Firewall module `app/enforcement/portal.py` `[ ]`
### 1.2 Data model `[ ]`
### 1.3 Portal redirect listener `app/portal_redirect.py` `[ ]`
### 1.4 Login grants access `[ ]`
### 1.5 Revoke access `[ ]`
### 1.6 Start-up reconciliation `[ ]`
### 1.7 Wired and wireless together `[ ]`

---

## P2 — Admin and portal UI

### 2.1 Access state in the dashboard `[ ]`
### 2.2 Portal page wording `[ ]`

---

## P3 — Tests and documentation

### 3.1 Automated tests `tests/test_portal.py` `[ ]`
### 3.2 Live test matrix (Pi or Kali) `[ ]`
### 3.3 Documentation `[ ]`

---

## Decisions needed before starting
1. Admin approval required, or email verification only? → **Default: approval required** (`ZTA_PORTAL_REQUIRE_APPROVAL=1`)
2. Session idle timeout. → **Default: 30 minutes**
3. After a restart: keep valid sessions, or make everyone sign in again? → **TBD during 1.6**
4. Portal over plain HTTP or HTTPS? → **Default: plain HTTP**
