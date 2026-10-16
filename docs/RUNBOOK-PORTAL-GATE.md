# Portal Gate Runbook — Network access only after sign-in

Live-validation checklist for the portal-gate feature (branch `feature/portal-gate`).
Code is written and unit-tested; this runbook turns it into **Lab-verified**.

Target machine:
- Kali VM or Raspberry Pi, dual-NIC: **eth0** = uplink (internet/WAN),
  **wlan0** = internal Wi-Fi AP or **eth1** = wired internal
  (`192.168.50.0/24`, gateway `192.168.50.1`).
- Run as root (iptables + port 80 require it).

---

## Step 1 — Setup

```bash
sudo apt install -y git python3-venv python3-pip hostapd dnsmasq iptables
git clone https://github.com/mayu3000/zta-gateway.git
cd zta-gateway
git checkout feature/portal-gate
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo ZTA_AP_PASSPHRASE='choose-8-to-63-chars' ./deploy/setup_ap.sh
```

## Step 2 — Start with the gate ON

```bash
sudo ZTA_PORTAL_GATE=1 ZTA_INTERNAL_IFACES=wlan0,eth1 \
     ZTA_SESSION_TTL_MINUTES=30 ./venv/bin/python run.py
```

Expected startup lines:
```
[enforcement] iptables DROP active (Linux, root)
[sniffer] listening on wlan0
[portal] gate ON, interfaces: wlan0,eth1
[portal] redirect listener on :80 -> http://192.168.50.1:5000/login
 * Running on http://0.0.0.0:5000
```

## Step 3 — Safety checklist (BEFORE testing)

```bash
# Backup current rules
sudo iptables-save > /tmp/rules.bak
# Auto-restore in 2 seconds if you lose access
(sleep 120; sudo iptables-restore < /tmp/rules.bak) &
```

**Never test on the admin's own device.** Use a second device (phone, laptop).

## Step 4 — Live test matrix

| # | Scenario | Command / Action | Expected |
|---|---|---|---|
| 1 | New phone joins Wi-Fi | Connect to ZTA-Gateway SSID | IP assigned, no internet, sign-in popup |
| 2 | New laptop on Ethernet | Plug into eth1 | IP assigned, no internet, redirect to portal |
| 3 | Register, verify, not approved | Register on device, verify email | Login blocked: "pending approval" |
| 4 | Admin approves, user signs in | Approve in dashboard, login on device | Internet works within seconds |
| 5 | Logout | Click logout | Internet stops |
| 6 | Idle past TTL | Wait 30+ min | Internet stops |
| 7 | Ban signed-in device | Trigger port sweep or admin ban | Blocked, stays blocked |
| 8 | Unban | Dashboard unban button | Blocked until signed in again |
| 9 | Restart gateway 3 times | Stop/start run.py | No duplicate rules |
| 10 | Reboot | sudo reboot | Gate returns without manual steps |

## Step 5 — Verify rule order

```bash
sudo iptables -S ZTA_FORWARD
sudo iptables -t nat -S ZTA_PREROUTING
```

Expected order in ZTA_FORWARD per interface:
1. Banned MAC DROP rules
2. Granted MAC ACCEPT rules
3. Default DROP

In ZTA_PREROUTING per interface:
1. Granted MAC RETURN (skip DNAT)
2. DNAT tcp/80 to gateway:80

## Step 6 — Verify idempotency

```bash
sudo iptables -S | sort | uniq -d   # should print nothing
```

## Step 7 — Cleanup

```bash
kill %1  # kill the safety-restore background job
sudo iptables-restore < /tmp/rules.bak  # restore original rules
```

---

## Failure triage

| Symptom | Likely cause | Fix |
|---|---|---|
| No sign-in popup on phone | OS probe not matching | Check dnsmasq resolves to gateway IP |
| Device has internet without login | Blanket FORWARD ACCEPT | Re-run setup_ap.sh (removed in P0.1) |
| Portal page unreachable | INPUT chain missing tcp/80 | `sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT` |
| Redirect loop | Portal URL wrong | Check ZTA_PORTAL_URL setting |
| Rules duplicated | setup_gate called without flush | Restart gateway |
