# Kali VM Runbook — Option A Inline Gateway (branch `feature/option-a-inline`)

Live-validation checklist for the inline-bridging port. Code is complete and
Windows-verified (95/95); this runbook turns it into **Lab-verified**. Read
each step BEFORE running it; the checkboxes block progression for a reason.

Target machine:
- Kali VM, dual-NIC: **eth0** = uplink (internet/WAN), **eth1** = internal
  (devices live here, `192.168.50.0/24`, gateway `192.168.50.1`).
- The VM must have working NAT/forwarding on eth0 already (from the earlier
  setup session). This runbook only ports the project onto it.

---

## Step 1 — Get the code + dependencies

```bash
sudo apt install -y git python3-venv python3-pip
git clone https://github.com/mayu3000/zta-gateway.git
cd zta-gateway
git checkout feature/option-a-inline     # if not already the branch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Check that scapy imported cleanly (raw sockets need root; harmless to check now):

```bash
python -c "from scapy.all import ARP, send, srp; print('scapy OK')"
```

> **If `pip install` fails on scapy's Npcap-style extras** — that's a Windows
> assumption; on Linux just scapy (not scapy[npcap]) is the requirement. If
> `requirements.txt` pins a niche extra, strip it here or note it in the viva
> limitations.

---

## Step 2 — Run, capture the startup banner

```bash
sudo venv/bin/python run.py
```

Look at the first lines of output. The startup banner is the **mode proof**:

```
[enforcement] iptables DROP active (Linux, root)     <-- EXPECT THIS
[sniffer] listening on eth1                          <-- and THIS
 * Running on http://0.0.0.0:5000
```

**What to do if instead you see**
`[enforcement] recorded-only mode — quarantines are logged but not enforced`:
- You are not root → rerun with `sudo`.
- Or `ZTA_ENFORCE` is set somewhere weird → unset it: `unset ZTA_ENFORCE`.
- (If you see `ARP spoof active` you explicitly exporte `ZTA_ENFORCE=arp` —
  only do that if you want to demo the legacy mode.)

Also confirm what it's actually sniffing — `ip addr show eth1` should show
`192.168.50.1/24` and the VM should already forward from eth1→eth0.

> **TEST NOTE (run while the server is UP):** in a second terminal, re-run the
> 3 suites as a NON-root user. Each suite sets `ZTA_ENFORCE=recorded` itself,
> so tests never touch iptables:
> ```bash
> cd zta-gateway && ./venv/bin/python tests/test_phase6.py    # 26
> ./venv/bin/python tests/test_phase7.py                      # 34
> ./venv/bin/python tests/test_integration.py                 # 35
> ```
> Expect 3× "ALL PASS" = 95 total. The live server's `db/zta.db` is separate
> from the throwaway test DB, so this is safe while run.py runs.

---

## Step 3 — Discovery + registration (smoke the sensors)

Keep the server running. From a **wired device plugged into eth1**, open
`http://192.168.50.1:5000/login`.

- The device should appear in the admin dashboard's device table within ~30 s
  (the 30 s `periodic_device_scan`). If it does NOT show up:
  - Check `ip neigh` on the VM — `sudo ip neigh show dev eth1`. If the MAC is
    missing, ping from the device or run
    `sudo ip neigh flush dev eth1` then wait for the device to ARP again.
  - Confirm scapy scan genuinely returns the device: `sudo python app/discovery.py`.
- A brand-new (unknown-status) device gets the **captive portal welcome**:
  any page → redirected to `/login`. Register → verify (console LAB MODE link)
  → admin approve → the device is online.

This step confirms discovery **and** resolution (`ip neigh` parse) end-to-end
on Linux. If the device shows up but Web port 5000 is unreachable through the
portal, that's a forwarding/dnsmasq issue on the VM, not the app.

---

## Step 4 — The money shot: real iptables enforcement + latency

Now the *only* part that can't be pre-verified. Run it **slowly**, terminal
split: app logs in window A, device in window B.

1. **From the approved device**, generate a port sweep (the reliable trigger):
   ```bash
   for p in $(seq 1 300); do nc -z -w 0.05 1.1.1.1 $p >/dev/null 2>&1; done
   ```
   (or your Python socket-probe equivalent, as in the tests) long enough to
   push composite risk over the escalation threshold (~70).

2. **Watch the app window (A)** for the ban line:
   ```
   ... total=7x HIGH ... status=banned
   ```
   then the QUARANTINE forensic event.

3. **The moment you see `status=banned`**, verify the rule exists:
   ```bash
   sudo iptables -L -v FORWARD | grep DROP
   ```

4. **Ordering / detection-latency check (do this BEFORE declaring victory):**
   On the **device** (window B), run a tight ping loop to a public host, then
   trigger the sweep (step 1) and record the sequence:
   ```
   T0  sweep starts
   T1  app shows banned (window A)
   T2  device's ping drops (first timeout in window B)
   T3  iptables -L -v FORWARD shows the DROP rule
   ```
   - **Ideal:** T3 ≈ T1 (< 1 s apart), T2 ≤ T1 + 1 window. If the device loses
     connectivity cleanly right as the ban lands → real, low-latency enforcement.
   - **If lag is noticeable** (rule appears *well before* the device visibly
     goes dark, or T2 is many seconds after T3): the device may be holding a
     cached connection, or DHCP/ARP re-resolution masks the block. Measure the
     gap and write it into the report — it becomes a real "detection→enforcement
     latency" datapoint (ties into the Phase 8 perf evidence, ~65 ms/window).
   - **If the rule appears but the device NEVER loses connectivity:** the
     target's traffic isn't actually traversing the gateway's FORWARD chain —
     check `ip route` on the device (it must route via 192.168.50.1) and that
     the VM's forwarding works on eth1. This is the failure that says "the
     inline-bridge story isn't complete on this setup yet."

5. **Unban** (dashboard button). Immediately re-check:
   ```bash
   sudo iptables -L -v FORWARD | grep DROP   # expect NO output — rule removed
   ```
   and confirm the device's pings resume. This proves the `release_device(ip)`
   path works — the exact bug the original plan would have shipped.

6. **Repeat-attack check:** run the sweep again. A prior-ban device bans at the
   escalated 0.75× threshold — confirm it bans faster the second time.

---

## Step 5 — Wrap-up / evidence capture

- [ ] Screenshot of `iptables -L -v FORWARD` showing the DROP rule for the sweeper IP.
- [ ] Screenshot of the app dashboard right after the ban (status=banned tile).
- [ ] The T0/T1/T2/T3 timing table (even a rough one) for the report.
- [ ] `git log --oneline` on the branch → shows `08ee637 Option A ...`.
- [ ] Optional: `sudo ip neigh flush dev eth1; sudo ./venv/bin/python run.py`
      once more to reproduce a clean boot, confirming the banner repeats.

If everything passed: the branch can be **merged into `main`** as a second,
validated enforcement path — or kept separate and presented as a documented
addendum (§13 of the BLACKBOOK). Recommend merging only after step 4 shows a
real device going offline and coming back.

---

## Failure triage quick-reference

| Symptom | Likely cause | Fix |
|---|---|---|
| Banner says `recorded-only` under root | env `ZTA_ENFORCE` set | `unset ZTA_ENFORCE`; rerun |
| Device never shows in dashboard | snipper bound to wrong iface / no ARP | `sudo python app/discovery.py`; check `ip neigh dev eth1` |
| Dashboard shows device, HTTP portal unreachable | VM forwarding / dnsmasq | fix eth1→eth0 NAT; DNS at 192.168.50.1 |
| Rule appears, device stays online | device not routing via gateway | set device gateway = 192.168.50.1 |
| Rule removed on unban but device still offline | stale ARP on device | `arp -d 192.168.50.1` on device, re-open browser |