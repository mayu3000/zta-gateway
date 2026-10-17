# Combined Runbook — portal gate + email warning + live monitoring

Branch: **`integration/all-features`** (Option A inline + Wi-Fi AP + portal gate +
email warning + demo monitoring, all in one).

This is the runbook for the **full demo**: a client device is captured by the
network-level captive portal, must register → verify → be approved → sign in
before it gets internet; meanwhile the admin dashboard shows a live event feed
and a ban toast, and the owner gets email warnings as risk rises.

Target machine: Kali VM (or Raspberry Pi), dual-NIC.
- **eth0** = uplink / WAN (already has internet via the home router)
- **eth1** = internal / LAN (`192.168.50.0/24`, gateway `192.168.50.1`)

Wired (`eth1`) is the primary path below; the Wi-Fi AP variant is in §8.
Everything needs **root**.

---

## 0. Prerequisites

```bash
sudo apt install -y git python3-venv python3-pip dnsmasq iptables
cat /proc/sys/net/ipv4/ip_forward          # should be 1 (we set it below)
ip -br addr                                # confirm eth0 (uplink) + eth1 (internal)
```

---

## 1. Get the code

```bash
cd ~/zta-gateway
git fetch origin
git checkout integration/all-features
git pull

# first time on a fresh clone instead:
#   git clone https://github.com/mayu3000/zta-gateway.git
#   cd zta-gateway && git checkout integration/all-features

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`app/policy/blocklist.txt` is **gitignored** and missing on a fresh box — recreate
it (the network-risk / blocked-domain scoring needs it):

```bash
curl -sL -o app/policy/blocklist.txt \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
wc -l app/policy/blocklist.txt          # sanity: many thousands of lines
```

---

## 2. Email (optional — lab mode works without it)

Copy the template and fill in a real Gmail address + **App Password**:

```bash
cp .env.example .env
nano .env        # MAIL_SERVER / MAIL_USERNAME / MAIL_PASSWORD / MAIL_DEFAULT_SENDER
```

With no `.env`, the app runs in **lab mode**: verification links and warnings are
printed to the console and the forensic log instead of emailed. Fine for the
demo — you just read the links from the terminal.

---

## 3. Bring up the internal network (wired `eth1`)

```bash
# 3a. gateway address on the internal NIC
sudo ip addr flush dev eth1
sudo ip addr add 192.168.50.1/24 dev eth1
sudo ip link set eth1 up

# 3b. DHCP + DNS for wired clients
sudo tee /etc/dnsmasq.d/zta-wired.conf >/dev/null <<'EOF'
interface=eth1
bind-interfaces
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,12h
dhcp-option=option:router,192.168.50.1
dhcp-option=option:dns-server,192.168.50.1
EOF
sudo systemctl restart dnsmasq

# 3c. forwarding + NAT out of the uplink
sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null \
  || sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# return path for established flows only — NEW flows must pass the portal gate
sudo iptables -C FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

> **Gotcha:** if a previous run left `/etc/dnsmasq.d/zta-ap.conf` (from
> `setup_ap.sh`) behind, it has `interface=wlan0` + `bind-interfaces`. If
> `wlan0` does not exist, dnsmasq will refuse to start and no client gets a
> lease. Either run the Wi-Fi path (§8) *or* move that file aside:
> `sudo mv /etc/dnsmasq.d/zta-ap.conf /root/`.

---

## 4. Safety net (do this BEFORE testing)

```bash
sudo iptables-save > /tmp/rules.bak
(sleep 300; sudo iptables-restore < /tmp/rules.bak) &   # auto-rollback in 5 min
```

**Never test on the admin's own machine.** Use a second device (friend's laptop
or phone). Replace `/tmp/rules.bak` with the rollback you actually want.

---

## 5. Start the gateway

```bash
sudo ZTA_PORTAL_GATE=1 \
     ZTA_INTERNAL_IFACES=eth1 \
     ZTA_UPLINK_IFACE=eth0 \
     ZTA_SESSION_TTL_MINUTES=30 \
     venv/bin/python run.py
```

You no longer need to hand-add `iptables -I INPUT -p tcp --dport 80 -j ACCEPT`:
`setup_gate()` now builds a `ZTA_INPUT` chain that accepts the redirect (80),
the web UI (5000), DNS (53) and DHCP (67) on the internal interfaces, and opens
DNS interception in `nat` (see §6). Set `ZTA_DNS_INTERCEPT=0` to disable DNS
interception.

Expected startup banner:

```
[enforcement] iptables DROP active (Linux, root)
[mail] LAB MODE (no MAIL_SERVER configured)
[sniffer] listening on eth1
[portal] gate ON, interfaces: eth1
[portal] restored 0 ban(s), 0 active session(s) (DNS intercept: on)
[portal] redirect listener on :80 -> http://192.168.50.1:5000/login
 * Running on http://0.0.0.0:5000
```

- `recorded-only mode` instead of `iptables DROP active` → not root, or `ZTA_ENFORCE`
  is exported weirdly (`unset ZTA_ENFORCE`).
- No `[portal]` lines → `ZTA_PORTAL_GATE=1` was not exported.
- `[mail]` shows `SMTP ready` once Flask-Mail is installed and `.env` is set;
  otherwise it shows `LAB MODE` and links print to this terminal.

---

## 6. Verify the rules (second terminal)

```bash
sudo ./deploy/verify_gate.sh            # all-in-one: PASS/FAIL for every check
# or by hand:
sudo iptables -t nat -S ZTA_PREROUTING   # DNAT :80 + udp/tcp :53 (DNS intercept)
sudo iptables -S ZTA_FORWARD             # order: DROP(ban) → ACCEPT(grant) → DROP(default)
sudo iptables -S ZTA_INPUT               # ACCEPT 53/67/80/5000 + ESTABLISHED
sudo ss -lntp | grep ':80'               # the redirect listener is up
```

Rule order matters: the catch-all `DROP` **must be last** or granted devices get
no internet (this was a real bug, fixed on this branch).

**DNS interception.** `ZTA_DNS_INTERCEPT=1` (default) rewrites every outbound
`udp/tcp 53` query from a client to `192.168.50.1:53`, so a signed-out device can
still resolve names through the gateway's dnsmasq (and cannot reach an outside
resolver, which also blocks DNS tunnelling). Signed-in devices are intercepted
too, so their lookups still show up in the Website Activity page. Limits:
DNS-over-HTTPS and DNS-over-TLS are not affected — signed-out devices cannot use
them because everything else is dropped, but signed-in devices can, which hides
those lookups from the monitor.

---

## 7. The demo flow

Open the admin UI on the gateway itself (or from a granted device):
`http://192.168.50.1:5000/login` → **admin / admin123**.

1. **Capture** — plug the friend's laptop into `eth1`. It should get a
   `192.168.50.x` lease. Open any `http://…` page → redirected to the portal
   `/login`. (The OS may also pop its native "Sign in to network" prompt.)
2. **Register** — on the device, register a user. Verify the email:
   - real SMTP → link arrives in the inbox;
   - lab mode → verification link is printed in the `run.py` terminal.
3. **Approve** — in the admin dashboard, approve the pending user
   (`ZTA_PORTAL_REQUIRE_APPROVAL` defaults to `1`).
4. **Sign in** — on the device, log in. Within a few seconds it gets real
   internet (a per-MAC ACCEPT is added above the default DROP).
5. **Live monitoring** — the dashboard **Event Feed** fills with forensic
   events; the **Recent Notifications** table lists emails; a **ban toast**
   pops in the corner when a device is auto-quarantined.
6. **Risk → warning → ban** — from the *device*, force a MEDIUM then HIGH risk:

   ```bash
   for p in $(seq 1 300); do nc -z -w 0.05 1.1.1.1 $p >/dev/null 2>&1; done
   ```

   - first MEDIUM window → **email warning** to the owner (10-min cooldown);
   - risk ≥ 70 (`HIGH_RISK_BAN_THRESHOLD`) → **ban**: device goes offline,
     `DROP` rule appears, dashboard toast fires, owner gets a ban notice.
7. **Unban / logout / TTL** —
   - dashboard **Unban** button → device must *sign in again* (unban resets
     approval to `unknown`);
   - **Logout** on the device → internet stops immediately;
   - idle past `ZTA_SESSION_TTL_MINUTES` (30) → session expires, access revoked.

---

## 8. Wi-Fi AP variant (instead of §3)

If a USB adapter supports AP mode (`iw list | grep -A8 'Supported interface modes'`
must list `AP`):

```bash
sudo ZTA_AP_PASSPHRASE='choose-8-to-63-chars' ./deploy/setup_ap.sh
```

This sets up `hostapd` + dnsmasq on `wlan0` and adds the NAT/forwarding rules.
Then start with the Wi-Fi interface:

```bash
sudo ZTA_PORTAL_GATE=1 ZTA_INTERNAL_IFACES=wlan0 ZTA_UPLINK_IFACE=eth0 \
     venv/bin/python run.py
```

Device joins SSID **ZTA-Gateway** and follows the same §7 flow.

---

## 9. Boot persistence (optional)

Instead of re-typing §3, run it once and let systemd do it on every boot:

```bash
sudo cp deploy/zta.env.example /etc/zta.env      # edit the interface names if needed
sudo ./deploy/gateway-up.sh                      # forwarding, NAT, dnsmasq drop-in

sudo cp deploy/zta-gateway.service /etc/systemd/system/
sudo sed -i "s#/opt/zta-gateway#$PWD#g" /etc/systemd/system/zta-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now zta-gateway
sudo ./deploy/verify_gate.sh
```

`gateway-up.sh` is idempotent and runs as `ExecStartPre`, so a reboot brings the
whole gate back without any hand-typed rules. Secrets stay in the repo's `.env`
(`chmod 600`); `/etc/zta.env` holds only non-secret switches.

> Save a real backup outside `/tmp` (it is wiped at reboot):
> `sudo mkdir -p /root/zta-backups && sudo iptables-save | sudo tee /root/zta-backups/rules-$(date +%F-%H%M).v4`

---

## 10. Teardown

```bash
# stop run.py (Ctrl-C), then kill the safety job if still pending and restore:
sudo iptables-restore < /tmp/rules.bak

# if you installed the systemd unit:
sudo systemctl disable --now zta-gateway
```

`run.py`'s `teardown_gate()` (on clean shutdown) removes the `ZTA_FORWARD`,
`ZTA_PREROUTING` and `ZTA_INPUT` chains and their jumps.

---

## Failure triage

| Symptom | Likely cause | Fix |
|---|---|---|
| Device gets `192.168.50.x` but no redirect | gate off / wrong branch | `ZTA_PORTAL_GATE=1`; confirm the `[portal]` banner and `sudo iptables -S ZTA_INPUT` |
| Device gets no DNS / names don't resolve when signed out | dnsmasq down, or DNS interception off | `systemctl status dnsmasq`; `sudo iptables -t nat -S ZTA_PREROUTING \| grep 53`; `ZTA_DNS_INTERCEPT=1` |
| No DHCP lease at all (169.254.x.x) | dnsmasq not serving `eth1` | §3b; check `interface=eth1` + `bind-interfaces`, no stale `zta-ap.conf` |
| Portal page loads but sign-in doesn't grant internet | catch-all DROP above the ACCEPT | must be fixed on this branch; verify `iptables -S ZTA_FORWARD` order |
| No "Sign in" OS popup, but manual URL works | client used HTTPS first, or OS probe path unmatched | try `http://neverssl.com`; probes answer `/generate_204`, `/connecttest.txt`, `/hotspot-detect.html` |
| No email arrives | no `.env` / wrong app password | lab mode prints link to console; else fix `MAIL_*` in `.env` |
| Device never appears in dashboard | sniffer on wrong NIC / no ARP | `sudo ip neigh show dev eth1`; `sudo python app/discovery.py` |
| `sync_bans`-era symptom: new ban kills everyone | old code | fixed on this branch (see HANDOFF) |
