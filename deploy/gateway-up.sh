#!/usr/bin/env bash
# gateway-up.sh — idempotent bring-up of the wired ZTA gateway (plan F6).
#
# Does what runbook §3 used to make you type by hand, and is safe to run on
# every boot (wired into deploy/zta-gateway.service as ExecStartPre):
#   * net.ipv4.ip_forward = 1, persisted in /etc/sysctl.d/99-zta.conf
#   * MASQUERADE out of the uplink
#   * RELATED,ESTABLISHED return path uplink -> internal
#   * gateway address on the internal NIC
#   * a dnsmasq drop-in for the internal interface (DHCP + DNS)
#
# Start the app itself separately (systemd unit, or run.py by hand).
# Run as root.  Env overrides: ZTA_UPLINK_IFACE, ZTA_INTERNAL_IFACE,
# ZTA_GATEWAY_IP, ZTA_INTERNAL_SUBNET.
set -eu

UPLINK=${ZTA_UPLINK_IFACE:-eth0}
INTERNAL=${ZTA_INTERNAL_IFACE:-eth1}
GWIP=${ZTA_GATEWAY_IP:-192.168.50.1}
SUBNET=${ZTA_INTERNAL_SUBNET:-192.168.50.0/24}
PREFIX=${SUBNET#*/}
DNSMASQ_CONF=/etc/dnsmasq.d/zta-wired.conf
SYSCTL_CONF=/etc/sysctl.d/99-zta.conf

if [ "$(id -u)" -ne 0 ]; then
    echo "gateway-up.sh must run as root" >&2
    exit 1
fi

log() { printf '[gateway-up] %s\n' "$*"; }

if ! ip link show "$INTERNAL" >/dev/null 2>&1; then
    log "ERROR: internal interface $INTERNAL does not exist"
    exit 1
fi
if ! ip link show "$UPLINK" >/dev/null 2>&1; then
    log "WARN: uplink interface $UPLINK does not exist yet"
fi

# --- 1. IP forwarding, persisted -------------------------------------------
log "enabling net.ipv4.ip_forward (persisted in $SYSCTL_CONF)"
sysctl -qw net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' > "$SYSCTL_CONF"

# --- 2. gateway address on the internal NIC --------------------------------
if ip -4 addr show dev "$INTERNAL" | grep -q "$GWIP"; then
    log "$INTERNAL already has $GWIP"
else
    log "adding $GWIP/$PREFIX to $INTERNAL"
    ip addr add "$GWIP/$PREFIX" dev "$INTERNAL" || true
fi
ip link set "$INTERNAL" up

# --- 3. NAT + return path (idempotent) -------------------------------------
if iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null; then
    log "MASQUERADE rule already present"
else
    log "adding MASQUERADE out $UPLINK"
    iptables -t nat -A POSTROUTING -o "$UPLINK" -j MASQUERADE
fi

if iptables -C FORWARD -i "$UPLINK" -o "$INTERNAL" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    log "ESTABLISHED return path already present"
else
    log "adding ESTABLISHED return path $UPLINK -> $INTERNAL"
    iptables -A FORWARD -i "$UPLINK" -o "$INTERNAL" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# --- 4. dnsmasq drop-in for the internal interface -------------------------
log "writing $DNSMASQ_CONF"
cat > "$DNSMASQ_CONF" <<EOF
# Managed by deploy/gateway-up.sh — wired internal interface.
interface=$INTERNAL
bind-interfaces
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,12h
dhcp-option=option:router,$GWIP
dhcp-option=option:dns-server,$GWIP
EOF

# --- 5. stale Wi-Fi config guard -------------------------------------------
if [ -f /etc/dnsmasq.d/zta-ap.conf ] \
        && ! ip link show wlan0 >/dev/null 2>&1; then
    log "WARNING: /etc/dnsmasq.d/zta-ap.conf exists but wlan0 is absent."
    log "         dnsmasq will refuse to start. Move it aside:"
    log "         mv /etc/dnsmasq.d/zta-ap.conf /root/"
fi

# --- 6. (re)start dnsmasq ---------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    if dnsmasq --test >/dev/null 2>&1; then
        systemctl restart dnsmasq
        log "dnsmasq restarted"
    else
        log "ERROR: dnsmasq config test failed — not restarting"
        dnsmasq --test || true
        exit 1
    fi
else
    log "systemctl not found; restart dnsmasq manually"
fi

log "done. Start the app:  sudo ZTA_PORTAL_GATE=1 venv/bin/python run.py"
log "then verify with:     sudo ./deploy/verify_gate.sh"
