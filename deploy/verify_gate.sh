#!/usr/bin/env bash
# verify_gate.sh — preflight / post-start checks for the ZTA captive portal.
#
# Run this on the gateway after `gateway-up.sh` (or after a reboot) and before
# a demo. It prints PASS / FAIL / WARN for each check and exits non-zero if any
# check FAILs, so it can be used as a gate in a script.
#
#   sudo ./deploy/verify_gate.sh              # rules + listeners
#   sudo ./deploy/verify_gate.sh 192.168.50.98  # also assert a client is seen
#
# Env overrides (same names the app uses):
#   ZTA_UPLINK_IFACE (default eth0), ZTA_INTERNAL_IFACE (default eth1),
#   ZTA_GATEWAY_IP   (default 192.168.50.1)
set -u

UPLINK=${ZTA_UPLINK_IFACE:-eth0}
INTERNAL=${ZTA_INTERNAL_IFACE:-eth1}
GWIP=${ZTA_GATEWAY_IP:-192.168.50.1}
EXPECT_DEVICE=${1:-}

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
warn() { printf 'WARN  %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

echo "== ZTA gate preflight =="
echo "   uplink=$UPLINK  internal=$INTERNAL  gateway=$GWIP"
echo

# --- 0. tools ---------------------------------------------------------------
if ! have iptables; then
    fail "iptables not found"
    exit 1
fi

# --- 1. forwarding ----------------------------------------------------------
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
    pass "net.ipv4.ip_forward = 1"
else
    fail "net.ipv4.ip_forward is not 1 (run deploy/gateway-up.sh)"
fi

# --- 2. NAT out of the uplink ----------------------------------------------
if iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null; then
    pass "nat POSTROUTING MASQUERADE out $UPLINK"
else
    fail "no MASQUERADE rule for $UPLINK"
fi

# --- 3. return path for established flows ----------------------------------
if iptables -C FORWARD -i "$UPLINK" -o "$INTERNAL" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    pass "ESTABLISHED return path $UPLINK -> $INTERNAL"
else
    fail "no RELATED,ESTABLISHED ACCEPT $UPLINK -> $INTERNAL"
fi

# --- 4. ZTA_FORWARD: default DROP last, no duplicates ----------------------
if iptables -S ZTA_FORWARD >/dev/null 2>&1; then
    last=$(iptables -S ZTA_FORWARD | tail -n 1)
    case "$last" in
        *"-j DROP") pass "ZTA_FORWARD last rule is the default DROP" ;;
        *)          fail "ZTA_FORWARD last rule is NOT a DROP: $last" ;;
    esac
    drops=$(iptables -S ZTA_FORWARD | grep -c -- "-i $INTERNAL -j DROP")
    if [ "$drops" -eq 1 ]; then
        pass "exactly one default DROP for $INTERNAL"
    else
        fail "expected 1 default DROP for $INTERNAL, found $drops"
    fi
else
    fail "chain ZTA_FORWARD does not exist (is the gate armed?)"
fi

# --- 5. duplicate rules anywhere in filter ---------------------------------
dups=$(iptables -S | sort | uniq -d)
if [ -z "$dups" ]; then
    pass "no duplicate rules in the filter table"
else
    fail "duplicate rules found:"
    printf '   %s\n' "$dups"
fi

# --- 6. nat ZTA_PREROUTING: portal + DNS interception ----------------------
if iptables -t nat -S ZTA_PREROUTING >/dev/null 2>&1; then
    if iptables -t nat -S ZTA_PREROUTING \
            | grep -q -- "dport 80 -j DNAT"; then
        pass "nat ZTA_PREROUTING redirects tcp/80 to the portal"
    else
        fail "nat ZTA_PREROUTING has no tcp/80 DNAT"
    fi
    for proto in udp tcp; do
        if iptables -t nat -S ZTA_PREROUTING \
                | grep -q -- "-p $proto --dport 53 -j DNAT"; then
            pass "nat ZTA_PREROUTING intercepts $proto/53 (DNS)"
        else
            warn "nat ZTA_PREROUTING has no $proto/53 DNS DNAT (ZTA_DNS_INTERCEPT=0?)"
        fi
    done
else
    fail "chain ZTA_PREROUTING (nat) does not exist"
fi

# --- 7. ZTA_INPUT: gateway services reachable -------------------------------
if iptables -S ZTA_INPUT >/dev/null 2>&1; then
    for dport in 53 67 80 5000; do
        if iptables -S ZTA_INPUT | grep -q -- "dport $dport .*-j ACCEPT"; then
            pass "ZTA_INPUT accepts port $dport"
        else
            fail "ZTA_INPUT does not accept port $dport"
        fi
    done
    if iptables -S INPUT | grep -q -- "-j ZTA_INPUT"; then
        pass "INPUT jumps to ZTA_INPUT"
    else
        fail "INPUT does not jump to ZTA_INPUT"
    fi
else
    fail "chain ZTA_INPUT does not exist"
fi

# --- 8. listeners -----------------------------------------------------------
if have ss; then
    for port in 80 5000; do
        if ss -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$port\$"; then
            pass "listener on tcp/$port"
        else
            fail "nothing listening on tcp/$port"
        fi
    done
else
    warn "ss not found; skipping listener checks"
fi

# --- 9. dnsmasq -------------------------------------------------------------
if have systemctl; then
    if systemctl is-active --quiet dnsmasq; then
        pass "dnsmasq is active"
    else
        fail "dnsmasq is not active (journalctl -u dnsmasq -n 30)"
    fi
fi

# --- 10. addresses and route -----------------------------------------------
if ip -4 addr show dev "$INTERNAL" 2>/dev/null | grep -q "$GWIP"; then
    pass "$INTERNAL has $GWIP"
else
    fail "$INTERNAL does not have $GWIP"
fi
if ip -4 addr show dev "$UPLINK" 2>/dev/null | grep -q "inet "; then
    pass "$UPLINK has an address"
else
    fail "$UPLINK has no IPv4 address"
fi
if ip route show default 2>/dev/null | grep -q "dev $UPLINK"; then
    pass "default route via $UPLINK"
else
    warn "no default route via $UPLINK"
fi

# --- 11. stale Wi-Fi dnsmasq config guard ----------------------------------
if [ -f /etc/dnsmasq.d/zta-ap.conf ] \
        && ! ip link show wlan0 >/dev/null 2>&1; then
    fail "stale /etc/dnsmasq.d/zta-ap.conf references a missing wlan0"
fi

# --- 12. optional: a specific client is visible to discovery ----------------
if [ -n "$EXPECT_DEVICE" ]; then
    if ip neigh show dev "$INTERNAL" 2>/dev/null \
            | grep -q "$EXPECT_DEVICE"; then
        pass "discovery sees $EXPECT_DEVICE on $INTERNAL"
    else
        fail "$EXPECT_DEVICE not in the neighbour table on $INTERNAL"
    fi
fi

echo
if [ "$FAILS" -eq 0 ]; then
    echo "== all checks passed =="
    exit 0
fi
echo "== $FAILS check(s) FAILED =="
exit 1
