#!/usr/bin/env bash
# Bring up the ZTA-Gateway Wi-Fi access point on the Kali VM (Option A, Wi-Fi).
#
#   sudo ZTA_AP_PASSPHRASE='choose-8-to-63-chars' ./deploy/setup_ap.sh
#
# Prerequisites
#   * A USB Wi-Fi adapter that supports AP mode, passed through to the VM.
#       iw list | grep -A8 'Supported interface modes'   # must list "AP"
#   * eth0 (or whatever UPLINK) already has internet via the home router.
#   * apt install hostapd dnsmasq iw iptables
#
# Optional overrides: ZTA_AP_IFACE (wlan0), ZTA_UPLINK_IFACE (eth0),
# ZTA_AP_SSID (ZTA-Gateway), ZTA_AP_CHANNEL (6), ZTA_GATEWAY_IP (192.168.50.1),
# ZTA_AP_COUNTRY (IN).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
: "${ZTA_AP_PASSPHRASE:?set ZTA_AP_PASSPHRASE (8-63 characters)}"
(( ${#ZTA_AP_PASSPHRASE} >= 8 && ${#ZTA_AP_PASSPHRASE} <= 63 )) \
  || { echo "passphrase must be 8-63 characters"; exit 1; }

AP_IFACE="${ZTA_AP_IFACE:-wlan0}"
UPLINK="${ZTA_UPLINK_IFACE:-eth0}"
SSID="${ZTA_AP_SSID:-ZTA-Gateway}"
CHANNEL="${ZTA_AP_CHANNEL:-6}"
GW_IP="${ZTA_GATEWAY_IP:-192.168.50.1}"
COUNTRY="${ZTA_AP_COUNTRY:-IN}"
DHCP_FROM="${GW_IP%.*}.10"
DHCP_TO="${GW_IP%.*}.100"

ip link show "$AP_IFACE" >/dev/null 2>&1 \
  || { echo "interface $AP_IFACE not found; is the USB adapter attached to the VM?"; exit 1; }
iw list 2>/dev/null | grep -qE '^\s+\* AP$' \
  || { echo "no adapter reports AP mode (iw list); this adapter cannot host a hotspot"; exit 1; }

echo "[1/5] freeing $AP_IFACE from NetworkManager and assigning $GW_IP/24"
rfkill unblock wifi || true
nmcli dev set "$AP_IFACE" managed no 2>/dev/null || true
ip addr flush dev "$AP_IFACE"
ip addr add "$GW_IP/24" dev "$AP_IFACE"
ip link set "$AP_IFACE" up

echo "[2/5] writing /etc/hostapd/zta-ap.conf"
install -d -m 755 /etc/hostapd
umask 077
cat > /etc/hostapd/zta-ap.conf <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
country_code=$COUNTRY
hw_mode=g
channel=$CHANNEL
ieee80211n=1
wmm_enabled=1
# Clients cannot talk to each other directly over the air, so every packet
# goes through the gateway and can be seen and scored.
ap_isolate=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$ZTA_AP_PASSPHRASE
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
EOF
umask 022

echo "[3/5] writing /etc/dnsmasq.d/zta-ap.conf"
install -d /etc/dnsmasq.d
cat > /etc/dnsmasq.d/zta-ap.conf <<EOF
interface=$AP_IFACE
bind-interfaces
dhcp-range=$DHCP_FROM,$DHCP_TO,255.255.255.0,12h
dhcp-option=option:router,$GW_IP
dhcp-option=option:dns-server,$GW_IP
log-queries
EOF

echo "[4/5] enabling forwarding and NAT out of $UPLINK"
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -o "$UPLINK" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o "$UPLINK" -j MASQUERADE
iptables -C FORWARD -i "$AP_IFACE" -o "$UPLINK" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$AP_IFACE" -o "$UPLINK" -j ACCEPT
iptables -C FORWARD -i "$UPLINK" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$UPLINK" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[5/5] starting dnsmasq and hostapd"
systemctl restart dnsmasq
pkill hostapd 2>/dev/null || true
hostapd -B /etc/hostapd/zta-ap.conf

cat <<EOF

Access point "$SSID" is up on $AP_IFACE ($GW_IP/24).
Now start the gateway with the Wi-Fi interface selected:

  sudo ZTA_INTERNAL_IFACE=$AP_IFACE ZTA_UPLINK_IFACE=$UPLINK ./venv/bin/python run.py

Check associated clients:  iw dev $AP_IFACE station dump
EOF
