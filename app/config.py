"""Deployment network constants.

Every value can be overridden with an environment variable, so the same code
runs on all three deployment targets without edits:

  Option A, wired    : ZTA_INTERNAL_IFACE=eth1  (default)
  Option A, Wi-Fi AP : ZTA_INTERNAL_IFACE=wlan0 (hostapd on a USB adapter)
  Windows / Option B : values are ignored, the sniffer picks the adapter by subnet

These drive discovery, sniffing, and the captive portal. The sniffer defaults
to INTERNAL_IFACE, so the argless `start_sniffing()` in run.py automatically
binds the right interface on either deployment target.

Kali VM layout:
  UPLINK_IFACE   = path to the internet/WAN (home router)
  INTERNAL_IFACE = the side clients connect to (Ethernet port or Wi-Fi AP)
"""
import os

# Internal subnet served by dnsmasq on INTERNAL_IFACE
INTERNAL_SUBNET = os.environ.get("ZTA_INTERNAL_SUBNET", "192.168.50.0/24")

# Gateway's own address on the internal interface
GATEWAY_INTERNAL_IP = os.environ.get("ZTA_GATEWAY_IP", "192.168.50.1")

# Interface names (Linux); resolved by Scapy on Windows via _pick_interface
INTERNAL_IFACE = os.environ.get("ZTA_INTERNAL_IFACE", "eth1")
UPLINK_IFACE = os.environ.get("ZTA_UPLINK_IFACE", "eth0")

# A device counts as "connected" if the discovery sensor saw it within this many
# seconds. The sensor runs every 30s (run.py), so 90s tolerates two missed scans.
CONNECTED_TTL_SECONDS = int(os.environ.get("ZTA_CONNECTED_TTL", "90"))
