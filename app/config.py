"""Deployment network constants (Option A inline-bridging target: Kali VM, dual-NIC).

These drive discovery, sniffing, and the captive portal. The sniffer defaults
to INTERNAL_IFACE, so the argless `start_sniffing()` in run.py automatically
binds the right interface on either deployment target.

On the Kali VM (inline bridging):
  eth0 = uplink to the internet/WAN
  eth1 = internal-facing, hosts live on this subnet
"""

# Internal (eth1) subnet
INTERNAL_SUBNET = "192.168.50.0/24"

# Gateway's own address on the internal interface
GATEWAY_INTERNAL_IP = "192.168.50.1"

# Interface names (Linux); resolved by Scapy on Windows via _pick_interface
INTERNAL_IFACE = "eth1"
UPLINK_IFACE = "eth0"
