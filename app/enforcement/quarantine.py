"""ARP-based quarantine (Option B enforcement).

Continuously spoof ARP replies to the target device telling it the gateway is
at an unreachable MAC, cutting it off from routing traffic anywhere — the same
mechanism attackers use offensively, applied defensively here so no router
firewall rule has to be touched.

Platform caveat (consistent with the Phase 1 ARP-scan finding): active packet
injection via Npcap on this Windows/MinGW box is unreliable. On Linux this
module truly isolates the target; on Windows the QUARANTINE action is still
recorded in the DB, traceback and forensic log in full, but the spoof loop is
skipped unless injection proves to work here. The log records which mode ran.
"""
import platform
import threading
import time

try:
    from scapy.all import ARP, send
    _HAS_SCAPY = True
except Exception:  # noqa: BLE001 — env may lack Npcap/scapy; degrade gracefully
    ARP = send = None
    _HAS_SCAPY = False

# Windows/MinGW scapy raw-socket injection is unreliable for ARP on this box.
INJECTION_AVAILABLE = _HAS_SCAPY and platform.system().lower() != "windows"

BOGUS_MAC = "00:00:00:00:00:00"

_active_quarantines = {}   # mac -> stop_event


def _spoof_loop(target_ip, target_mac, gateway_ip, stop_event):
    """Tell the target its ARP entry for the gateway is invalid, every 2s."""
    while not stop_event.is_set():
        if _HAS_SCAPY:
            spoofed = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                          psrc=gateway_ip, hwsrc=BOGUS_MAC)
            send(spoofed, verbose=0)
        time.sleep(2)


def quarantine_device(target_ip, target_mac, gateway_ip="192.168.1.1"):
    """Start spoofing for `target_mac`. Returns True if actually quarantining
    on the wire, False if it's a recorded-only (Windows fallback) quarantine."""
    if target_mac in _active_quarantines:
        return INJECTION_AVAILABLE
    stop_event = threading.Event()
    if INJECTION_AVAILABLE:
        thread = threading.Thread(target=_spoof_loop,
                                  args=(target_ip, target_mac, gateway_ip,
                                        stop_event),
                                  daemon=True)
        thread.start()
    # On Windows we still register the MAC so release_device / status stays
    # coherent and the dashboard Active Bans + traceback flow works end-to-end.
    _active_quarantines[target_mac] = stop_event
    return INJECTION_AVAILABLE


def release_device(target_mac):
    stop_event = _active_quarantines.pop(target_mac, None)
    if stop_event:
        stop_event.set()


def active_quarantines():
    """MACs currently registered as quarantined (spoofed or recorded-only)."""
    return list(_active_quarantines)