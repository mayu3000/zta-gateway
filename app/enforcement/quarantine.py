"""Enforcement engine — quarantine/release a device on the wire.

Three modes, selected once at startup via the ZTA_ENFORCE env var
(defaults to auto-detect: iptables on Linux+root, recorded-only otherwise):

  iptables  — inline firewall: DROP all FORWARD traffic from the target IP.
              Requires root on Linux (`sudo venv/bin/python run.py`).
  arp       — ARP-spoof loop (the original Option B). Continuously spoofs
              replies telling the target the gateway has a bogus MAC.
  recorded  — DB + forensic log only; no on-wire effect. Used on Windows
              (injection unreliable) and during test runs (set
              ZTA_ENFORCE=recorded to keep iptables out of the test suite).

INJECTION_AVAILABLE is True for both iptables and arp modes (the device will
actually be isolated); False for recorded (DB + log only).  run.py uses it
for the startup banner and per-ban log messages.
"""
import os
import platform
import re
import subprocess
import threading
import time

# --- mode resolution ----------------------------------------------------------

def _is_linux_root():
    """True when running on Linux/Unix and as effective root."""
    try:
        return platform.system() != "Windows" and os.geteuid() == 0
    except (AttributeError, OSError):  # Windows has no geteuid
        return False

def _resolve_mode():
    """Pick enforcement mode once at import time."""
    env = os.environ.get("ZTA_ENFORCE", "").strip().lower()
    if env in ("iptables", "arp", "recorded"):
        return env
    if _is_linux_root():
        return "iptables"
    return "recorded"

ENFORCEMENT_MODE = _resolve_mode()
INJECTION_AVAILABLE = ENFORCEMENT_MODE != "recorded"

# --- ARP spoofing (legacy path, active only in arp mode) ----------------------

try:
    from scapy.all import ARP, send as _scapy_send
    _HAS_SCAPY = True
except Exception:  # noqa: BLE001 — env may lack Npcap/scapy; degrade gracefully
    ARP = _scapy_send = None
    _HAS_SCAPY = False

BOGUS_MAC = "00:00:00:00:00:00"
_active_quarantines = {}   # mac -> stop_event (arp) or None (iptables/recorded)


def _spoof_loop(target_ip, target_mac, gateway_ip, stop_event):
    """Tell the target its ARP entry for the gateway is invalid, every 2s."""
    while not stop_event.is_set():
        if _HAS_SCAPY:
            spoofed = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                          psrc=gateway_ip, hwsrc=BOGUS_MAC)
            _scapy_send(spoofed, verbose=0)
        time.sleep(2)

# --- iptables helpers ---------------------------------------------------------

def _iptables_add(ip):
    """Insert a FORWARD DROP rule for the target IP. No-op when ip is falsy."""
    if not ip:
        return
    subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
                   check=False)

def _iptables_del(ip):
    """Remove the FORWARD DROP rule for the target IP (if it exists)."""
    if not ip:
        return
    subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                   check=False)

# --- public API ---------------------------------------------------------------

def quarantine_device(target_ip, target_mac, gateway_ip=None):
    """Block *target_mac* on the wire according to the active mode.

    Returns True if the device is actually isolated on the wire;
    False if the action was recorded only (DB + forensic log).
    """
    if target_mac in _active_quarantines:
        return INJECTION_AVAILABLE

    if ENFORCEMENT_MODE == "iptables":
        _iptables_add(target_ip)
        _active_quarantines[target_mac] = None
        return True

    if ENFORCEMENT_MODE == "arp" and _HAS_SCAPY:
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_spoof_loop,
            args=(target_ip, target_mac, gateway_ip, stop_event),
            daemon=True,
        )
        thread.start()
        _active_quarantines[target_mac] = stop_event
        return True

    # recorded-only fallback (Windows / tests)
    _active_quarantines[target_mac] = None
    return False


def release_device(target_ip, target_mac):
    """Remove the quarantine for *target_mac*.

    On Linux + iptables the DROP rule is deleted.  On arp mode the spoof
    thread is stopped.  On recorded mode the registration is simply removed.
    """
    stop_event = _active_quarantines.pop(target_mac, None)
    if stop_event is not None and ENFORCEMENT_MODE == "arp":
        stop_event.set()
    elif ENFORCEMENT_MODE == "iptables":
        _iptables_del(target_ip)


def active_quarantines():
    """MACs currently registered as quarantined (on-wire or recorded-only)."""
    return list(_active_quarantines)
