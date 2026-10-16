"""Portal gate firewall module (P1.1).

Manages iptables/nftables rules that enforce network-level captive-portal gating.
All operations are idempotent: safe to call repeatedly without duplicating rules.

On Windows or when ZTA_PORTAL_GATE=0 every function is a no-op.
"""
import subprocess
import logging

from app import config as cfg

log = logging.getLogger(__name__)

# --- safety net ---------------------------------------------------------------

def _run(args):
    """Run an iptables command. Returns (ok, output). Mocked in tests."""
    cmd = ["sudo"] + args if _needs_sudo() else args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return ok, output
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def _needs_sudo():
    """Check if we need sudo (non-root Linux)."""
    import os
    return os.name == "posix" and os.geteuid() != 0


def _enabled():
    """Check if the portal gate is enabled."""
    if not cfg.PORTAL_GATE:
        return False
    return True


# --- chain management ---------------------------------------------------------

FORWARD_CHAIN = "ZTA_FORWARD"
NAT_CHAIN = "ZTA_PREROUTING"


def _ensure_forward_chain():
    """Create ZTA_FORWARD if it doesn't exist, flush it, and jump to it."""
    # Create chain (ignore "File exists" error)
    _run(["iptables", "-N", FORWARD_CHAIN])
    # Flush existing rules
    _run(["iptables", "-F", FORWARD_CHAIN])
    # Add jump from FORWARD if not already there
    ok, _ = _run(["iptables", "-C", "FORWARD", "-j", FORWARD_CHAIN])
    if not ok:
        _run(["iptables", "-I", "FORWARD", "1", "-j", FORWARD_CHAIN])


def _ensure_nat_chain():
    """Create ZTA_PREROUTING in the nat table if it doesn't exist, flush it,
    and jump to it from PREROUTING."""
    _run(["iptables", "-t", "nat", "-N", NAT_CHAIN])
    _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
    ok, _ = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
    if not ok:
        _run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", NAT_CHAIN])


def setup_gate():
    """Set up the complete portal gate. Idempotent.

    Rule order per interface in ZTA_FORWARD:
      1. Banned MACs DROP
      2. Granted MACs ACCEPT
      3. Default DROP

    In nat ZTA_PREROUTING per interface:
      1. Granted MACs RETURN (skip redirect)
      2. Everything else DNAT tcp/80 to gateway:80
    """
    if not _enabled():
        return

    _ensure_forward_chain()
    _ensure_nat_chain()

    # --- FORWARD chain ---
    for iface in cfg.INTERNAL_IFACES:
        # 1. Banned MACs DROP (filled by sync_bans)
        # (bans are added individually by sync_bans)

        # 2. Granted MACs ACCEPT (filled by grant_access)
        # (grants are added individually by grant_access)

        # 3. Default DROP for this interface
        _run(["iptables", "-A", FORWARD_CHAIN,
              "-i", iface, "-j", "DROP"])

    # --- nat PREROUTING chain ---
    for iface in cfg.INTERNAL_IFACES:
        # Granted MACs RETURN (skip DNAT) -- filled by grant_access
        _run(["iptables", "-t", "nat", "-A", NAT_CHAIN,
              "-i", iface, "-p", "tcp", "--dport", "80",
              "-j", "DNAT", "--to-dest", f"{cfg.GATEWAY_INTERNAL_IP}:80"])

    log.info("[portal] gate ON, interfaces: %s",
             ",".join(cfg.INTERNAL_IFACES))


def teardown_gate():
    """Remove all portal gate rules. Idempotent."""
    if not _enabled():
        return

    # Remove jump from FORWARD
    _run(["iptables", "-D", "FORWARD", "-j", FORWARD_CHAIN])
    # Remove jump from PREROUTING
    _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN])
    # Flush and delete chains
    _run(["iptables", "-F", FORWARD_CHAIN])
    _run(["iptables", "-X", FORWARD_CHAIN])
    _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
    _run(["iptables", "-t", "nat", "-X", NAT_CHAIN])


# --- grant / revoke -----------------------------------------------------------

def grant_access(mac):
    """Grant network access to a MAC address. Idempotent.

    Adds an ACCEPT rule in ZTA_FORWARD for each internal interface,
    and a RETURN rule in nat ZTA_PREROUTING to skip the portal redirect.
    """
    if not _enabled():
        return

    for iface in cfg.INTERNAL_IFACES:
        # ACCEPT in FORWARD
        ok, _ = _run(["iptables", "-C", FORWARD_CHAIN,
                      "-i", iface, "-m", "mac", "--mac-source", mac,
                      "-j", "ACCEPT"])
        if not ok:
            _run(["iptables", "-A", FORWARD_CHAIN,
                  "-i", iface, "-m", "mac", "--mac-source", mac,
                  "-j", "ACCEPT"])

        # RETURN in nat PREROUTING (skip DNAT)
        ok, _ = _run(["iptables", "-t", "nat", "-C", NAT_CHAIN,
                      "-i", iface, "-m", "mac", "--mac-source", mac,
                      "-p", "tcp", "--dport", "80",
                      "-j", "RETURN"])
        if not ok:
            _run(["iptables", "-t", "nat", "-I", NAT_CHAIN,
                  "-i", iface, "-m", "mac", "--mac-source", mac,
                  "-p", "tcp", "--dport", "80",
                  "-j", "RETURN"])

    log.info("[portal] grant_access: %s", mac)


def revoke_access(mac):
    """Revoke network access for a MAC address. Idempotent (ignores missing)."""
    if not _enabled():
        return

    for iface in cfg.INTERNAL_IFACES:
        # Remove from FORWARD
        _run(["iptables", "-D", FORWARD_CHAIN,
              "-i", iface, "-m", "mac", "--mac-source", mac,
              "-j", "ACCEPT"])
        # Remove from nat PREROUTING
        _run(["iptables", "-t", "nat", "-D", NAT_CHAIN,
              "-i", iface, "-m", "mac", "--mac-source", mac,
              "-p", "tcp", "--dport", "80",
              "-j", "RETURN"])

    log.info("[portal] revoke_access: %s", mac)


def is_granted(mac):
    """Check if a MAC has a grant ACCEPT rule."""
    if not _enabled():
        return False
    for iface in cfg.INTERNAL_IFACES:
        ok, _ = _run(["iptables", "-C", FORWARD_CHAIN,
                      "-i", iface, "-m", "mac", "--mac-source", mac,
                      "-j", "ACCEPT"])
        if ok:
            return True
    return False


# --- ban sync -----------------------------------------------------------------

def sync_bans(active_ban_macs):
    """Re-add DROP rules for all currently banned MACs. Idempotent.

    Removes old ban DROPs first, then re-adds from the provided set.
    """
    if not _enabled():
        return

    # Flush and re-add ban DROPs at the top of ZTA_FORWARD
    # (bans must sit above grants)
    _run(["iptables", "-F", FORWARD_CHAIN])

    for mac in active_ban_macs:
        for iface in cfg.INTERNAL_IFACES:
            ok, _ = _run(["iptables", "-C", FORWARD_CHAIN,
                          "-i", iface, "-m", "mac", "--mac-source", mac,
                          "-j", "DROP"])
            if not ok:
                _run(["iptables", "-A", FORWARD_CHAIN,
                      "-i", iface, "-m", "mac", "--mac-source", mac,
                      "-j", "DROP"])

    # Re-add default DROP per interface
    for iface in cfg.INTERNAL_IFACES:
        ok, _ = _run(["iptables", "-C", FORWARD_CHAIN,
                      "-i", iface, "-j", "DROP"])
        if not ok:
            _run(["iptables", "-A", FORWARD_CHAIN,
                  "-i", iface, "-j", "DROP"])

    log.info("[portal] sync_bans: %d banned MACs", len(active_ban_macs))
