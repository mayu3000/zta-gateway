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


def _ensure_default_drops():
    """Keep exactly one default DROP per interface, always as the LAST rules.

    iptables is first-match-wins, so a per-MAC ACCEPT (grant) is only effective
    if it sits *above* the catch-all DROP. Every time a ban or grant is added we
    delete and re-append the default DROP, which moves it back to the end of the
    chain and leaves the freshly added ACCEPT/DROP rules ahead of it.
    """
    for iface in cfg.INTERNAL_IFACES:
        # Delete if present (a no-op/ignored error if it is not).
        _run(["iptables", "-D", FORWARD_CHAIN, "-i", iface, "-j", "DROP"])
        # Re-append so it is last again.
        _run(["iptables", "-A", FORWARD_CHAIN, "-i", iface, "-j", "DROP"])


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
    # Order per interface is: banned DROP  >  granted ACCEPT  >  default DROP.
    # Bans are inserted at the top by sync_bans(); grants are appended by
    # grant_access(); both then call _ensure_default_drops() so the catch-all
    # DROP always ends up last (and thus never shadows a granted ACCEPT).
    _ensure_default_drops()

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

    # Push the catch-all DROP back to the end so the ACCEPT above stays
    # reachable (first-match-wins).
    _ensure_default_drops()

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
    """Reconcile ban DROP rules in ZTA_FORWARD. Idempotent.

    Removes the existing per-MAC ban DROPs and re-inserts the current set at the
    TOP of the chain so bans always outrank grants. Crucially this does **not**
    flush the chain: a blanket `-F` would also wipe the ACCEPT grants added by
    grant_access(), silently cutting off every already-signed-in device.
    """
    if not _enabled():
        return

    # 1. Remove only the existing per-MAC ban DROPs (never the default DROP,
    #    never the grant ACCEPTs).
    ok, listing = _run(["iptables", "-S", FORWARD_CHAIN])
    if ok:
        for line in (listing or "").splitlines():
            if "-m mac --mac-source" not in line:
                continue                      # default DROP / jump / not ours
            if not line.rstrip().endswith("-j DROP"):
                continue                      # e.g. a grant ACCEPT
            spec = line.split()
            if spec and spec[0] in ("-A", "-I"):
                spec = spec[1:]               # drop the action flag
            if spec and spec[0] == FORWARD_CHAIN:
                _run(["iptables", "-D"] + spec)

    # 2. Insert the current bans at the top so they outrank grants.
    for mac in active_ban_macs:
        for iface in cfg.INTERNAL_IFACES:
            ok, _ = _run(["iptables", "-C", FORWARD_CHAIN,
                          "-i", iface, "-m", "mac", "--mac-source", mac,
                          "-j", "DROP"])
            if not ok:
                _run(["iptables", "-I", FORWARD_CHAIN, "1",
                      "-i", iface, "-m", "mac", "--mac-source", mac,
                      "-j", "DROP"])

    # 3. Keep the catch-all DROP last.
    _ensure_default_drops()

    log.info("[portal] sync_bans: %d banned MACs", len(active_ban_macs))
