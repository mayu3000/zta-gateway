"""Network risk: DNS queries against a blocklist + connection to suspicious ports.

The full blocklist lives in `blocklist.txt` (downloaded open-source hosts file,
gitignored). If it isn't present, a small built-in seed of well-known
ad/tracker domains keeps the feature working and testable out of the box.
"""
import os

_BLOCKLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.txt")

# Seed so network risk works even before the full list is downloaded. These are
# widely-known ad/tracker domains (present in every public blocklist).
_BUILTIN = {
    "doubleclick.net",
    "ads.doubleclick.net",
    "googleadservices.com",
    "adservice.google.com",
    "scorecardresearch.com",
    "adnxs.com",
    "googlesyndication.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
}

SUSPICIOUS_PORTS = {23, 445, 3389, 6667}   # telnet, SMB, RDP, IRC — common attack/C2 ports


def load_blocklist(path: str = _BLOCKLIST_PATH):
    domains = set(_BUILTIN)
    if not os.path.exists(path):
        print(f"[network_risk] blocklist not found at {path}; using built-in seed "
              f"({len(domains)} domains)", flush=True)
        return domains
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) >= 2:
                    domains.add(parts[1].lower())
    print(f"[network_risk] loaded {len(domains)} domains from blocklist", flush=True)
    return domains


BLOCKLIST = load_blocklist()


def _is_blocked(domain: str, blocklist) -> bool:
    """Exact or parent-domain match, e.g. ads.doubleclick.net -> doubleclick.net."""
    d = domain.lower().rstrip(".")
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in blocklist:
            return True
    return False


def compute_network_risk(dns_queries, dst_ports) -> tuple[int, list]:
    """Return (score 0-100, list of flagged domain names)."""
    flagged = sorted({d for d in dns_queries if _is_blocked(d, BLOCKLIST)})
    port_hits = dst_ports & SUSPICIOUS_PORTS

    score = min(len(flagged) * 40, 80) + min(len(port_hits) * 20, 20)
    return min(score, 100), flagged


def is_blocked_domain(domain: str) -> bool:
    """Public accessor used by DNSLog persistence (Phase 7)."""
    return _is_blocked(domain, BLOCKLIST)