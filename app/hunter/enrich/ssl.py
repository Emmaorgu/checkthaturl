# app/hunter/enrich/ssl.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
import socket, ssl

def _parse_notafter(s: str | None) -> datetime | None:
    if not s:
        return None
    # Typical format: 'May  1 12:00:00 2025 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z",):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None

def _match_san(host: str, sans: List[Tuple[str, str]]) -> bool:
    host = host.lower()
    names = [v.lower() for k, v in sans if k == "DNS"]
    for n in names:
        if n.startswith("*."):
            # wildcard only covers one label
            suf = n[1:]  # '.example.com'
            if host.endswith(suf) and host.count(".") == n.count("."):
                return True
        elif n == host:
            return True
    return False

def fetch(host: str, timeout: float = 5.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": 0, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we do manual matching
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        out["error"] = f"{type(e).__name__}"
        out["ssl_risk"] = 0.5  # handshake failures are somewhat suspicious but not decisive
        return out

    not_after = _parse_notafter(cert.get("notAfter"))
    now = datetime.now(timezone.utc)
    valid = None
    days_left = None
    if not_after:
        days_left = int((not_after - now).total_seconds() // 86400)
        valid = days_left > 0

    issuer = cert.get("issuer")
    subject = cert.get("subject")
    sans = cert.get("subjectAltName") or []

    name_ok = _match_san(host, sans) if sans else False

    # risk:
    risk = 0.0
    if valid is False:
        risk += 0.9
    if not name_ok:
        risk += 0.25
    # very fresh certs can be riskier for phishing pop-ups
    if not_after and days_left is not None and days_left > 0:
        # approximate "freshness" via cert lifetime; we don't have notBefore, so we can't be precise
        pass  # keep simple; we already have WHOIS age signal

    out.update({
        "ok": 1,
        "issuer": issuer,
        "subject": subject,
        "san": sans,
        "not_after": not_after.isoformat() if not_after else None,
        "days_left": days_left,
        "name_matches_host": bool(name_ok),
        "ssl_risk": min(1.0, max(0.0, risk)),
    })
    return out
