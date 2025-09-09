# app/hunter/enrich/dns.py
from __future__ import annotations
from typing import Optional, Dict, Any
import socket

def resolve_dns(domain: str, timeout: int = 6) -> Optional[Dict[str, Any]]:
    """
    Very light DNS presence check so the editor stops flagging imports.
    The enrich worker already has a socket fallback; this mirrors it.
    """
    try:
        socket.setdefaulttimeout(timeout)
        rows = socket.getaddrinfo(domain, 80)
        addrs = sorted({r[4][0] for r in rows if r and r[4]})
        return {"a_aaaa": addrs, "count": len(addrs)}
    except Exception:
        return None
