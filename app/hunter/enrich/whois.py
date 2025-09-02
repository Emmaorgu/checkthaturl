# app/hunter/enrich/whois.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple
from functools import lru_cache
import socket
import logging
import requests

# — Quiet the python-whois logger; we'll only use it as a fallback —
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)

try:
    import whois as pywhois  # pip install python-whois
except Exception:
    pywhois = None


# ---------- Helpers ----------
def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Try a few common RDAP formats
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return _as_utc(datetime.strptime(s, fmt))
        except Exception:
            pass
    try:
        # best-effort ISO
        return _as_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except Exception:
        return None

def _rdap_registrar_name(entities: List[Dict[str, Any]]) -> Optional[str]:
    if not entities:
        return None
    for e in entities:
        roles = [r.lower() for r in (e.get("roles") or [])]
        if "registrar" in roles:
            v = e.get("vcardArray")
            # vcardArray looks like ["vcard", [[ "fn", {}, "text", "Registrar, Inc." ], ...]]
            if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], list):
                for item in v[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
    return None

def _rdap_nameservers(objs: List[Dict[str, Any]]) -> List[str]:
    out = []
    for ns in objs or []:
        n = ns.get("ldhName") or ns.get("unicodeName")
        if n:
            out.append(str(n).rstrip("."))
    return out

def _rdap_events(events: List[Dict[str, Any]]) -> Tuple[Optional[datetime], Optional[datetime], Optional[datetime]]:
    created = updated = expires = None
    for ev in events or []:
        action = (ev.get("eventAction") or "").lower()
        ts = _parse_dt(ev.get("eventDate"))
        if action in {"registration", "registered"} and ts and (created is None or ts < created):
            created = ts
        elif action in {"last changed", "last changed date", "last update of rdap database"} and ts:
            updated = ts
        elif action in {"expiration", "expiry"} and ts:
            expires = ts
    return created, updated, expires

def _age_days(created: Optional[datetime]) -> Optional[int]:
    if not created:
        return None
    now = datetime.now(timezone.utc)
    return max(0, (now - created).days)

def _risk_from_age(age_days: Optional[int]) -> float:
    if age_days is None:
        return 0.15  # missing WHOIS data => small risk
    if age_days < 7:      return 1.00
    if age_days < 30:     return 0.70
    if age_days < 90:     return 0.40
    if age_days < 365:    return 0.15
    return 0.0


# ---------- RDAP (HTTPS JSON) ----------
def _rdap_lookup(domain: str, timeout: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": 0, "error": None}
    try:
        # rdap.org is a multiplexer (works for most TLDs) over HTTPS
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=timeout,
        )
        if r.status_code != 200:
            out["error"] = f"rdap_http_{r.status_code}"
            return out
        data = r.json()
    except Exception as e:
        out["error"] = f"rdap_{type(e).__name__}"
        return out

    created, updated, expires = _rdap_events(data.get("events") or [])
    registrar = _rdap_registrar_name(data.get("entities") or [])
    nameservers = _rdap_nameservers(data.get("nameservers") or [])
    age = _age_days(created)

    out.update({
        "ok": 1,
        "domain": domain,
        "created": created.isoformat() if created else None,
        "updated": updated.isoformat() if updated else None,
        "expires": expires.isoformat() if expires else None,
        "age_days": age,
        "registrar": registrar,
        "name_servers": nameservers,
        "whois_risk": _risk_from_age(age),
        "source": "rdap",
    })
    return out


# ---------- Fallback: python-whois (port 43) ----------
class _TempSocketTimeout:
    def __init__(self, seconds: float): self.seconds, self._old = seconds, None
    def __enter__(self): self._old = socket.getdefaulttimeout(); socket.setdefaulttimeout(self.seconds)
    def __exit__(self, exc_type, exc, tb): socket.setdefaulttimeout(self._old)

def _whois_lookup(domain: str, timeout: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": 0, "error": None}
    if not pywhois:
        out["error"] = "python-whois-not-installed"
        out["whois_risk"] = 0.0
        return out
    try:
        with _TempSocketTimeout(timeout):
            w = pywhois.whois(domain)
    except Exception as e:
        out["error"] = f"whois_{type(e).__name__}"
        out["whois_risk"] = 0.0
        return out

    def _as_dt_any(x) -> Optional[datetime]:
        # python-whois returns dt | [dt] | str | None
        if isinstance(x, list):
            for v in x:
                if isinstance(v, datetime):
                    return _as_utc(v)
        if isinstance(x, datetime):
            return _as_utc(x)
        if isinstance(x, str):
            try:
                return _as_utc(datetime.fromisoformat(x))
            except Exception:
                pass
        return None

    created = _as_dt_any(getattr(w, "creation_date", None))
    updated = _as_dt_any(getattr(w, "updated_date", None))
    expires = _as_dt_any(getattr(w, "expiration_date", None))
    registrar = getattr(w, "registrar", None)
    name_servers = getattr(w, "name_servers", None)
    if isinstance(name_servers, (set, tuple)):
        name_servers = list(name_servers)
    age = _age_days(created)

    out.update({
        "ok": 1,
        "domain": domain,
        "created": created.isoformat() if created else None,
        "updated": updated.isoformat() if updated else None,
        "expires": expires.isoformat() if expires else None,
        "age_days": age,
        "registrar": registrar,
        "name_servers": name_servers,
        "whois_risk": _risk_from_age(age),
        "source": "whois",
    })
    return out


# ---------- Public API (cached) ----------
@lru_cache(maxsize=8192)
def _lookup_cached(domain: str) -> Dict[str, Any]:
    # Try RDAP first
    rd = _rdap_lookup(domain, timeout=6.0)
    if rd.get("ok"):
        return rd
    # Fallback to classic WHOIS only if RDAP failed
    return _whois_lookup(domain, timeout=6.0)

def lookup(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Resolve WHOIS via RDAP (HTTPS JSON) first, fallback to classic WHOIS.
    Returns a dict with created/updated/expires/age_days/registrar/name_servers + whois_risk∈[0,1].
    """
    try:
        return dict(_lookup_cached(domain))
    except Exception as e:
        return {"ok": 0, "error": f"lookup_{type(e).__name__}", "whois_risk": 0.0}
