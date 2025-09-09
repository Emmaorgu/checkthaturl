# app/hunter/workers/enrich.py
from __future__ import annotations

import argparse
import socket
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Single source of truth for app + db
from app.app import app as flask_app, db
from app.hunter.models import DiscoveredURL, Enrichment, URLStatus

# Optional helpers if you already have modules in app/hunter/enrich/*
try:
    from app.hunter.enrich.whois import lookup_whois  # returns dict or None
except Exception:
    lookup_whois = None  # we'll degrade gracefully

try:
    from app.hunter.enrich.dns import resolve_dns  # returns dict or None
except Exception:
    resolve_dns = None  # degrade gracefully

try:
    from app.hunter.enrich.ssl import fetch_ssl  # returns dict or None
except Exception:
    fetch_ssl = None  # degrade gracefully


def _safe_whois(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Try your module first; otherwise return a minimal stub."""
    if lookup_whois:
        try:
            return lookup_whois(domain, timeout=timeout)
        except Exception:
            return None
    # Minimal stub: unknown age; caller will handle scoring conservatively.
    return None


def _safe_dns(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Try your module first; else use socket.getaddrinfo as a lightweight fallback."""
    if resolve_dns:
        try:
            return resolve_dns(domain, timeout=timeout)
        except Exception:
            pass
    try:
        # basic A/AAAA presence check
        socket.setdefaulttimeout(timeout)
        rows = socket.getaddrinfo(domain, 80)
        addrs = sorted({r[4][0] for r in rows if r and r[4]})
        return {"a_aaaa": addrs, "count": len(addrs)}
    except Exception:
        return None


def _safe_ssl(domain: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Use your SSL fetcher if present; otherwise skip for speed."""
    if fetch_ssl:
        try:
            return fetch_ssl(domain, timeout=timeout)
        except Exception:
            return None
    return None


_BAD_TLDS = {
    "xyz", "top", "tk", "gq", "ml", "cf", "quest", "info", "cam", "monster",
    "click", "link", "buzz", "cyou", "work", "rest", "casa", "live"
}


def _tld(domain: str) -> str:
    parts = (domain or "").lower().split(".")
    return parts[-1] if len(parts) >= 2 else ""


def _age_days_from_whois(w: Optional[Dict[str, Any]]) -> Optional[int]:
    """Try common fields produced by whois libraries or your own module."""
    if not w:
        return None
    for key in ("creation_date", "created", "created_date", "registered_on"):
        val = w.get(key)
        if not val:
            continue
        # some libs return datetime, others string
        if isinstance(val, datetime):
            dt = val
        elif isinstance(val, (list, tuple)) and val and isinstance(val[0], datetime):
            dt = val[0]
        elif isinstance(val, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y/%m/%d"):
                try:
                    dt = datetime.strptime(val[:19], fmt)
                    break
                except Exception:
                    dt = None
            if dt is None:
                continue
        else:
            continue
        return max(0, (datetime.utcnow() - dt).days)
    return None


def _compute_passive_score(domain: str, whois_json, dns_json, ssl_json) -> float:
    """
    Simple, transparent scoring in [0,1]:
      +0.45 if WHOIS age < 14 days
      +0.25 if TLD in _BAD_TLDS
      +0.15 if no DNS resolution
      +0.15 if SSL info missing where we'd expect it (heuristic)
    """
    score = 0.0
    # WHOIS age
    age = _age_days_from_whois(whois_json)
    if age is not None and age < 14:
        score += 0.45

    # Suspicious TLD
    if _tld(domain) in _BAD_TLDS:
        score += 0.25

    # DNS presence
    if not dns_json or not (dns_json.get("a_aaaa") or dns_json.get("records")):
        score += 0.15

    # SSL presence heuristic (domain looks like a site but we couldn't fetch ssl info)
    if ssl_json is None:
        score += 0.15

    # clip
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return round(score, 3)


def run(batch: int, timeout: int) -> Dict[str, int]:
    """
    Enrich up to `batch` DiscoveredURL rows that don't have an Enrichment yet.
    Persist WHOIS/DNS/SSL JSON and a passive_score in [0,1].
    """
    inserted = skipped = 0

    with flask_app.app_context():
        # Select URLs with NO enrichment yet (one-time enrichment is fine for Phase 1)
        from sqlalchemy import select, exists
        subq = select(Enrichment.id).where(Enrichment.url_id == DiscoveredURL.id).limit(1)
        stmt = (
            select(DiscoveredURL)
            .where(~exists(subq))
            .order_by(DiscoveredURL.first_seen.asc())
            .limit(batch)
        )
        rows = list(db.session.scalars(stmt).all())
        if not rows:
            return {"inserted": 0, "skipped": 0, "batch": batch}

        for d in rows:
            domain = d.domain
            try:
                whois_json = _safe_whois(domain, timeout=timeout)
                dns_json   = _safe_dns(domain, timeout=timeout)
                ssl_json   = _safe_ssl(domain, timeout=timeout)

                passive = _compute_passive_score(domain, whois_json, dns_json, ssl_json)

                enr = Enrichment(
                    url_id=d.id,
                    whois_json=whois_json,
                    dns_json=dns_json,
                    ssl_json=ssl_json,
                    passive_score=passive,
                )
                db.session.add(enr)

                # Optional: move status forward for scheduling clarity
                if d.status == URLStatus.NEW.value:
                    d.status = URLStatus.ENRICHED.value

                inserted += 1
            except Exception:
                db.session.rollback()
                skipped += 1
            else:
                db.session.commit()

    return {"inserted": inserted, "skipped": skipped, "batch": batch}


def main():
    p = argparse.ArgumentParser(description="Hunter passive enrichment worker.")
    p.add_argument("--batch", type=int, default=100, help="Max URLs to enrich this run")
    p.add_argument("--timeout", type=int, default=6, help="Per-network call timeout (seconds)")
    args = p.parse_args()

    t0 = time.monotonic()
    res = run(batch=args.batch, timeout=args.timeout)
    res["elapsed_s"] = round(time.monotonic() - t0, 2)
    print(res)


if __name__ == "__main__":
    main()
