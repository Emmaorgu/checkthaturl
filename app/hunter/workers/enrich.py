# app/hunter/workers/enrich.py
from __future__ import annotations
import argparse, sys
from typing import Dict, Any

from app.app import app as flask_app
from app.db import db
from app.hunter.models import DiscoveredURL, Enrichment, URLStatus
from app.hunter.enrich.whois import lookup as whois_lookup
from app.hunter.enrich.dns import resolve as dns_resolve
from app.hunter.enrich.ssl import fetch as ssl_fetch

def _clip01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x

def _combine_score(whois_risk: float, dns_risk: float, ssl_risk: float) -> float:
    return _clip01(0.5*whois_risk + 0.3*dns_risk + 0.2*ssl_risk)

def _registrable_domain(norm: str) -> str:
    from urllib.parse import urlparse
    host = (urlparse(norm).netloc or "").split(":")[0].lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def enrich_one(row: DiscoveredURL, timeout: float) -> Dict[str, Any]:
    domain = row.domain or _registrable_domain(row.normalized)
    w = whois_lookup(domain, timeout=timeout)
    d = dns_resolve(domain, timeout=max(2.0, timeout-0.5))
    s = {}
    # only try SSL if DNS has A/AAAA and not NXDOMAIN
    if d.get("ok") and not d.get("nxdomain") and (d.get("a") or d.get("aaaa")):
        s = ssl_fetch(domain, timeout=max(2.5, timeout))
    else:
        s = {"ok": 0, "error": "dns_unresolved", "ssl_risk": 0.0}

    passive_score = _combine_score(float(w.get("whois_risk", 0.0)),
                                   float(d.get("dns_risk", 0.0)),
                                   float(s.get("ssl_risk", 0.0)))

    return {
        "whois_json": w,
        "dns_json": d,
        "ssl_json": s,
        "passive_score": passive_score,
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Hunter passive enrichment worker")
    parser.add_argument("--batch", type=int, default=100, help="how many NEW rows to enrich")
    parser.add_argument("--timeout", type=float, default=6.0, help="per-lookup timeout seconds")
    args = parser.parse_args(argv)

    with flask_app.app_context():
        # pick NEW rows without any enrichment yet
        rows = db.session.execute(
            db.select(DiscoveredURL).where(DiscoveredURL.status == URLStatus.NEW).limit(args.batch)
        ).scalars().all()

        inserted, skipped = 0, 0
        for row in rows:
            # skip if already enriched (paranoia)
            exists = db.session.execute(
                db.select(Enrichment.id).where(Enrichment.url_id == row.id)
            ).first()
            if exists:
                skipped += 1
                continue

            payload = enrich_one(row, timeout=args.timeout)
            enr = Enrichment(
                url_id=row.id,
                whois_json=payload["whois_json"],
                dns_json=payload["dns_json"],
                ssl_json=payload["ssl_json"],
                passive_score=payload["passive_score"],
            )
            db.session.add(enr)
            row.status = URLStatus.ENRICHED
            try:
                db.session.commit()
                inserted += 1
            except Exception:
                db.session.rollback()

        print({"inserted": inserted, "skipped": skipped, "batch": len(rows)})
        flask_app.logger.info("ENRICH summary inserted=%s skipped=%s", inserted, skipped)

if __name__ == "__main__":
    sys.exit(main())
