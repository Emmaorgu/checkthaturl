# app/hunter/workers/discover.py
from __future__ import annotations
import argparse, sys, datetime as dt
from typing import Iterable, List

from flask import current_app
from app.app import app as flask_app  # use the already-initialized Flask app
from app.db import db
from app.hunter.models import DiscoveredURL, URLStatus
from app.hunter.sources.base import Candidate, normalize_url
from app.hunter.sources import openphish as op
from app.hunter.sources import urlhaus as uh
from app.hunter.sources import typosquat as ts

def _pull_from_sources(sources: list[str], limit: int, brands: list[str], tlds: list[str]) -> list[Candidate]:
    cands: list[Candidate] = []
    for src in sources:
        if src == "openphish":
            cands += op.pull(limit=limit)
        elif src == "urlhaus":
            cands += uh.pull(limit=limit)
        elif src == "typosquat":
            cands += ts.generate(brands=brands, tlds=tlds, max_per_brand=max(10, limit // max(1, len(brands))))
    return cands

def persist(cands: Iterable[Candidate]) -> dict:
    """
    Normalize, de-dupe by url_hash, and insert new rows.
    Returns a small summary dict for visibility.
    """
    inserted = 0
    skipped_dupe = 0
    errors = 0

    for c in cands:
        try:
            norm, domain, url_hash = normalize_url(c.url)
        except Exception:
            errors += 1
            continue

        # Up-front fast check to avoid unique constraint hits
        exists = db.session.execute(
            db.select(DiscoveredURL.id).where(DiscoveredURL.url_hash == url_hash)
        ).first()
        if exists:
            skipped_dupe += 1
            continue

        row = DiscoveredURL(
            url=c.url,
            domain=domain,
            source=c.source,
            first_seen=c.first_seen,
            url_hash=url_hash,
            normalized=norm,
            status=URLStatus.NEW,
        )
        db.session.add(row)
        try:
            db.session.commit()
            inserted += 1
        except Exception:
            db.session.rollback()
            skipped_dupe += 1  # if race/unique constraint triggers
    return {"inserted": inserted, "dupes": skipped_dupe, "errors": errors}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Hunter discovery worker")
    parser.add_argument("--limit", type=int, default=200, help="per-source limit")
    parser.add_argument("--sources", type=str, default="openphish,urlhaus,typosquat",
                        help="comma list: openphish,urlhaus,typosquat")
    parser.add_argument("--brands", type=str,
                        default="firstbank,zenithbank,gtbank,accessbank,uba,wema,kuda,opay,palmpay,moniepoint",
                        help="comma list for typosquat generator")
    parser.add_argument("--tlds", type=str, default=".ng,.com,.net,.co,.biz",
                        help="comma list of TLDs for typosquat generator")
    args = parser.parse_args(argv)

    srcs = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    brands = [b.strip() for b in args.brands.split(",") if b.strip()]
    tlds = [t.strip() for t in args.tlds.split(",") if t.strip()]

    with flask_app.app_context():
        result = persist(_pull_from_sources(srcs, args.limit, brands, tlds))
        current_app.logger.info("DISCOVER summary inserted=%s dupes=%s errors=%s",
                                result["inserted"], result["dupes"], result["errors"])
        print(result)

if __name__ == "__main__":
    sys.exit(main())
