# app/hunter/workers/discover.py
from __future__ import annotations

import argparse
import hashlib
from datetime import datetime
from urllib.parse import urlparse

from app.app import app as flask_app, db
from app.hunter.models import DiscoveredURL, URLStatus

BRANDS = [
    "firstbank", "zenith", "gtbank", "access", "uba", "kuda", "opay", "palmpay",
    "moniepoint", "wema", "polaris", "stanbic", "sterling", "fcmb", "fidelity",
    "union", "jaiz", "keystone"
]
TLDS = [".ng", ".com", ".co", ".net"]
SUFFIXES = ["-login", "-verify", "-secure", "-support", "-update", "-card", "-auth"]
PREFIXES = ["my-", "online-", "secure-", "customer-", "ibanking-"]
PATHS = ["", "/login", "/signin", "/update", "/account/verify"]

def _norm_url(url: str) -> str:
    # strip fragments and spaces
    return url.strip().split("#", 1)[0]

def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _build_candidates(limit: int):
    # Generate deterministic-ish typosquats until limit
    out = []
    for b in BRANDS:
        for t in TLDS:
            # three patterns per brand/tld family
            bases = [
                f"{b}{t}",
                f"{b}{t}".replace("bank", "bnk"),
                f"{b.replace('bank','bnk')}{t}",
            ]
            for base in bases:
                # prefix/suffix combos
                for pre in [""] + PREFIXES:
                    for suf in [""] + SUFFIXES:
                        host = f"{pre}{base.replace(t, '')}{suf}{t}"
                        for p in PATHS:
                            url = f"https://{host}{p}"
                            out.append(url)
                            if len(out) >= limit:
                                return out
    return out[:limit]

def run(limit: int):
    inserted = dupes = errors = 0
    now = datetime.utcnow()

    with flask_app.app_context():
        urls = _build_candidates(limit)
        for url in urls:
            try:
                u = _norm_url(url)
                h = _hash(u)
                parsed = urlparse(u)
                domain = parsed.netloc.lower()
                rec = DiscoveredURL(
                    url=u,
                    domain=domain,
                    source="typosquat",
                    first_seen=now,
                    url_hash=h,
                    normalized=u,
                    status=URLStatus.NEW.value,
                )
                db.session.add(rec)
                db.session.commit()
                inserted += 1
            except Exception:
                db.session.rollback()
                # likely duplicate on unique(url_hash)
                dupes += 1
                # continue loop
        return {"inserted": inserted, "dupes": dupes, "errors": errors, "limit": limit}

def main():
    p = argparse.ArgumentParser(description="Generate typosquat candidates for Hunter.")
    p.add_argument("--limit", type=int, default=1000)
    args = p.parse_args()
    stats = run(limit=args.limit)
    print(stats)

if __name__ == "__main__":
    main()
