# app/hunter/workers/propose.py
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

import yaml
from sqlalchemy import select, func, desc

from app.app import app as flask_app, db
from app.hunter.models import (
    DiscoveredURL,
    Enrichment,
    ScanRecord,
    Proposal,
)

# --- Tunables for dev (kept simple/transparent) ---
BRANDS_DEV = [
    "firstbank","zenith","gtbank","access","uba","kuda","opay","palmpay",
    "moniepoint","wema","polaris","stanbic","sterling","fcmb","fidelity",
    "union","jaiz","keystone"
]
PATH_KEYWORDS = ["login", "signin", "verify", "update", "secure", "auth", "ibanking", "customer"]
BAD_TLDS = {
    "xyz","top","tk","gq","ml","cf","quest","info","cam","monster",
    "click","link","buzz","cyou","work","rest","casa","live"
}


def _load_policy(path: str = "policy.yaml") -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    # default dev policy
    return {
        "propose_block": {
            "threshold_score": 0.30,
            "require": {
                "min_explanations": 1,
                "any_of": [],  # dev: no boolean gate
            },
            "ttl_minutes": 60,
            "suggested_actions": ["block_email_gateway","block_web_proxy"],
        }
    }


def _tld(domain: str) -> str:
    parts = (domain or "").lower().split(".")
    return parts[-1] if len(parts) >= 2 else ""


def _bool(val: Any) -> bool:
    return bool(val) is True


def _brand_in_domain(domain: str, brands: List[str]) -> bool:
    d = (domain or "").lower()
    return any(b in d for b in brands)


def _path_hits(url: str, keywords: List[str]) -> bool:
    u = (url or "").lower()
    return any(kw in u for kw in keywords)


def _any_flags(flags: Dict[str, Any]) -> bool:
    return any(_bool(v) for v in (flags or {}).values())


def _satisfies_any_of(require_any: List[str], flags: Dict[str, Any], brand_by_domain: bool) -> bool:
    if not require_any:
        return True
    # map policy names to computed signals
    m = {
        "has_js_timer": bool(flags.get("has_js_timer")),
        "credential_form_detected": bool(flags.get("credential_form_detected")),
        # allow domain brand match to satisfy brand_impersonation even if scan didn't label it
        "brand_impersonation": bool(flags.get("brand_impersonation")) or brand_by_domain,
    }
    return any(m.get(k, False) for k in require_any)


def _final_confidence(
    scan_score: float,
    passive_score: float,
    flags_any: bool,
    brand_by_domain: bool,
    path_hit: bool,
    bad_tld: bool,
) -> float:
    """
    Transparent confidence mixer in [0,1].
    Weighted blend (dev values chosen to be clear + adjustable later):

      0.45 * scan_score
      0.30 * passive_score
      +0.12 if brand_by_domain
      +0.07 if path_hit
      +0.06 if bad_tld
      +0.10 if flags_any   (timer/credential/brand from scan)

    Capped at 1.0
    """
    conf = 0.45 * float(scan_score or 0.0) + 0.30 * float(passive_score or 0.0)
    if brand_by_domain:
        conf += 0.12
    if path_hit:
        conf += 0.07
    if bad_tld:
        conf += 0.06
    if flags_any:
        conf += 0.10
    if conf < 0.0:
        conf = 0.0
    if conf > 1.0:
        conf = 1.0
    return round(conf, 4)


def run(limit: int, min_conf: float) -> Dict[str, Any]:
    policy = _load_policy()
    pol = policy.get("propose_block") or {}
    pol_threshold = float(pol.get("threshold_score", min_conf))
    threshold = max(min_conf, pol_threshold)  # respect the higher of CLI or policy
    require = pol.get("require") or {}
    min_expl = int(require.get("min_explanations", 1))
    require_any = require.get("any_of") or []
    ttl_minutes = int(pol.get("ttl_minutes", 60))
    suggested_actions = pol.get("suggested_actions") or ["block_email_gateway", "block_web_proxy"]

    brands_env = os.getenv("HUNTER_BRANDS")
    brands = [b.strip().lower() for b in (brands_env.split(",") if brands_env else BRANDS_DEV) if b.strip()]

    inserted = skipped = 0
    created_ids: List[int] = []

    with flask_app.app_context():
        # join on the latest scan per URL; simple approach: just join ScanRecord (we assume 1 per URL in Phase-1)
        stmt = (
            select(DiscoveredURL, Enrichment, ScanRecord)
            .join(Enrichment, Enrichment.url_id == DiscoveredURL.id)
            .join(ScanRecord, ScanRecord.url_id == DiscoveredURL.id)
            .order_by(desc(ScanRecord.ts))
            .limit(limit)
        )
        rows = db.session.execute(stmt).all()
        if not rows:
            return {"inserted": 0, "skipped": 0, "threshold": threshold, "limit": limit}

        now = datetime.utcnow()
        expires = now + timedelta(minutes=ttl_minutes)

        for d, e, s in rows:
            # Explanations gate
            expl_items = []
            if isinstance(s.explanations_json, dict):
                items = s.explanations_json.get("items")
                if isinstance(items, list):
                    expl_items = [x for x in items if isinstance(x, str)]
            if len(expl_items) < min_expl:
                skipped += 1
                continue

            # Feature flags from scan
            flags = {}
            if isinstance(s.features_json, dict):
                flags = s.features_json.get("flags", {}) or {}

            # Heuristics
            brand_by_domain = _brand_in_domain(d.domain, brands)
            path_hit = _path_hits(d.normalized or d.url, PATH_KEYWORDS)
            bad_tld = _tld(d.domain) in BAD_TLDS
            flags_any = _any_flags(flags)

            # Policy's any_of
            if not _satisfies_any_of(require_any, flags, brand_by_domain):
                skipped += 1
                continue

            # Confidence
            conf = _final_confidence(
                scan_score=float(s.score or 0.0),
                passive_score=float(e.passive_score or 0.0),
                flags_any=flags_any,
                brand_by_domain=brand_by_domain,
                path_hit=path_hit,
                bad_tld=bad_tld,
            )

            if conf < threshold:
                skipped += 1
                continue

            # Prevent duplicates: same URL_id pending already?
            exists_pending = db.session.scalar(
                select(func.count()).select_from(Proposal)
                .where(Proposal.url_id == d.id, Proposal.state == "pending")
            )
            if exists_pending:
                skipped += 1
                continue

            # Build proposal row
            prop = Proposal(
                url_id=d.id,
                confidence=conf,
                suggested_actions_json={"actions": suggested_actions},
                ttl_minutes=ttl_minutes,
                state="pending",
                approver=None,
                decision_ts=None,
                audit_log_json={
                    "created": now.isoformat() + "Z",
                    "expires": expires.isoformat() + "Z",
                    "why_top": expl_items[:3],
                    "flags": flags,
                    "signals": {
                        "brand_by_domain": brand_by_domain,
                        "path_hit": path_hit,
                        "bad_tld": bad_tld,
                        "scan_score": float(s.score or 0.0),
                        "passive_score": float(e.passive_score or 0.0),
                    },
                },
            )
            db.session.add(prop)
            db.session.commit()
            inserted += 1
            created_ids.append(prop.id)

    return {"inserted": inserted, "skipped": skipped, "threshold": threshold, "limit": limit, "ids": created_ids[:10]}


def main():
    ap = argparse.ArgumentParser(description="Hunter proposals worker")
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--min-confidence", type=float, default=0.30)
    args = ap.parse_args()
    res = run(limit=args.limit, min_conf=args.min-confidence if hasattr(args, "min-confidence") else args.min_confidence)
    # The dash name in argparse becomes 'min_confidence'; be robust:
    if isinstance(res, dict):
        print(json.dumps(res))
    else:
        print(res)

if __name__ == "__main__":
    main()
