# app/hunter/workers/scan.py
from __future__ import annotations

import argparse
import os
import time
from typing import Dict, Any, List, Optional

import requests
from sqlalchemy import select, exists

from app.app import app as flask_app, db
from app.hunter.models import DiscoveredURL, ScanRecord, URLStatus


def _internal_scan_url() -> str:
    return os.getenv("CTU_INTERNAL_SCAN_URL", "http://127.0.0.1:5000/check").strip()


def _flatten_explanations(resp: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in ("domain_risks", "content_risks", "behavior_risks"):
        vals = resp.get(key) or []
        for v in vals[:3]:
            if isinstance(v, str) and v:
                out.append(v)
    if not out and isinstance(resp.get("explanation"), str):
        out = [resp["explanation"]]
    return out[:12]


def _mk_artifacts(resp: Dict[str, Any]) -> Dict[str, Any]:
    policy = resp.get("policy") or {}
    return {
        "legal_pages": policy.get("legal_probe_pages") or [],
        "structure_template": (resp.get("structure") or {}).get("template"),
        "visual_closest": (resp.get("visual") or {}).get("closest"),
    }


def _derive_flags(resp: Dict[str, Any], domain: str) -> Dict[str, bool]:
    domain_risks = [str(x).lower() for x in (resp.get("domain_risks") or [])]
    content_risks = [str(x).lower() for x in (resp.get("content_risks") or [])]
    behavior_risks = [str(x).lower() for x in (resp.get("behavior_risks") or [])]
    visual = (resp.get("visual") or {})
    structure = (resp.get("structure") or {})

    # Behavior flags
    has_timer = any(("timer" in x) or ("redirect" in x) for x in behavior_risks)
    cred_form = any(("password" in x) or ("credential" in x) or ("login form" in x) for x in content_risks)

    # Brand impersonation heuristic
    brands_env = os.getenv(
        "HUNTER_BRANDS",
        "firstbank,zenith,gtbank,access,uba,kuda,opay,palmpay,moniepoint,wema,polaris,stanbic,sterling,fcmb,fidelity,union,jaiz,keystone"
    )
    brands = [b.strip().lower() for b in brands_env.split(",") if b.strip()]
    text_blobs = domain_risks + content_risks + [
        str(visual.get("closest", "")).lower(),
        str(structure.get("template", "")).lower(),
    ]
    brand_imp = any(any(b in blob for blob in text_blobs) for b in brands)

    # If the real brand is exactly the domain, discount (basic guard)
    for b in brands:
        if b and (b in domain):
            # leave as-is; more advanced guard can be added later
            pass

    return {
        "has_js_timer": bool(has_timer),
        "credential_form_detected": bool(cred_form),
        "brand_impersonation": bool(brand_imp),
    }


def _mk_features(resp: Dict[str, Any], domain: str) -> Dict[str, Any]:
    features = {
        "category_scores": resp.get("category_scores"),
        "behavior": resp.get("behavior"),
        "risk": resp.get("risk"),
        "confidence": resp.get("confidence"),
    }
    features["flags"] = _derive_flags(resp, domain)
    return features


def _post_check(session: requests.Session, scan_ep: str, url: str, timeout: int) -> Optional[Dict[str, Any]]:
    r = session.post(scan_ep, json={"url": url}, timeout=timeout)
    if r.status_code != 200:
        return None
    if not r.headers.get("content-type", "").startswith("application/json"):
        return None
    return r.json()


def run(batch: int, timeout: int, rescan: bool) -> Dict[str, int]:
    inserted = updated = skipped = errors = 0
    scan_ep = _internal_scan_url()

    with flask_app.app_context():
        if rescan:
            stmt = (
                select(DiscoveredURL)
                .order_by(DiscoveredURL.first_seen.asc())
                .limit(batch)
            )
        else:
            subq = select(ScanRecord.id).where(ScanRecord.url_id == DiscoveredURL.id).limit(1)
            stmt = (
                select(DiscoveredURL)
                .where(~exists(subq))
                .order_by(DiscoveredURL.first_seen.asc())
                .limit(batch)
            )

        urls = list(db.session.scalars(stmt).all())
        if not urls:
            return {"inserted": 0, "updated": 0, "skipped": 0, "errors": 0, "batch": batch}

        s = requests.Session()
        s.headers.update({"User-Agent": "HunterScan/1.1 (+internal)"})

        for d in urls:
            try:
                resp = _post_check(s, scan_ep, d.url, timeout)
                if not resp:
                    skipped += 1
                    continue

                verdict = (resp.get("verdict") or "").strip().lower() or "suspicious"
                score = resp.get("risk", 0.0)
                try:
                    score = float(score)
                except Exception:
                    score = {"phishing": 0.9, "suspicious": 0.5, "legitimate": 0.1}.get(verdict, 0.5)
                score = max(0.0, min(1.0, score))

                explanations = _flatten_explanations(resp)
                artifacts = _mk_artifacts(resp)
                features = _mk_features(resp, d.domain)

                # If a record exists and we're in rescan mode, update it.
                existing: Optional[ScanRecord] = None
                if rescan:
                    existing = db.session.scalar(
                        select(ScanRecord).where(ScanRecord.url_id == d.id).order_by(ScanRecord.ts.desc()).limit(1)
                    )

                if existing:
                    existing.verdict = verdict
                    existing.score = score
                    existing.explanations_json = {"items": explanations}
                    existing.artifacts_json = artifacts
                    existing.features_json = features
                    updated += 1
                else:
                    rec = ScanRecord(
                        url_id=d.id,
                        verdict=verdict,
                        score=score,
                        explanations_json={"items": explanations},
                        artifacts_json=artifacts,
                        features_json=features,
                    )
                    db.session.add(rec)
                    inserted += 1

                if d.status != URLStatus.SCANNED.value:
                    d.status = URLStatus.SCANNED.value

            except Exception:
                errors += 1
                db.session.rollback()
            else:
                db.session.commit()

    return {"inserted": inserted, "updated": updated, "skipped": skipped, "errors": errors, "batch": batch}


def main():
    p = argparse.ArgumentParser(description="Hunter active scan worker (calls internal /check).")
    p.add_argument("--batch", type=int, default=50, help="Max URLs to process")
    p.add_argument("--timeout", type=int, default=20, help="HTTP timeout per request (seconds)")
    p.add_argument("--rescan", action="store_true", help="Update existing ScanRecord rows too")
    args = p.parse_args()

    t0 = time.monotonic()
    stats = run(batch=args.batch, timeout=args.timeout, rescan=args.rescan)
    stats["elapsed_s"] = round(time.monotonic() - t0, 2)
    print(stats)


if __name__ == "__main__":
    main()
