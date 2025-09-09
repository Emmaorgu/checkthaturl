# app/hunter/workers/triage.py
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy import select, desc, func

from app.app import app as flask_app, db
from app.hunter.models import Proposal, DiscoveredURL, ScanRecord
from app.hunter.workers.triage_rules import classify

def _now_iso(): return datetime.now(timezone.utc).isoformat()

def _safe_set_triage_fields(p: Proposal, bucket: str, reasons: list[str]) -> None:
    # write to columns if present…
    if hasattr(p, "bucket"): p.bucket = bucket
    if hasattr(p, "triage_reason_json"): p.triage_reason_json = {"reasons": reasons}
    if hasattr(p, "triaged_at"): p.triaged_at = datetime.now(timezone.utc)
    # …and always into audit_log_json
    alog: Dict[str, Any] = (p.audit_log_json or {})
    tri = (alog.get("triage") or {})
    tri.update({"bucket": bucket, "reasons": reasons, "at": _now_iso()})
    alog["triage"] = tri
    p.audit_log_json = alog

def _append_audit(p: Proposal, event: Dict[str, Any]) -> None:
    alog: Dict[str, Any] = (p.audit_log_json or {})
    events = list(alog.get("events") or [])
    events.append(event)
    alog["events"] = events
    p.audit_log_json = alog

def run(limit: int = 200, allow_auto_deny: bool = True) -> dict:
    triaged = auto_denied = 0
    c_high = c_norm = c_low = 0

    with flask_app.app_context():
        latest_scans = (
            select(ScanRecord.url_id, func.max(ScanRecord.ts).label("max_ts"))
            .group_by(ScanRecord.url_id)
            .subquery("latest_scans")
        )
        stmt = (
            select(Proposal, DiscoveredURL, ScanRecord)
            .join(DiscoveredURL, DiscoveredURL.id == Proposal.url_id)
            .join(latest_scans, latest_scans.c.url_id == Proposal.url_id)
            .join(ScanRecord, (ScanRecord.url_id == Proposal.url_id) & (ScanRecord.ts == latest_scans.c.max_ts))
            .where(Proposal.state == "pending")
            .order_by(desc(Proposal.confidence))
            .limit(limit)
        )
        rows = list(db.session.execute(stmt).all())

        for p, d, s in rows:
            url = (d.normalized or d.url or "") if d else ""
            domain = (d.domain or "") if d else ""
            flags = ((s.features_json or {}).get("flags") or {}) if s else {}
            artifacts = s.artifacts_json or {} if s else {}
            explanations = (s.explanations_json or {}).get("items") or []

            bucket, reasons, deny = classify(url, domain, p.confidence, flags, artifacts, explanations)
            _safe_set_triage_fields(p, bucket, reasons)
            triaged += 1
            if bucket == "high": c_high += 1
            elif bucket == "low": c_low += 1
            elif bucket == "normal": c_norm += 1

            if deny and allow_auto_deny:
                prev = p.state
                p.state = "denied"
                auto_denied += 1
                _append_audit(p, {
                    "at": _now_iso(), "type": "auto_deny",
                    "from": prev, "to": "denied",
                    "reasons": reasons, "via": "triage_rules_v1",
                })

        db.session.commit()

    return {
        "triaged": triaged,
        "auto_denied": auto_denied,
        "buckets": {"high": c_high, "normal": c_norm, "low": c_low},
        "limit": limit,
    }

def main():
    ap = argparse.ArgumentParser(description="Auto-triage pending proposals into buckets (and auto-deny obvious bad).")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--no-autodeny", action="store_true", help="Do not flip state to denied even if rules say so.")
    args = ap.parse_args()
    print(json.dumps(run(limit=args.limit, allow_auto_deny=not args.no_autodeny), ensure_ascii=False))

if __name__ == "__main__":
    main()
