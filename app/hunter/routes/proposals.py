# app/hunter/routes/proposals.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from flask import Blueprint, jsonify, request, abort
from sqlalchemy import select, desc
from sqlalchemy.orm import aliased

from app.app import db
from app.hunter.models import Proposal, DiscoveredURL, ScanRecord

bp = Blueprint("hunter_proposals", __name__)

def _serialize_row(p: Proposal, d: DiscoveredURL, s: ScanRecord) -> Dict[str, Any]:
    """Compact JSON for lists."""
    return {
        "id": p.id,
        "url": d.normalized or d.url,
        "domain": d.domain,
        "state": p.state,
        "confidence": float(p.confidence or 0.0),
        "created_ts": p.created_ts.isoformat() + "Z" if getattr(p, "created_ts", None) else None,
        "ttl_minutes": p.ttl_minutes,
        "why_top": (p.audit_log_json or {}).get("why_top"),
        "explanations": (s.explanations_json or {}).get("items"),
        "flags": ((s.features_json or {}).get("flags") or {}),
        "artifacts": s.artifacts_json,
    }

def _serialize_detail(p: Proposal, d: DiscoveredURL, s: ScanRecord) -> Dict[str, Any]:
    """Full JSON for a single proposal."""
    return {
        **_serialize_row(p, d, s),
        "suggested_actions": (p.suggested_actions_json or {}).get("actions"),
        "audit_log": p.audit_log_json,
        "approver": p.approver,
        "decision_ts": p.decision_ts.isoformat() + "Z" if p.decision_ts else None,
    }

def _latest_scan_subquery():
    """Scalar subquery: latest ScanRecord.id for a given Proposal.url_id."""
    sr_alias = aliased(ScanRecord)
    return (
        select(sr_alias.id)
        .where(sr_alias.url_id == Proposal.url_id)
        .order_by(desc(sr_alias.ts))
        .limit(1)
        .scalar_subquery()
    )

@bp.get("/proposals")
def list_proposals():
    state = request.args.get("state", "pending").lower()
    limit = min(int(request.args.get("limit", 50)), 200)
    q = request.args.get("q", "").strip().lower()  # optional domain filter

    latest_scan_id = _latest_scan_subquery()
    stmt = (
        select(Proposal, DiscoveredURL, ScanRecord)
        .join(DiscoveredURL, DiscoveredURL.id == Proposal.url_id)
        .join(ScanRecord, ScanRecord.id == latest_scan_id)
        .where(Proposal.state == state)
        .order_by(desc(Proposal.confidence))
        .limit(limit)
    )
    rows = list(db.session.execute(stmt).all())

    if q:
        rows = [r for r in rows if q in (r[1].domain or "").lower()]

    data = [_serialize_row(p, d, s) for (p, d, s) in rows]
    return jsonify(data), 200

@bp.get("/proposals/<int:pid>")
def get_proposal(pid: int):
    latest_scan_id = _latest_scan_subquery()
    stmt = (
        select(Proposal, DiscoveredURL, ScanRecord)
        .join(DiscoveredURL, DiscoveredURL.id == Proposal.url_id)
        .join(ScanRecord, ScanRecord.id == latest_scan_id)
        .where(Proposal.id == pid)
        .limit(1)
    )
    row = db.session.execute(stmt).first()
    if not row:
        abort(404, description="Proposal not found")
    p, d, s = row
    return jsonify(_serialize_detail(p, d, s)), 200

@bp.post("/proposals/<int:pid>/decision")
def decide(pid: int):
    body = request.get_json(silent=True) or {}
    decision = (body.get("decision") or "").strip().lower()
    approver = (body.get("approver") or "").strip()
    notes = (body.get("notes") or "").strip()

    if decision not in ("approve", "deny"):
        abort(400, description="decision must be 'approve' or 'deny'")
    if not approver:
        abort(400, description="approver is required (email or name)")

    p: Proposal | None = db.session.get(Proposal, pid)
    if not p:
        abort(404, description="Proposal not found")
    if p.state not in ("pending",):
        abort(409, description=f"Proposal already {p.state}")

    # transition
    p.state = "approved" if decision == "approve" else "denied"
    p.approver = approver
    p.decision_ts = datetime.utcnow()
    audit = dict(p.audit_log_json or {})
    audit.setdefault("decisions", []).append(
        {"ts": p.decision_ts.isoformat() + "Z", "by": approver, "decision": p.state, "notes": notes}
    )
    p.audit_log_json = audit

    db.session.add(p)
    db.session.commit()

    return jsonify({"id": p.id, "status": p.state}), 200

@bp.get("/proposals/<int:pid>/approve")
def approve_via_get(pid: int):
    approver = (request.args.get("by") or "slack").strip()
    notes = (request.args.get("notes") or "slack button").strip()
    # Reuse POST logic by building a fake request body
    request.get_json = lambda *a, **k: {"decision": "approve", "approver": approver, "notes": notes}
    return decide(pid)

@bp.get("/proposals/<int:pid>/deny")
def deny_via_get(pid: int):
    approver = (request.args.get("by") or "slack").strip()
    notes = (request.args.get("notes") or "slack button").strip()
    request.get_json = lambda *a, **k: {"decision": "deny", "approver": approver, "notes": notes}
    return decide(pid)
