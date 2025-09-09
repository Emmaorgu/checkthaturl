# app/hunter/workers/notify.py
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, quote_plus

import requests
from sqlalchemy import select, desc, func

from app.app import app as flask_app, db
from app.hunter.models import Proposal, DiscoveredURL, ScanRecord

from app.hunter.slack_sender import should_skip_id, mark_sent_id, log_run
from app.hunter.security.signer import sign

PUBLIC_BASE_URL   = (os.getenv("PUBLIC_BASE_URL") or "").rstrip("/")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK") or ""
HUNTER_SIGNING_SECRET = os.getenv("HUNTER_SIGNING_SECRET") or ""
INCLUDE_LOW = (os.getenv("NOTIFY_INCLUDE_LOW") or "0").strip() in ("1", "true", "yes")

def _first_str(*vals) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _host_from_url(u: str) -> str:
    try:
        return urlparse(u).netloc.split(":")[0]
    except Exception:
        return ""

def _map_get_url_like(m: Any) -> Optional[str]:
    if not isinstance(m, dict):
        return None
    keys = ("final_url","resolved_url","canonical_url","target_url","submitted_url","original_url","url","href","link")
    for k in keys:
        v = m.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            sub = _map_get_url_like(v)
            if sub:
                return sub
    return None

def _enhanced_url_and_domain(d: DiscoveredURL, s: ScanRecord, p: Proposal) -> Tuple[str, str]:
    url = _first_str(getattr(d, "normalized", None), getattr(d, "url", None)) or ""
    if not url:
        url = _map_get_url_like(s.artifacts_json or {}) or url
    if not url:
        url = _map_get_url_like(s.features_json or {}) or url
    if not url:
        url = _first_str(getattr(p, "url", None), getattr(p, "target_url", None), getattr(p, "original_url", None), getattr(p, "submitted_url", None)) or ""
    domain = _first_str(getattr(d, "domain", None)) or _host_from_url(url)
    return url, (domain or "")

def _top_reasons(p: Proposal, s: ScanRecord) -> List[str]:
    items = (s.explanations_json or {}).get("items")
    if isinstance(items, list) and items:
        return [str(x) for x in items][:3]
    why = (p.audit_log_json or {}).get("why_top")
    if isinstance(why, list) and why:
        return [str(x) for x in why][:3]
    if isinstance(why, str) and why.strip():
        return [why.strip()]
    flags = ((s.features_json or {}).get("flags") or {})
    outs: List[str] = []
    if isinstance(flags, dict):
        if flags.get("credential_form_detected"): outs.append("🔒 Credential form detected.")
        if flags.get("brand_impersonation"):      outs.append("🛑 Possible brand impersonation.")
        if flags.get("has_js_timer"):             outs.append("⏳ Countdown/timer script present.")
    return outs[:3] if outs else []

def _signed_action_urls(pid: int) -> Tuple[str, str]:
    if not PUBLIC_BASE_URL:       raise RuntimeError("PUBLIC_BASE_URL is not set")
    if not HUNTER_SIGNING_SECRET: raise RuntimeError("HUNTER_SIGNING_SECRET is not set")
    t_a, s_a = sign({"pid": pid, "act": "approve"})
    t_d, s_d = sign({"pid": pid, "act": "deny"})
    return (
        f"{PUBLIC_BASE_URL}/hunter/review?act=approve&t={t_a}&s={s_a}",
        f"{PUBLIC_BASE_URL}/hunter/review?act=deny&t={t_d}&s={s_d}",
    )

def _build_blocks(payload: Dict[str, Any]) -> Dict[str, Any]:
    pid     = payload["id"]
    url     = (payload.get("url") or "").strip()
    domain  = (payload.get("domain") or _host_from_url(url) or "(unknown)").strip()
    state   = str(payload.get("state") or "pending").lower()

    conf_raw = float(payload.get("confidence") or 0.0)
    conf_pct = conf_raw * 100.0 if conf_raw <= 1.0 else conf_raw

    reasons = payload.get("explanations") or payload.get("why_top") or []
    if isinstance(reasons, str): reasons = [reasons]
    reasons = [str(r).strip() for r in reasons if str(r).strip()]
    reasons_md = "\n".join(f"• {r}" for r in reasons[:3]) if reasons else "• (no single dominant factor)"

    status_dot = {"pending": ":large_orange_circle:", "approved": ":white_check_mark:", "denied": ":x:"}.get(state, ":large_orange_circle:")
    title = f"*URL Review* • {status_dot} *{state.capitalize()}*"

    approve_url, deny_url = _signed_action_urls(int(pid))
    open_scanner = f"{PUBLIC_BASE_URL}/?u={quote_plus(url)}" if url and PUBLIC_BASE_URL else None

    url_field    = f"*URL:*\n<{url}|{url}>" if url else "*URL:*\n(n/a)"
    domain_field = f"*Domain:*\n{domain}"

    blocks: List[Dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {"type": "section", "fields": [{"type": "mrkdwn", "text": url_field}, {"type": "mrkdwn", "text": domain_field}]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Confidence:*\n{conf_pct:.1f}%"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why this surfaced:*\n{reasons_md}"}},
    ]
    action_elems: List[Dict[str, Any]] = []
    if open_scanner:
        action_elems.append({"type": "button", "text": {"type": "plain_text", "text": "Open in scanner"}, "url": open_scanner})
    action_elems.append({"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve ✅"}, "url": approve_url})
    action_elems.append({"type": "button", "style": "danger",  "text": {"type": "plain_text", "text": "Deny ❌"},    "url": deny_url})
    blocks.append({"type": "actions", "elements": action_elems})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Proposal #{pid} • Signed links expire in 48h."}]})

    return {"text": f"[{domain}] {conf_pct:.1f}% confidence", "blocks": blocks}

def _post_to_slack(blocks_payload: Dict[str, Any]) -> bool:
    if not SLACK_WEBHOOK_URL: raise RuntimeError("SLACK_WEBHOOK_URL is not set")
    r = requests.post(SLACK_WEBHOOK_URL, json=blocks_payload, timeout=12)
    return (r.status_code == 200) and (r.text.strip().lower() == "ok")

def _get_bucket_from(p: Proposal) -> Optional[str]:
    # Prefer real column if present
    b = getattr(p, "bucket", None)
    if isinstance(b, str) and b: return b
    # Fallback to audit_log_json["triage"]["bucket"]
    tri = ((p.audit_log_json or {}).get("triage") or {})
    b = tri.get("bucket")
    return b if isinstance(b, str) and b else None

def run(state: str, limit: int, dry_run: bool = False, max_retries: int = 3, base_delay: float = 0.8) -> dict:
    sent = failed = 0

    slack_env_present  = bool(SLACK_WEBHOOK_URL)
    public_url_present = bool(PUBLIC_BASE_URL)
    secret_present     = bool(HUNTER_SIGNING_SECRET)
    effective_dry_run = dry_run or (not slack_env_present) or (not public_url_present) or (not secret_present)

    if effective_dry_run and not dry_run:
        print("[WARN] Missing one of SLACK_WEBHOOK_URL / PUBLIC_BASE_URL / HUNTER_SIGNING_SECRET. Falling back to dry-run.", file=sys.stderr)

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
            .where(Proposal.state == state)
            .order_by(desc(Proposal.confidence))
            .limit(max(limit * 3, limit))  # overfetch so we can bucket-filter locally
        )
        rows = list(db.session.execute(stmt).all())

        # Allowed buckets
        allowed = {"high", "normal"}
        if INCLUDE_LOW:
            allowed.add("low")

        # Filter by bucket locally (works even without a DB column)
        filtered: List[tuple[Proposal, DiscoveredURL, ScanRecord]] = []
        for p, d, s in rows:
            b = _get_bucket_from(p)
            if b is None:
                # not triaged yet => treat as normal to avoid dropping items
                b = "normal"
            if b in allowed:
                filtered.append((p, d, s))
            if len(filtered) >= limit:
                break

        for p, d, s in filtered:
            pid = str(p.id)
            url, domain = _enhanced_url_and_domain(d, s, p)

            payload = {
                "id": p.id,
                "url": url,
                "domain": domain,
                "state": p.state,
                "confidence": float(p.confidence or 0.0),
                "why_top": (p.audit_log_json or {}).get("why_top"),
                "explanations": (s.explanations_json or {}).get("items"),
                "flags": ((s.features_json or {}).get("flags") or {}),
                "artifacts": s.artifacts_json,
            }

            if effective_dry_run:
                print(json.dumps({"dry_run_card": payload}, ensure_ascii=False))
                sent += 1
                continue

            if should_skip_id(pid):
                continue

            blocks_payload = _build_blocks(payload)

            ok = False
            for attempt in range(1, max_retries + 1):
                try:
                    ok = _post_to_slack(blocks_payload)
                except Exception as e:
                    ok = False
                    print(f"[SLACK EXCEPTION] {type(e).__name__}: {e} (proposal_id={pid}, attempt={attempt}/{max_retries})", file=sys.stderr)

                if ok:
                    mark_sent_id(pid)
                    sent += 1
                    break

                if attempt < max_retries:
                    delay = base_delay * (2 ** (attempt - 1))
                    print(f"[SLACK RETRY] proposal_id={pid} attempt={attempt}/{max_retries} sleeping={delay:.2f}s", file=sys.stderr)
                    time.sleep(delay)
                else:
                    failed += 1

    results = {"sent": sent, "failed": failed, "state": state, "limit": limit, "dry_run": effective_dry_run}
    try:
        log_run(state=state, limit=limit, sent=sent, failed=failed)
    except Exception as e:
        print(f"[LOG WARN] Failed to log run: {e}", file=sys.stderr)
    return results


def main():
    ap = argparse.ArgumentParser(description="Send Slack cards for Hunter proposals (dedupe + buckets + rich UI)")
    ap.add_argument("--state", default="pending")
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=0.8)
    args = ap.parse_args()

    res = run(state=args.state, limit=args.limit, dry_run=args.dry_run, max_retries=args.retries, base_delay=args.backoff)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
