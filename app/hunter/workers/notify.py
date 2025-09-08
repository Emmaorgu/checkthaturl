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

# Dedupe + retry + run logging utilities (unchanged)
from app.hunter.slack_sender import (
    should_skip_id,
    mark_sent_id,
    log_run,
)

# Signed links for Approve/Deny
from app.hunter.security.signer import sign


# ────────────────────────────────────────────────────────────────────────────────
# Env + constants
# ────────────────────────────────────────────────────────────────────────────────
PUBLIC_BASE_URL   = (os.getenv("PUBLIC_BASE_URL") or "").rstrip("/")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK") or ""
HUNTER_SIGNING_SECRET = os.getenv("HUNTER_SIGNING_SECRET") or ""  # sign() uses this under the hood

# If any of the above are missing we’ll auto-fall back to dry-run (exactly like your
# previous worker’s behavior). No surprises.


# ────────────────────────────────────────────────────────────────────────────────
# URL / domain helpers
# ────────────────────────────────────────────────────────────────────────────────
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
    """Search common URL-ish keys inside a (possibly nested) dict."""
    if not isinstance(m, dict):
        return None
    keys = (
        "final_url", "resolved_url", "canonical_url", "target_url",
        "submitted_url", "original_url", "url", "href", "link"
    )
    for k in keys:
        v = m.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            sub = _map_get_url_like(v)
            if sub:
                return sub
    return None

def _enhanced_url_and_domain(p: Proposal, d: DiscoveredURL, s: ScanRecord) -> Tuple[str, str]:
    """
    Keep the working source of truth (DiscoveredURL), but fill gaps from ScanRecord/Proposal.
    """
    # 1) canonical path (what made your old worker reliable)
    url = _first_str(getattr(d, "normalized", None), getattr(d, "url", None)) or ""

    # 2) look inside latest ScanRecord JSON blobs when empty
    if not url:
        url = _map_get_url_like(s.artifacts_json or {}) or url
    if not url:
        url = _map_get_url_like(s.features_json or {}) or url

    # 3) as a last resort, try a few Proposal fields
    if not url:
        url = _first_str(
            getattr(p, "url", None),
            getattr(p, "target_url", None),
            getattr(p, "original_url", None),
            getattr(p, "submitted_url", None),
        ) or ""

    domain = _first_str(getattr(d, "domain", None)) or _host_from_url(url)
    return url, (domain or "")


# ────────────────────────────────────────────────────────────────────────────────
# “Top signals” extraction (keeps your previous semantics)
# ────────────────────────────────────────────────────────────────────────────────
def _top_reasons(p: Proposal, s: ScanRecord) -> List[str]:
    # prefer explanations list from ScanRecord
    items = (s.explanations_json or {}).get("items")
    if isinstance(items, list) and items:
        return [str(x) for x in items][:3]

    # fall back to why_top from Proposal audit log
    why = (p.audit_log_json or {}).get("why_top")
    if isinstance(why, list) and why:
        return [str(x) for x in why][:3]
    if isinstance(why, str) and why.strip():
        return [why.strip()]

    # derive short sentences from flags if present
    flags = ((s.features_json or {}).get("flags")) or {}
    outs: List[str] = []
    if isinstance(flags, dict):
        if flags.get("credential_form_detected"):
            outs.append("🔒 Credential form detected.")
        if flags.get("brand_impersonation"):
            outs.append("🛑 Possible brand impersonation.")
        if flags.get("has_js_timer"):
            outs.append("⏳ Countdown/timer script present.")
    return outs[:3] if outs else []


# ────────────────────────────────────────────────────────────────────────────────
# Slack Blocks payload
# ────────────────────────────────────────────────────────────────────────────────
def _signed_action_urls(pid: int) -> Tuple[str, str]:
    if not PUBLIC_BASE_URL:
        raise RuntimeError("PUBLIC_BASE_URL is not set")
    if not HUNTER_SIGNING_SECRET:
        raise RuntimeError("HUNTER_SIGNING_SECRET is not set")

    t_a, s_a = sign({"pid": pid, "act": "approve"})
    t_d, s_d = sign({"pid": pid, "act": "deny"})
    approve_url = f"{PUBLIC_BASE_URL}/hunter/review?act=approve&t={t_a}&s={s_a}"
    deny_url    = f"{PUBLIC_BASE_URL}/hunter/review?act=deny&t={t_d}&s={s_d}"
    return approve_url, deny_url

def _build_blocks(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Render the card like your preferred layout, with an extra
    'Open in scanner' button when a URL exists.
    """
    pid     = payload["id"]
    url     = (payload.get("url") or "").strip()
    domain  = (payload.get("domain") or _host_from_url(url) or "(unknown)").strip()
    state   = str(payload.get("state") or "pending").lower()

    # confidence: accept 0..1 or 0..100
    conf_raw = float(payload.get("confidence") or 0.0)
    conf_pct = conf_raw * 100.0 if conf_raw <= 1.0 else conf_raw

    # top reasons (prefer explanations, then why_top)
    reasons = payload.get("explanations") or payload.get("why_top") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    reasons = [str(r).strip() for r in reasons if str(r).strip()]
    reasons_md = "\n".join(f"• {r}" for r in reasons[:3]) if reasons else "• (no single dominant factor)"

    status_dot = {
        "pending":  ":large_orange_circle:",
        "approved": ":white_check_mark:",
        "denied":   ":x:",
    }.get(state, ":large_orange_circle:")
    title = f"*URL Review* • {status_dot} *{state.capitalize()}*"

    # Signed action links
    approve_url, deny_url = _signed_action_urls(int(pid))

    # Optional: deep link to your scanner UI (?u=<url>)
    open_scanner = None
    if url and PUBLIC_BASE_URL:
        open_scanner = f"{PUBLIC_BASE_URL}/?u={quote_plus(url)}"

    # URL field (Slack will auto-truncate the link)
    url_field = f"*URL:*\n<{url}|{url}>" if url else "*URL:*\n(n/a)"
    domain_field = f"*Domain:*\n{domain}"

    # Build blocks
    blocks: List[Dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": url_field},
            {"type": "mrkdwn", "text": domain_field},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Confidence:*\n{conf_pct:.1f}%"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why this surfaced:*\n{reasons_md}"}},
    ]

    action_elems: List[Dict[str, Any]] = []
    if open_scanner:
        action_elems.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Open in scanner"},
            "url": open_scanner
        })
    action_elems.append({
        "type": "button",
        "style": "primary",
        "text": {"type": "plain_text", "text": "Approve ✅"},
        "url": approve_url
    })
    action_elems.append({
        "type": "button",
        "style": "danger",
        "text": {"type": "plain_text", "text": "Deny ❌"},
        "url": deny_url
    })
    blocks.append({"type": "actions", "elements": action_elems})

    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": f"Proposal #{pid} • Signed links expire in 48h."}
    ]})

    return {
        "text": f"[{domain}] {conf_pct:.1f}% confidence",
        "blocks": blocks,
    }


def _post_to_slack(blocks_payload: Dict[str, Any]) -> bool:
    if not SLACK_WEBHOOK_URL:
        raise RuntimeError("SLACK_WEBHOOK_URL is not set")
    r = requests.post(SLACK_WEBHOOK_URL, json=blocks_payload, timeout=12)
    return (r.status_code == 200) and (r.text.strip().lower() == "ok")


# ────────────────────────────────────────────────────────────────────────────────
# Serializer (preserves your working shape; URL/domain enhanced)
# ────────────────────────────────────────────────────────────────────────────────
def _serialize_row(p: Proposal, d: DiscoveredURL, s: ScanRecord) -> Dict[str, Any]:
    url, domain = _enhanced_url_and_domain(p, d, s)
    return {
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


# ────────────────────────────────────────────────────────────────────────────────
# Worker core (dedupe + retry + run logging preserved)
# ────────────────────────────────────────────────────────────────────────────────
def run(state: str, limit: int, dry_run: bool = False, max_retries: int = 3, base_delay: float = 0.8) -> dict:
    sent = 0
    failed = 0

    # Auto dry-run if critical envs missing (same behavior as before)
    slack_env_present  = bool(SLACK_WEBHOOK_URL)
    public_url_present = bool(PUBLIC_BASE_URL)
    secret_present     = bool(HUNTER_SIGNING_SECRET)
    effective_dry_run = dry_run or (not slack_env_present) or (not public_url_present) or (not secret_present)

    if effective_dry_run and not dry_run:
        print(
            "[WARN] Missing one of SLACK_WEBHOOK_URL / PUBLIC_BASE_URL / HUNTER_SIGNING_SECRET. "
            "Falling back to dry-run printing.",
            file=sys.stderr,
        )

    with flask_app.app_context():
        # latest scan per URL: (url_id, MAX(ts))  ← unchanged
        latest_scans = (
            select(ScanRecord.url_id, func.max(ScanRecord.ts).label("max_ts"))
            .group_by(ScanRecord.url_id)
            .subquery("latest_scans")
        )

        stmt = (
            select(Proposal, DiscoveredURL, ScanRecord)
            .join(DiscoveredURL, DiscoveredURL.id == Proposal.url_id)
            .join(latest_scans, latest_scans.c.url_id == Proposal.url_id)
            .join(
                ScanRecord,
                (ScanRecord.url_id == Proposal.url_id) & (ScanRecord.ts == latest_scans.c.max_ts),
            )
            .where(Proposal.state == state)
            .order_by(desc(Proposal.confidence))
            .limit(limit)
        )
        rows = list(db.session.execute(stmt).all())

        for p, d, s in rows:
            payload = _serialize_row(p, d, s)
            pid = str(p.id)

            # Dry-run: print the original JSON your tooling expects (unchanged)
            if effective_dry_run:
                try:
                    print(json.dumps({"dry_run_card": payload}, ensure_ascii=False))
                except Exception:
                    print(f"[DRY-RUN] proposal_id={pid}", file=sys.stderr)
                sent += 1
                continue

            # Dedupe (unchanged)
            if should_skip_id(pid):
                continue

            # Build rich Slack message
            reasons = _top_reasons(p, s)
            if reasons and not payload.get("explanations"):
                payload["explanations"] = reasons  # so dry-run/debug prints match the visible card

            blocks_payload = _build_blocks(payload)

            # Send with exponential backoff (unchanged pattern)
            ok = False
            for attempt in range(1, max_retries + 1):
                try:
                    ok = _post_to_slack(blocks_payload)
                except Exception as e:
                    ok = False
                    print(
                        f"[SLACK EXCEPTION] {type(e).__name__}: {e} "
                        f"(proposal_id={pid}, attempt={attempt}/{max_retries})",
                        file=sys.stderr,
                    )

                if ok:
                    mark_sent_id(pid)
                    sent += 1
                    break

                if attempt < max_retries:
                    delay = base_delay * (2 ** (attempt - 1))
                    print(
                        f"[SLACK RETRY] proposal_id={pid} attempt={attempt}/{max_retries} "
                        f"sleeping={delay:.2f}s",
                        file=sys.stderr,
                    )
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
    ap = argparse.ArgumentParser(description="Send Slack cards for Hunter proposals (dedupe + retry + logging, rich UI)")
    ap.add_argument("--state", default="pending")
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true", help="Print cards instead of posting to Slack")
    ap.add_argument("--retries", type=int, default=3, help="Max retries on Slack errors")
    ap.add_argument("--backoff", type=float, default=0.8, help="Base delay (seconds) for exponential backoff")
    args = ap.parse_args()

    results = run(
        state=args.state,
        limit=args.limit,
        dry_run=args.dry_run,
        max_retries=args.retries,
        base_delay=args.backoff,
    )
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
