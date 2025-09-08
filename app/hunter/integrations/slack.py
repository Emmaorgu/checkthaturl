from __future__ import annotations
import os, time, requests
from typing import Dict, Any, List, Optional
from app.hunter.security.signer import sign

WEBHOOK = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")

def _build_review_links(proposal_id: int, ttl_hours: int = 48) -> Dict[str, str]:
    exp = int(time.time() + ttl_hours * 3600)
    base = f"{PUBLIC_BASE_URL.rstrip('/')}/hunter/review"
    # approve
    t_a, s_a = sign({"pid": proposal_id, "act": "approve", "exp": exp})
    approve = f"{base}?act=approve&t={t_a}&s={s_a}"
    # deny
    t_d, s_d = sign({"pid": proposal_id, "act": "deny", "exp": exp})
    deny = f"{base}?act=deny&t={t_d}&s={s_d}"
    return {"approve": approve, "deny": deny}

def _blocks_from_payload(p: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Expected minimal fields (as produced by notify._serialize_row):
      id, url, domain, confidence, why_top, explanations, flags
    """
    rid = p.get("id")
    links = _build_review_links(int(rid))
    url = p.get("url")
    domain = p.get("domain")
    conf = p.get("confidence", 0.0)
    why_top = p.get("why_top")
    explanations = p.get("explanations") or []
    flags = p.get("flags") or {}

    expl_text = ""
    if why_top and isinstance(why_top, (list, tuple)):
        expl_text = "\n".join(f"• {x}" for x in why_top[:5])
    elif explanations and isinstance(explanations, (list, tuple)):
        expl_text = "\n".join(f"• {x}" for x in explanations[:5])

    badge = "🟠 Pending"
    conf_pct = f"{round(float(conf)*100, 1)}%"

    return [
        {"type": "header", "text": {"type": "plain_text", "text": f"URL Review • {badge}", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*URL:*\n<{url}|{url[:70]}...>" if url else "*URL:*\n(n/a)"},
            {"type": "mrkdwn", "text": f"*Domain:*\n{domain}"},
            {"type": "mrkdwn", "text": f"*Confidence:*\n{conf_pct}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why this surfaced:*\n{expl_text or '—'}"}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "✅ Approve"}, "style": "primary", "url": links["approve"]},
            {"type": "button", "text": {"type": "plain_text", "text": "⛔ Deny"}, "style": "danger", "url": links["deny"]},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Proposal #{rid} • Signed links expire in 48h."}]},
        {"type": "divider"},
    ]

def post_card(p: Dict[str, Any]) -> bool:
    if not (WEBHOOK and PUBLIC_BASE_URL):
        raise RuntimeError("Missing SLACK_WEBHOOK_URL/SLACK_WEBHOOK or PUBLIC_BASE_URL")
    blocks = _blocks_from_payload(p)
    payload = {"text": f"Review URL: {p.get('url')}", "blocks": blocks}
    r = requests.post(WEBHOOK, json=payload, timeout=12)
    return (r.status_code == 200 and r.text.strip() == "ok")
