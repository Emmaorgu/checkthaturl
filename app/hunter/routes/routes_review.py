from __future__ import annotations

from datetime import datetime
from flask import Blueprint, request, make_response, current_app
from app.app import db  # safe to import; avoids circular app instance import
from app.hunter.models import Proposal
from app.hunter.security.signer import verify

review_bp = Blueprint("review", __name__)

_HTML_BASE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1220; color:#e6edf3; padding:2rem; }}
.card {{ max-width:720px; margin:auto; background:#121b2e; border:1px solid #233150; border-radius:16px; padding:24px; }}
h1 {{ margin:0 0 12px 0; font-size:1.4rem; }}
p  {{ line-height:1.5; opacity:0.95; }}
a.btn {{ display:inline-block; padding:10px 14px; border-radius:10px; background:#1f6feb; color:white; text-decoration:none; margin-top:12px; }}
.code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#0b1220; padding:4px 6px; border-radius:6px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{body}</p>
    {extra}
  </div>
</body>
</html>
"""

def _html(title: str, body: str, extra: str = ""):
    return make_response(_HTML_BASE.format(title=title, body=body, extra=extra))

@review_bp.get("/hunter/review")
def review():
    """
    Secure Approve/Deny handler.

    Query params:
      act = approve | deny
      t   = base64url payload (signed)
      s   = hex signature

    Signed payload JSON:
      {"pid": <int>, "act": "approve|deny", "exp": <unix ts>}
    """
    act = (request.args.get("act") or "").strip().lower()
    t   = (request.args.get("t")   or "").strip()
    s   = (request.args.get("s")   or "").strip()

    obj = verify(t, s)
    if not obj:
        return _html(
            "Link invalid or expired",
            "This review link is invalid, expired, or has been tampered with. "
            "Ask the system to resend a fresh card."
        ), 403

    pid = obj.get("pid")
    claimed_act = (obj.get("act") or "").lower()

    if act not in ("approve", "deny") or act != claimed_act:
        return _html("Action mismatch", "The requested action does not match the signed token."), 400

    # Map action -> final state used by your API (/api/proposals?state=approved|denied)
    new_state = "approved" if act == "approve" else "denied"

    # We are inside a request, so an application context is already active.
    # No need to push app_context(); avoiding circular import bugs.
    p: Proposal | None = db.session.get(Proposal, pid)
    if not p:
        return _html("Not found", f"No proposal with id <span class='code'>{pid}</span> exists."), 404

    # Idempotent: already in that state
    if (p.state or "").lower() == new_state:
        return _html(
            "Already processed",
            f"Proposal <span class='code'>#{pid}</span> was already <span class='code'>{new_state}</span>. Nothing to do."
        )

    prev = p.state
    p.state = new_state

    # Minimal audit trail (if your model has audit_log_json)
    alog = (p.audit_log_json or {})
    events = list(alog.get("review_events") or [])
    events.append({
        "at": datetime.utcnow().isoformat() + "Z",
        "from": prev,
        "to": new_state,
        "via": "slack_link",
        "ip": request.headers.get("X-Forwarded-For") or request.remote_addr,
        "ua": request.user_agent.string,
    })
    alog["review_events"] = events
    p.audit_log_json = alog

    db.session.commit()

    try:
        current_app.logger.info("review_state_change pid=%s from=%s to=%s", pid, prev, new_state)
    except Exception:
        pass

    extra = "<a class='btn' href='/'>Back to CheckThatURL</a>"
    return _html("Success", f"Proposal <span class='code'>#{pid}</span> marked as <span class='code'>{new_state}</span>.", extra)
