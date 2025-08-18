# app/policy_utils.py
from __future__ import annotations
import os, re

# -------- Tunables mirrored from app.py (kept here to avoid circular imports) --------
PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", "0.70"))
LEGIT_THRESHOLD    = float(os.getenv("LEGIT_THRESHOLD", "0.30"))

STRICT_SURFACE_GUARD    = os.getenv("STRICT_SURFACE_GUARD", "1") not in {"0","false","no"}
STARTUP_EXCEPTION_GUARD = os.getenv("STARTUP_EXCEPTION_GUARD", "1") not in {"0","false","no"}
DOMAIN_ONLY_CAN_PHISH   = os.getenv("DOMAIN_ONLY_CAN_PHISH", "0") in {"1","true","yes"}

def clip01(x) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except Exception:
        return 0.0

def _choose_verdict(p_phish: float) -> str:
    if p_phish >= PHISHING_THRESHOLD: return "Phishing"
    if p_phish <= LEGIT_THRESHOLD:    return "Legitimate"
    return "Suspicious"

def compute_category_scores(feats: dict, behavior_score: float) -> dict:
    """
    Same weighting used in your app.py, extracted to a shared utility.
    - Domain: suspicious TLD, young domain, high entropy
    - Link: external-link ratio, mismatched anchors, link red flags
    - Content: NLP + red flag count
    - Behavior: behavior_score passed through
    """
    domain = 0.0
    domain += 0.35 * int(feats.get("suspicious_tld", 0) == 1)
    domain += 0.35 * int(feats.get("is_new_domain", 0) == 1)
    domain += 0.30 * min(1.0, float(feats.get("domain_entropy", 0)) / 4.5)

    # Do not penalize many *internal* links; only when clearly external/mismatched.
    link = 0.0
    if float(feats.get("external_link_ratio", 0)) > 0.65:
        link = 0.66
    if float(feats.get("mismatched_anchor_ratio", 0)) > 0.30:
        link = max(link, 0.66)
    if int(feats.get("link_red_flags", 0)):
        link = max(link, 0.5)

    nlp = float(feats.get("phish_context_score", 0.0))
    content_flags = int(feats.get("content_red_flags", 0))
    content = clip01(0.6 * nlp + 0.4 * (content_flags / 7.0))

    behavior = clip01(behavior_score)
    return {
        "domain": round(domain, 3),
        "link": round(link, 3),
        "content": round(content, 3),
        "behavior": round(behavior, 3),
    }

def guarded_verdict(p_like: float, feats: dict, behavior_score: float = 0.0) -> str:
    """
    Apply guardrails so we don't label 'Phishing' on domain-only signals.
    Mirrors the logic you’re using in app.py.
    """
    base = _choose_verdict(p_like)
    surface = (
        int(feats.get("is_new_domain", 0) == 1) +
        int(feats.get("has_https", 1) == 0) +
        int(feats.get("suspicious_tld", 0) == 1)
    )
    non_surface = int(feats.get("non_surface_red_flags", 0))
    link_sig = (
        int(feats.get("link_red_flags", 0)) or
        float(feats.get("mismatched_anchor_ratio", 0)) > 0.30 or
        float(feats.get("external_link_ratio", 0)) > 0.65
    )
    content_sig  = int(feats.get("content_red_flags", 0)) or float(feats.get("phish_context_score", 0)) >= 0.35
    behavior_sig = float(behavior_score) >= 0.25

    # Domain-only can’t be "Phishing" unless explicitly enabled
    if not DOMAIN_ONLY_CAN_PHISH and base == "Phishing" and not (content_sig or link_sig or behavior_sig or non_surface):
        return "Suspicious"

    # If *only* surface flags, soften
    if STRICT_SURFACE_GUARD and base == "Phishing" and non_surface == 0 and surface > 0:
        return "Suspicious" if p_like >= 0.45 else "Legitimate"

    # Early-stage/startup leniency
    if STARTUP_EXCEPTION_GUARD and base == "Phishing" \
       and feats.get("startup_like", 0) == 1 and feats.get("is_new_domain", 0) == 1 \
       and non_surface <= 1 and p_like < 0.85:
        return "Suspicious"

    return base

# --- Timer fallback (regex/keyword) when behavior engine misses it ---
_TIMER_TIME_RE = re.compile(r"\b(?:[0-5]?\d:[0-5]\d)(?:\s*(?:mins?|min|seconds?|secs?))?\b", re.I)
_TIMER_WORDS   = ("countdown","time left","expires in","grant expires","hurry","remaining","left","seconds","minutes")

def detect_urgency_timer(html: str) -> dict:
    if not html:
        return {"has_js_timer": 0, "has_html_timer": 0, "timer_urgency_score": 0.0}
    low = html.lower()
    js_hits = ("setinterval(" in low) or ("settimeout(" in low) or ("new date(" in low and "gettime()" in low) \
              or ("countdown" in low and "function" in low) or ("data-countdown" in low)
    has_time_like = bool(_TIMER_TIME_RE.search(low))
    keyword_hits = sum(1 for w in _TIMER_WORDS if w in low)
    html_flag = 1 if (has_time_like or keyword_hits >= 2) else 0
    js_flag   = 1 if js_hits else 0
    score = clip01(0.25 * js_flag + 0.25 * int(has_time_like) + 0.1 * keyword_hits)
    return {"has_js_timer": js_flag, "has_html_timer": html_flag, "timer_urgency_score": score}
