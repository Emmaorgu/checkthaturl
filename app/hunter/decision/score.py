# app/hunter/decision/score.py
from __future__ import annotations
from typing import Dict, Any, Tuple, Optional, Iterable
import math
import re

# Reuse the same brand list you used for typosquat generation (Nigeria-first)
BRANDS = [
    "firstbank", "zenith", "gtbank", "accessbank", "uba", "wema",
    "kuda", "opay", "palmpay", "moniepoint",
    # common short-forms / variants:
    "first bank", "zenith bank", "gt bank", "access bank"
]

CRED_WORDS = [
    "password", "passcode", "pin", "otp", "token", "cvv", "credit card",
    "debit card", "bvn", "nin", "login", "sign in", "verify account"
]
TIMER_WORDS = [
    "settimeout", "setinterval", "countdown", "timer", "redirect in", "redirecting"
]

def _text_blob(d: Any) -> str:
    """Flatten nested dict/list of strings into a single lowercase blob."""
    out: list[str] = []
    def walk(x: Any):
        if x is None:
            return
        if isinstance(x, (str, bytes)):
            s = x.decode("utf-8", "ignore") if isinstance(x, bytes) else x
            out.append(s)
        elif isinstance(x, dict):
            for v in x.values(): walk(v)
        elif isinstance(x, (list, tuple, set)):
            for v in x: walk(v)
        # other types ignored
    walk(d)
    return " ".join(out).lower()

def _contains_any(blob: str, words: Iterable[str]) -> bool:
    for w in words:
        if w in blob:
            return True
    return False

def derive_signals(
    domain: str,
    explanations_json: Optional[Dict[str, Any]],
    features_json: Optional[Dict[str, Any]],
) -> Dict[str, bool]:
    """
    Heuristically detect key phishing behaviors:
    - credential_form_detected: hints of login/credential capture
    - has_js_timer: countdown/forced-redirect behavior
    - brand_impersonation: bank brand tokens in domain/explanations
    """
    blob_e = _text_blob(explanations_json)
    blob_f = _text_blob(features_json)
    blob = " ".join([domain.lower(), blob_e, blob_f])

    cred = _contains_any(blob, CRED_WORDS)
    timer = _contains_any(blob, TIMER_WORDS)
    brand = any(b in blob for b in BRANDS)

    return {
        "credential_form_detected": cred,
        "has_js_timer": timer,
        "brand_impersonation": brand,
    }

def explanations_count(explanations_json: Optional[Dict[str, Any]]) -> int:
    """
    Count how many non-empty evidence buckets we have among:
    explanation, domain_risks, content_risks, link_risks, behavior_risks, status
    """
    if not isinstance(explanations_json, dict):
        return 0
    keys = ["explanation", "domain_risks", "content_risks", "link_risks", "behavior_risks", "status"]
    c = 0
    for k in keys:
        v = explanations_json.get(k)
        if isinstance(v, (list, tuple, set)) and len(v) > 0:
            c += 1
        elif isinstance(v, dict) and len(v) > 0:
            c += 1
        elif isinstance(v, str) and v.strip():
            c += 1
    return c

def compute_confidence(
    active_score: float,             # CTU "risk" 0..1
    passive_score: float,            # our enrichment 0..1
    signals: Dict[str, bool],
) -> float:
    """
    Blend passive + active + signals into one confidence ∈ [0,1].
    We bias slightly toward ACTIVE risk from CTU (0.55) then PASSIVE (0.35),
    and add up to +0.10 from strong signals.
    """
    active_w = 0.55
    passive_w = 0.35
    bonus = 0.0
    if signals.get("credential_form_detected"): bonus += 0.06
    if signals.get("has_js_timer"):             bonus += 0.02
    if signals.get("brand_impersonation"):      bonus += 0.02
    base = active_w * float(active_score or 0.0) + passive_w * float(passive_score or 0.0)
    return max(0.0, min(1.0, base + min(0.10, bonus)))
