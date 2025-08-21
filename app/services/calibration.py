# app/services/calibration.py
from __future__ import annotations
import math
import os
from typing import Dict, Tuple

# --- Config via env (safe defaults) ---
# Logistic calibration on the *blended* risk:
# p_cal = sigmoid(A * logit(p_raw) + B)
CALIB_A = float(os.getenv("CTU_CALIB_A", "1.0"))
CALIB_B = float(os.getenv("CTU_CALIB_B", "0.0"))

# Thresholds after calibration
THRESH_LEGIT_MAX = float(os.getenv("CTU_THRESH_LEGIT_MAX", "0.30"))
THRESH_PHISH_MIN = float(os.getenv("CTU_THRESH_PHISH_MIN", "0.70"))

def _sigmoid(x: float) -> float:
    try:
        if x >= 0:
            z = math.exp(-x)
            return 1.0 / (1.0 + z)
        z = math.exp(x)
        return z / (1.0 + z)
    except OverflowError:
        return 0.0 if x < 0 else 1.0

def _logit(p: float) -> float:
    eps = 1e-6
    p = min(max(p, eps), 1.0 - eps)
    return math.log(p / (1.0 - p))

def clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))

def calibrate_probability(p_raw: float) -> float:
    """Temperature/logistic-style calibration on blended risk."""
    try:
        return clip01(_sigmoid(CALIB_A * _logit(float(p_raw)) + CALIB_B))
    except Exception:
        return clip01(float(p_raw))

def verdict_from_calibrated(p_cal: float) -> str:
    if p_cal >= THRESH_PHISH_MIN:
        return "Phishing"
    if p_cal <= THRESH_LEGIT_MAX:
        return "Legitimate"
    return "Suspicious"

def reliability_info(p_cal: float) -> Dict:
    """Coarse reliability bands for UI/telemetry."""
    p = float(p_cal)
    if p < 0.15:
        band = ("Very Low", 0.05)
    elif p < 0.30:
        band = ("Low", 0.10)
    elif p < 0.55:
        band = ("Medium", 0.18)
    elif p < 0.75:
        band = ("High", 0.25)
    else:
        band = ("Very High", 0.30)
    return {
        "band": band[0],
        "expected_error_rate": band[1],
        "thresholds": {"legit_max": THRESH_LEGIT_MAX, "phish_min": THRESH_PHISH_MIN},
        "calibration_params": {"A": CALIB_A, "B": CALIB_B},
    }

def apply_contradiction_guards(verdict: str, p_cal: float, features: Dict, behavior: Dict, structure: Dict, legal_ok: bool) -> Tuple[str, float]:
    """
    Final sanity pass to avoid contradictions like:
    - Verdict 'Legitimate' but hard phishing signals present.
    - Verdict 'Phishing' with no hard signals AND verified legal pages.
    Keeps p_cal as is; adjusts verdict only when clearly warranted.
    """
    v = verdict

    # Hard content/behavior signals
    hard_content = (
        int(features.get("has_password_field", 0)) == 1 or
        float(features.get("phish_context_score", 0.0)) >= 0.45 or
        float(features.get("timer_urgency_score", 0.0)) >= 0.45 or
        "timer_decreasing_confirmed" in (behavior.get("events") or []) or
        int(behavior.get("post_action_redirects_form", 0)) >= 1
    )

    # Strong structure similarity w/o being a known benign template
    s_score = float(structure.get("score", 0.0) or 0.0)
    tmpl = (structure.get("template") or "").strip()
    benign = (tmpl.startswith(("ctu_","benign_","safe_","homepage_")) or tmpl in {"ctu_home"})
    strong_structure = (s_score >= 0.75 and not benign)

    # 1) If Legitimate but hard signals or strong structure (and no legal pages), bump to Suspicious
    if v == "Legitimate" and (hard_content or (strong_structure and not legal_ok)):
        v = "Suspicious"

    # 2) If Phishing but no hard signals and legal pages verified, soften to Suspicious
    if v == "Phishing" and (not hard_content) and legal_ok:
        v = "Suspicious"

    return v, p_cal
