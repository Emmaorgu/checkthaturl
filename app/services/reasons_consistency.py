# app/services/reasons_consistency.py
from __future__ import annotations
import re
from typing import Dict, List
from .behavior_detectors import detect_behavior_reasons

_WEAK_PHRASE = re.compile(
    r"(further\s+checks\s+recommended|seek\s+further\s+verification|manual\s+review\s+recommended)",
    re.I,
)

_BUCKETS = ("domain_risks", "content_risks", "link_risks", "behavior_risks")


def _clean_list(values) -> List[str]:
    out: List[str] = []
    for v in values or []:
        s = str(v or "").strip()
        if not s:
            continue
        if _WEAK_PHRASE.search(s):
            continue
        if s not in out:
            out.append(s)
    return out


def build_reasons(scan: Dict) -> Dict[str, List[str]]:
    """
    Returns canonical reason buckets with concrete abnormalities.
    - Keeps backend verdict AS-IS.
    - For Phishing/Suspicious, guarantees concrete behavior reasons derived from telemetry.
    - Never emits 'No notable issues' strings; UI handles that for Legitimate only.
    """
    verdict = (scan or {}).get("verdict", "Legitimate")
    out = {
        "domain_risks": _clean_list((scan or {}).get("domain_risks")),
        "content_risks": _clean_list((scan or {}).get("content_risks")),
        "link_risks": _clean_list((scan or {}).get("link_risks")),
        "behavior_risks": _clean_list((scan or {}).get("behavior_risks")),
    }

    # Derive concrete behavior abnormalities when verdict is non-legit
    if verdict in ("Phishing", "Suspicious"):
        if not out["behavior_risks"]:
            out["behavior_risks"] = detect_behavior_reasons(scan)

    # Hard guarantee: for non-legit, at least one concrete reason across buckets
    if verdict in ("Phishing", "Suspicious"):
        total = sum(len(out[k]) for k in _BUCKETS)
        if total == 0:
            # LAST resort: surface a plain telemetry anomaly; do NOT change verdict.
            out["behavior_risks"] = ["Telemetry anomaly during scan (redirects/events captured)."]

    # Defensive: cap list sizes for UX
    for k in _BUCKETS:
        if len(out[k]) > 12:
            out[k] = out[k][:12]

    return out
