# app/hunter/client/ctu.py
from __future__ import annotations
import os
import requests
from typing import Any, Dict

SCAN_URL = os.getenv("CTU_INTERNAL_SCAN_URL", "http://127.0.0.1:5000/check")

def scan_url(url: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Call existing CTU /check API and normalize a few fields for storage.
    Returns a dict with: verdict, score, explanations, artifacts, features, raw
    """
    try:
        r = requests.post(SCAN_URL, json={"url": url}, timeout=timeout)
        r.raise_for_status()
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    except Exception as e:
        # Normalize an error payload so worker can still store something
        return {
            "ok": False,
            "verdict": "Suspicious",
            "score": 0.0,
            "explanations": {"error": f"{type(e).__name__}: {e}"},
            "artifacts": {},
            "features": {},
            "raw": {},
        }

    # Map CTU fields → our storage shape
    verdict = (data.get("verdict") or "Suspicious")
    score = float(data.get("risk", 0.0))  # /check returns 0..1 in "risk"

    explanations = {
        "explanation": data.get("explanation"),
        "domain_risks": data.get("domain_risks"),
        "content_risks": data.get("content_risks"),
        "link_risks": data.get("link_risks"),
        "behavior_risks": data.get("behavior_risks"),
        "status": data.get("status"),
    }
    artifacts = {
        "final_url": data.get("url"),
        "elapsed_ms": data.get("elapsed_ms"),
        # (screenshot path would live here later if you wire Playwright capture)
    }
    features = {
        "category_scores": data.get("category_scores"),
        "behavior": data.get("behavior"),
        "structure": data.get("structure"),
        "visual": data.get("visual"),
        "policy": data.get("policy"),
    }

    return {
        "ok": True,
        "verdict": verdict,
        "score": score,
        "explanations": explanations,
        "artifacts": artifacts,
        "features": features,
        "raw": data,  # keep the raw response for traceability
    }
