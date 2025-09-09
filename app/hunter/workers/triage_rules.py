# app/hunter/workers/triage_rules.py
from __future__ import annotations
import ipaddress
from typing import Any, List, Tuple
from urllib.parse import urlparse

BAD_TLDS = {".top", ".cn", ".ru", ".gq", ".tk", ".ml", ".cf"}
DROPPER_EXTS = {".exe", ".msi", ".bat", ".cmd", ".js", ".ps1", ".sh", ".apk"}
SUSP_PATH_HINTS = {"/i", "/bins", "/payload", "/dl", "/download", "/update", "/pay", "/verify", "/login", "/signin"}

def _norm_conf(conf: Any) -> float:
    try:
        f = float(conf or 0.0)
        return f * 100.0 if f <= 1.0 else f
    except Exception:
        return 0.0

def _host(u: str) -> str:
    try: return urlparse(u).netloc.split(":")[0]
    except Exception: return ""

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host); return True
    except Exception:
        return False

def _tld(host: str) -> str:
    if not host: return ""
    parts = host.lower().split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""

def _path(u: str) -> str:
    try: return urlparse(u).path.lower()
    except Exception: return ""

def _has_urgency(texts: List[str]) -> bool:
    if not texts: return False
    joined = " ".join(x.lower() for x in texts)
    return any(k in joined for k in ["urgent","countdown","expire","verify now","confirm now","limited time"])

def classify(url: str, domain: str, conf: Any, flags: dict, artifacts: dict, explanations: List[str]) -> Tuple[str, List[str], bool]:
    """
    Returns (bucket, reasons, auto_deny)
    bucket ∈ {'high','normal','low','auto_denied'}
    """
    reasons: List[str] = []
    conf_pct = _norm_conf(conf)

    host = domain or _host(url)
    scheme = (urlparse(url).scheme or "").lower() if url else ""
    path = _path(url)

    cred   = bool((flags or {}).get("credential_form_detected"))
    imp    = bool((flags or {}).get("brand_impersonation"))
    timer  = bool((flags or {}).get("has_js_timer"))
    malware= bool((flags or {}).get("malware_download"))

    legal_pages = (artifacts or {}).get("legal_pages") or []

    # Auto-deny
    ext_match = any(path.endswith(ext) for ext in DROPPER_EXTS)
    susp_path = any(seg in path for seg in SUSP_PATH_HINTS)
    host_is_ip= _is_ip(host)
    bad_tld   = _tld(host) in BAD_TLDS

    if (scheme == "http" and ext_match) or (host_is_ip and susp_path) or malware or (bad_tld and conf_pct >= 75):
        if scheme == "http" and ext_match: reasons.append("Direct executable over HTTP.")
        if host_is_ip and susp_path:       reasons.append("IP host with dropper-like path.")
        if malware:                         reasons.append("Malware download flag from scanner.")
        if bad_tld and conf_pct >= 75:     reasons.append("High risk on known-bad TLD.")
        return "auto_denied", (reasons[:3] or ["Unsafe download pattern."]), True

    # High
    if cred:  reasons.append("Credential form detected.")
    if imp:   reasons.append("Brand impersonation signals.")
    if timer and _has_urgency(explanations or []): reasons.append("Timer/urgency present.")
    if conf_pct >= 70: reasons.append(f"Model risk {conf_pct:.0f}%.")

    if reasons: return "high", reasons[:3], False

    # Low
    if legal_pages and conf_pct <= 45:
        return "low", ["Legal/Policy pages present.", f"Low model risk {conf_pct:.0f}%."], False

    struct = (artifacts or {}).get("structure_template")
    if struct in {"JobConf","template_portal"} and not (cred or imp):
        return "low", [f"Template structure: {struct}."], False

    # Normal
    return "normal", ["No high-risk signals; needs review."], False
