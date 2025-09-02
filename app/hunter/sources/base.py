# app/hunter/sources/base.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# Optional dependency; we fall back gracefully if missing
try:
    import tldextract
except Exception:
    tldextract = None

TRACKER_PREFIXES = ("utm_",)
TRACKER_KEYS = {
    "gclid", "fbclid", "mc_eid", "mc_cid", "igshid", "si", "spm",
    "ref", "ref_src", "source", "campaign", "track"
}

@dataclass(frozen=True)
class Candidate:
    url: str
    source: str
    first_seen: datetime

def _strip_trackers(query_pairs):
    clean = []
    for k, v in query_pairs:
        lk = (k or "").lower()
        if lk.startswith(TRACKER_PREFIXES) or lk in TRACKER_KEYS:
            continue
        clean.append((k, v))
    return clean

def _registrable_domain(host: str) -> str:
    host = (host or "").lower().split(":")[0]
    if not host:
        return ""
    if tldextract:
        ext = tldextract.extract(host)  # e.g. sub, domain, suffix
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return host
    # Fallback heuristic if tldextract not installed
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:]).lower()

def normalize_url(raw: str) -> Tuple[str, str, str]:
    """
    Return (normalized_url, domain, url_hash)
    - enforces scheme (defaults to https)
    - lowercases host, strips default ports
    - removes tracker params and sorts remaining params
    - keeps path/query/fragment otherwise intact
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty url")
    if raw.startswith("//"):
        raw = "https:" + raw
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    p = urlparse(raw)
    scheme = p.scheme.lower()
    host = (p.netloc or "").lower()
    # strip default ports
    if host.endswith(":80") and scheme == "http":
        host = host[:-3]
    if host.endswith(":443") and scheme == "https":
        host = host[:-4]

    # dedupe & clean query
    q_pairs = parse_qsl(p.query, keep_blank_values=True)
    q_pairs = _strip_trackers(q_pairs)
    q_pairs.sort(key=lambda kv: (kv[0].lower(), kv[1]))  # stable order
    query = urlencode(q_pairs, doseq=True)

    norm = urlunparse((scheme, host, p.path or "/", p.params, query, p.fragment))
    domain = _registrable_domain(host)
    url_hash = sha256(norm.encode("utf-8", errors="ignore")).hexdigest()
    return norm, domain, url_hash
