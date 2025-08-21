# app/services/behavior_detectors.py
from __future__ import annotations
import re
from typing import Dict, List, Iterable, Tuple
from urllib.parse import urlparse

_WEAK_PHRASE = re.compile(
    r"(further\s+checks\s+recommended|seek\s+further\s+verification|manual\s+review\s+recommended)",
    re.I,
)


def _norm_events(events: Iterable[str]) -> List[str]:
    out: List[str] = []
    for e in events or []:
        if not e:
            continue
        s = str(e).strip()
        if s:
            out.append(s.lower())
    return out


def _hop_hosts(chain: Iterable[str]) -> List[str]:
    hosts: List[str] = []
    for u in chain or []:
        try:
            h = urlparse(u).hostname or ""
        except Exception:
            h = ""
        if h:
            hosts.append(h.lower())
    return hosts


def _same_etld1(a: str, b: str) -> bool:
    """Heuristic eTLD+1 matcher (last two labels)."""
    def key(h: str) -> str:
        parts = [p for p in h.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else h
    return key(a) == key(b)


def _cross_site_pairs(hosts: List[str]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    if len(hosts) < 2:
        return pairs
    prev = hosts[0]
    for h in hosts[1:]:
        if not _same_etld1(prev, h):
            pairs.append((prev, h))
        prev = h
    return pairs


def detect_behavior_reasons(scan: Dict) -> List[str]:
    """
    Build a list of concrete behavior abnormalities using only observed telemetry.
    No weak language, no guesses.
    """
    reasons: List[str] = []
    beh = (scan or {}).get("behavior", {}) or {}
    chain = beh.get("redirect_chain") or []
    events = _norm_events(beh.get("events") or [])

    # Redirects
    if isinstance(chain, list) and len(chain) >= 2:
        reasons.append(f"Multiple redirects observed ({len(chain)} hops).")

    hosts = _hop_hosts(chain)
    xsite = _cross_site_pairs(hosts)
    if xsite:
        a, b = xsite[0]
        reasons.append(f"Redirect crosses site boundary: {a} → {b}.")

    # Helper for event matching
    def seen(rx: str) -> bool:
        r = re.compile(rx, re.I)
        return any(r.search(e) for e in events)

    # Specific behaviors
    if seen(r"\b(js_)?redirect\b|location\.(assign|replace)|meta_refresh"):
        reasons.append("JavaScript or meta refresh redirect triggered.")

    if seen(r"\b(post_redirect|form_submit|credential_submit)\b"):
        reasons.append("Post-submission redirect flow detected.")

    if seen(r"\b(consent_click|allow_click|permission_accept)\b"):
        reasons.append("Consent/permission dialog interaction recorded.")

    # Timers (features or events)
    features = (scan or {}).get("features", {}) or {}
    has_js_timer = bool(features.get("has_js_timer"))
    has_html_timer = bool(features.get("has_html_timer"))
    timer_ev = seen(r"\b(timer|countdown)\b")
    if has_js_timer or has_html_timer or timer_ev:
        reasons.append("Urgency/countdown timer behavior detected.")

    # DOM mutation burst
    mut_count = 0
    for e in events:
        m = re.search(r"dom[_-]?mutation[:=](\d+)", e)
        if m:
            try:
                mut_count = max(mut_count, int(m.group(1)))
            except ValueError:
                pass
    if mut_count >= 20 or seen(r"\b(dom[_-]?mutation|mutation_observed)\b"):
        txt = f"Rapid DOM mutation burst observed{f' (~{mut_count})' if mut_count else ''}."
        reasons.append(txt)

    # Embedding / obfuscation / clipboard / notifications
    if seen(r"\b(third[_-]?party_iframe|iframe_detected)\b"):
        reasons.append("Third-party iframe embedding present.")
    if seen(r"\b(obfuscated_script|eval_call|new Function)\b"):
        reasons.append("Obfuscated or dynamic script execution observed.")
    if seen(r"\b(clipboard|copy_to_clipboard)\b"):
        reasons.append("Clipboard access attempt observed.")
    if seen(r"\b(notification[_-]?prompt|push_permission)\b"):
        reasons.append("Browser notification permission prompt observed.")

    # Deduplicate & drop any weak phrases (belt-and-braces)
    uniq: List[str] = []
    for r in reasons:
        if not r or _WEAK_PHRASE.search(r):
            continue
        if r not in uniq:
            uniq.append(r)
    return uniq
