# app/services/static_detectors.py
from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

# Very light HTML parsers (regex on purpose—no heavy deps)
ANCHOR_RE = re.compile(r"<a\b[^>]*href=['\"]([^'\"#]+)['\"][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)

# Form cues
INPUT_PASSWORD_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.I)
INPUT_OTP_RE = re.compile(r'(?:one[-_\s]*time|otp|2fa|two[-_\s]*factor)', re.I)
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
SUBMIT_RE = re.compile(r"<button[^>]*>(?:\s*sign\s*in|\s*log\s*in|\s*login|\s*verify|\s*continue)\s*</button>", re.I)

# Phrases that often accompany credential capture or verification
CRED_PHRASES = [
    "sign in", "log in", "login", "password", "passcode", "otp", "2fa", "verification code",
    "seed phrase", "private key", "mnemonic", "wallet connect", "verify your account",
    "confirm your identity", "update your payment", "re-authenticate", "enter password",
]

def _registrable_domain(u: str) -> str:
    try:
        host = urlparse(u).hostname or ""
        parts = host.split(".")
        if len(parts) < 2: return host
        last2, last3 = ".".join(parts[-2:]), ".".join(parts[-3:])
        multi = ("co.uk","org.uk","gov.uk","ac.uk","com.au","net.au","org.au",
                 "com.br","com.mx","com.tr","com.ng","co.jp")
        if any(last3.endswith(t) for t in multi) and len(parts) >= 3: return last3
        return last2
    except Exception:
        return ""

def _visible_text(html: str) -> str:
    if not html: return ""
    html = SCRIPT_STYLE_RE.sub(" ", html)          # drop scripts/styles entirely
    txt = TAG_RE.sub(" ", html)
    return WS_RE.sub(" ", txt).strip().lower()

def detect_credential_phrases(html: str) -> List[str]:
    """
    Be conservative: only flag if we also see a <form> with either a password
    input OR clear OTP/2FA cues or a submit button that says 'log in'/'verify'.
    """
    if not html: return []
    text = _visible_text(html)

    # must have a form
    if not FORM_RE.search(html):
        return []

    # strong form cues
    has_pwd = bool(INPUT_PASSWORD_RE.search(html))
    has_otp = bool(INPUT_OTP_RE.search(text))
    has_submit = bool(SUBMIT_RE.search(html))

    # weak cues: natural-language phrases
    weak_hits = [p for p in CRED_PHRASES if p in text]

    # Require at least one strong cue OR >=2 weak cues to fire
    strong = has_pwd or has_otp or has_submit
    if strong or len(weak_hits) >= 2:
        reasons = []
        if has_pwd:
            reasons.append("Credential prompt present (password field).")
        elif has_otp:
            reasons.append("Verification prompt present (OTP/2FA).")
        elif has_submit:
            reasons.append("Credential/verification submit button present.")
        elif weak_hits:
            reasons.append("Credential/verification prompts present.")
        return reasons

    return []

def anchor_mismatch(html: str, base_url: str) -> Tuple[int, int, List[str]]:
    """
    Returns: (total_anchors, cross_site, example_reasons[])
    - cross_site: number of anchors that go to a different registrable domain
    - example_reasons: at most 3 small, human-readable examples
    NOTE: much stricter than before to reduce false-positives.
    """
    anchors = ANCHOR_RE.findall(html or "")
    if not anchors:
        return 0, 0, []
    base_reg = _registrable_domain(base_url)
    examples, cross = [], 0
    for href, inner in anchors:
        absu = urljoin(base_url, href)
        reg = _registrable_domain(absu)
        if reg and base_reg and reg != base_reg:
            cross += 1
            label = TAG_RE.sub("", inner or "")
            label = WS_RE.sub(" ", label).strip()
            if label and len(examples) < 3:
                examples.append(f"Anchor “{label[:24]}” → {reg}")
    return len(anchors), cross, examples

def collect_static_reasons(url: str, html: str, *, min_links: int = 8, offsite_ratio: float = 0.60) -> List[str]:
    """
    Conservative static-only cues that never run scripts.
    """
    reasons: List[str] = []

    # 1) Credential / verification prompts (only when a form exists with strong cues)
    reasons += detect_credential_phrases(html)

    # 2) Cross-site link propensity (require many anchors + high ratio)
    total, cross, ex = anchor_mismatch(html, url)
    if total >= min_links and cross / max(1, total) >= offsite_ratio:
        reasons.append(f"Many links go off-site ({cross}/{total}).")
        if ex:
            reasons += [f"Link out: {e}." for e in ex]

    return reasons
