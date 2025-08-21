# app/services/brand_spoof.py
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse

# eTLD+1 helper (same heuristic used elsewhere)
def _registrable_domain(u: str) -> str:
    try:
        host = urlparse(u).hostname or ""
        parts = host.split(".")
        if len(parts) < 2: return host
        last2, last3 = ".".join(parts[-2:]), ".".join(parts[-3:])
        multi = ("co.uk","org.uk","gov.uk","ac.uk","com.au","net.au","org.au","com.br","com.mx","com.tr","com.ng","co.jp")
        if any(last3.endswith(t) for t in multi) and len(parts) >= 3: return last3
        return last2
    except Exception:
        return ""

# Core brands we most often see spoofed (add more later)
BRANDS = {
    "paypal.com": ["paypal", "pypl"],
    "microsoft.com": ["microsoft", "outlook", "live", "microsoftonline"],
    "apple.com": ["apple", "icloud", "appleid"],
    "google.com": ["google", "gmail", "googlemail", "gpay"],
    "amazon.com": ["amazon", "aws"],
    "facebook.com": ["facebook", "meta"],
    "netflix.com": ["netflix"],
    "binance.com": ["binance"],
    "paystack.com": ["paystack"],
    "flutterwave.com": ["flutterwave"],
    "interswitchgroup.com": ["interswitch"],
    "monnify.com": ["monnify"],
    "firstbanknigeria.com": ["firstbank"],
    "gtbank.com": ["gtbank", "gtco"],
    "accessbankplc.com": ["accessbank", "access"],
    "zenithbank.com": ["zenith", "zenithbank"],
}

CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "@": "a", "$": "s"
})

def _norm(s: str) -> str:
    s = s.lower()
    return re.sub(r"[^a-z0-9]+", "", s.translate(CONFUSABLES))

def _lev(a: str, b: str) -> int:
    # tiny Levenshtein (O(len(a)*len(b)))
    n, m = len(a), len(b)
    if n == 0: return m
    if m == 0: return n
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, m + 1):
            cur = dp[j]
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev + cost)
            prev = cur
    return dp[m]

def detect_brand_spoof(url: str, html: str, trusted_domains: set[str] | None = None) -> List[str]:
    """
    If the registrable domain is a near-miss of a major brand but NOT that brand's domain,
    return human-readable spoof reasons.
    """
    reasons: List[str] = []
    reg = _registrable_domain(url)
    host = urlparse(url).hostname or ""
    trusted_domains = trusted_domains or set()

    # If this is already a trusted/official domain, don't flag
    if reg in BRANDS.keys() or reg in trusted_domains:
        return reasons

    base = _norm(reg.split(".")[0])  # core label to compare (e.g., 'paypa1-secure' -> 'paypalsecure')
    for brand_domain, tokens in BRANDS.items():
        brand_key = _norm(brand_domain.split(".")[0])  # e.g., 'paypal'
        d = _lev(base, brand_key)
        if d == 1 or (d == 2 and len(base) >= 6) or any(t in base for t in map(_norm, tokens)):
            reasons.append(f"Domain resembles {brand_domain} (possible brand spoof).")
            break

    # Subdomain trick (e.g., paypal.com.evil.xyz)
    if any(t + "." in host.lower() for t in sum(BRANDS.values(), [])):
        reasons.append("Brand name appears in a subdomain of a different site.")

    return reasons
