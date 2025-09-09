# app/hunter/sources/typosquat.py
from __future__ import annotations
import datetime as dt
from .base import Candidate

PREFIXES = ["secure", "update", "verify", "login", "auth", "support", "wallet"]
SEPARATORS = ["", "-", ""]

def _variants(brand: str) -> list[str]:
    b = brand.lower().replace(" ", "")
    alts = {b, b + "bank", b + "ng", b + "online"}
    return sorted(alts)

def generate(brands: list[str], tlds: list[str], max_per_brand: int = 100) -> list[Candidate]:
    now = dt.datetime.utcnow()
    out: list[Candidate] = []
    tlds = [t if t.startswith(".") else "." + t for t in tlds]
    for brand in brands:
        candidates = []
        for core in _variants(brand):
            for pre in PREFIXES:
                for sep in SEPARATORS:
                    host = f"{pre}{sep}{core}" if pre else core
                    for tld in tlds:
                        candidates.append(f"https://{host}{tld}/")
        # cap per brand; we just want a representative pool
        candidates = candidates[:max_per_brand]
        out.extend([Candidate(url=u, source="typosquat", first_seen=now) for u in candidates])
    return out
