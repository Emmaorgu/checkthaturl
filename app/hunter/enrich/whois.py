# app/hunter/enrich/whois.py
from __future__ import annotations
from typing import Optional, Dict, Any

def lookup_whois(domain: str, timeout: int = 6) -> Optional[Dict[str, Any]]:
    """
    Stub for editor satisfaction. Return None so the worker's fallback path is used.
    Replace with a real WHOIS implementation later.
    """
    return None
