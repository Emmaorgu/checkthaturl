# app/hunter/sources/openphish.py
from __future__ import annotations
import requests, datetime as dt
from .base import Candidate

FEED_URL = "https://openphish.com/feed.txt"  # free feed: plain text, one URL per line

def pull(limit: int = 200, timeout: int = 10) -> list[Candidate]:
    try:
        r = requests.get(FEED_URL, timeout=timeout)
        r.raise_for_status()
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
    except Exception:
        lines = []  # be resilient; discovery shouldn’t crash pipeline

    lines = lines[:max(0, limit)]
    now = dt.datetime.utcnow()
    return [Candidate(url=u, source="openphish", first_seen=now) for u in lines]
