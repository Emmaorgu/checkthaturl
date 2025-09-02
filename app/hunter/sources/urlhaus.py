# app/hunter/sources/urlhaus.py
from __future__ import annotations
import csv, io, requests, datetime as dt
from .base import Candidate

# CSV with # comments; columns: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

def pull(limit: int = 200, timeout: int = 10) -> list[Candidate]:
    out = []
    try:
        r = requests.get(FEED_URL, timeout=timeout)
        r.raise_for_status()
        buf = io.StringIO(r.text, newline="")
        reader = csv.reader(buf)
        now = dt.datetime.utcnow()
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                url = row[2].strip()
            except Exception:
                continue
            if url:
                out.append(Candidate(url=url, source="urlhaus", first_seen=now))
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out
