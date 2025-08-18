#!/usr/bin/env python3
"""
phish_benchmark_runner.py

A single-file, ready-to-run benchmarking script that:
1. Fetches 5 malicious URLs from OpenPhish (public feed)
2. Uses 5 benign example URLs (hardcoded popular sites)
3. Queries checkthaturl.com (tries /api/scan then falls back to scraping the UI)
4. Saves results to results/raw_results.csv and prints simple metrics

Safety notes:
- This script NEVER opens or renders malicious pages in a browser. It only performs lookups (HTTP GET) against public APIs/pages.
- Respect rate limits (default 1 request/sec). Adjust RATE_LIMIT if you need to be gentler.

Usage:
  1. (Optional) create and activate a venv: python -m venv .venv && source .venv/bin/activate
  2. pip install -r requirements.txt  (or: pip install requests pandas)
  3. python phish_benchmark_runner.py

Output:
  - results/raw_results.csv  (url,label,checkthat_verdict,raw_snippet)
  - results/metrics.txt

If you want to add Google Safe Browsing or VirusTotal, put keys in the config section below and I can extend the script.
"""

import time
import requests
import csv
import os
from pathlib import Path
from urllib.parse import quote_plus
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, accuracy_score, confusion_matrix

# ------------------ Config ------------------
CHECKTHAT_BASE = "https://checkthaturl.com"
RATE_LIMIT = 1.0  # seconds between requests to external services
RESULTS_DIR = Path("results")
DATA_DIR = Path("dataset")
DATA_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# If you have API keys, you can add them here later.
GOOGLE_SAFE_BROWSING_KEY = None
VIRUSTOTAL_KEY = None

# ------------------ Helper funcs ------------------

def fetch_openphish_sample(n=5):
    """Fetch the OpenPhish public feed and return n urls."""
    feed = "https://openphish.com/feed.txt"
    print("Downloading OpenPhish feed...", feed)
    r = requests.get(feed, timeout=20)
    r.raise_for_status()
    lines = [l.strip() for l in r.text.splitlines() if l.strip()]
    print(f"OpenPhish returned {len(lines)} entries; sampling {n}")
    return lines[:n]


def build_dataset(malicious_n=5, benign_n=5):
    """Return a list of (url,label) pairs. Malicious sourced from OpenPhish. Benign hardcoded popular sites."""
    malicious = fetch_openphish_sample(malicious_n)
    benign_examples = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.bbc.co.uk",
        "https://www.amazon.co.uk",
    ]
    benign = benign_examples[:benign_n]
    rows = []
    for u in malicious:
        rows.append((u, "malicious"))
    for u in benign:
        rows.append((u, "benign"))
    # shuffle but keep deterministic order for reproducibility
    return rows


def check_checkthaturl(url, session):
    """Try to query checkthaturl API endpoint, fallback to scraping UI.
    Returns a dict with at least 'verdict' key.
    """
    try:
        q = quote_plus(url)
        # Try API endpoint first
        api_try = f"{CHECKTHAT_BASE}/api/scan?url={q}"
        print("Trying API endpoint:", api_try)
        r = session.get(api_try, timeout=20)
        if r.status_code == 200:
            # If JSON, parse
            ctype = r.headers.get("content-type","")
            if "application/json" in ctype:
                return r.json()
            # sometimes returns HTML; fallthrough
        # Fallback: UI page
        ui_url = f"{CHECKTHAT_BASE}/?url={q}"
        print("Falling back to UI page:", ui_url)
        r = session.get(ui_url, timeout=20)
        if r.status_code != 200:
            return {"verdict": "error", "http_status": r.status_code}
        text = r.text.lower()
        if "malicious" in text:
            v = "malicious"
        elif "suspicious" in text:
            v = "suspicious"
        elif "safe" in text or "benign" in text:
            v = "benign"
        else:
            v = "unknown"
        return {"verdict": v, "raw_html_snippet": r.text[:500]}
    except Exception as e:
        return {"verdict": "error", "error": str(e)}


# ------------------ Main runner ------------------

def run_small_benchmark():
    dataset = build_dataset(malicious_n=5, benign_n=5)
    out_rows = []
    session = requests.Session()
    session.headers.update({"User-Agent": "CheckBench/1.0 (+https://example.com)"})
    print("Starting checks (rate limit", RATE_LIMIT, "s)...")

    for url, label in dataset:
        print("\nChecking:", url)
        res = check_checkthaturl(url, session)
        verdict = res.get("verdict") if isinstance(res, dict) else str(res)
        raw = ''
        if isinstance(res, dict):
            raw = str(res.get('raw_html_snippet') or res)[:800]
        out_rows.append({
            'url': url,
            'label': label,
            'checkthat_verdict': verdict,
            'raw': raw
        })
        time.sleep(RATE_LIMIT)

    # save CSV
    out_csv = RESULTS_DIR / "raw_results.csv"
    keys = ['url','label','checkthat_verdict','raw']
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in out_rows:
            writer.writerow(r)
    print("Saved results to", out_csv)

    # Evaluate simple metrics: treat 'suspicious' as malicious
    df = pd.DataFrame(out_rows)
    def map_pred(p):
        if isinstance(p, str):
            p = p.lower()
            if 'malicious' in p:
                return 'malicious'
            if 'suspicious' in p:
                return 'malicious'
            if 'benign' in p or p == 'safe':
                return 'benign'
        return 'unknown'
    df['pred'] = df['checkthat_verdict'].apply(map_pred)
    df_eval = df[df['pred'] != 'unknown']
    if df_eval.empty:
        print("No usable predictions returned (all unknown). See results/raw_results.csv for raw output.")
        return

    y_true = df_eval['label'].map(lambda x: 'malicious' if x == 'malicious' else 'benign')
    y_pred = df_eval['pred']
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', pos_label='malicious')
    acc = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred, labels=['malicious','benign'])

    summary = f"Precision: {precision:.3f}\nRecall: {recall:.3f}\nF1: {f1:.3f}\nAccuracy: {acc:.3f}\nConfusion:\n{cm.tolist()}\n"
    print('\n' + summary)
    with open(RESULTS_DIR / 'metrics.txt', 'w', encoding='utf-8') as f:
        f.write(summary)
    print("Wrote", RESULTS_DIR / 'metrics.txt')


if __name__ == '__main__':
    run_small_benchmark()
