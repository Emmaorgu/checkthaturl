#!/usr/bin/env python3
import os, csv, json, time
from pathlib import Path
import requests

BASE = os.environ.get("CTU_BASE", "http://127.0.0.1:5000")
TIMEOUT = float(os.environ.get("CTU_TIMEOUT", "30"))

def load_urls(fp):
    rows = []
    with open(fp, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip()
            if url:
                rows.append({"url": url, "label": label})
    return rows

def scan(url):
    r = requests.post(f"{BASE}/check", json={"url": url}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", required=True, help="dir with legit_startups.csv and phish_set.csv")
    ap.add_argument("--write-report", required=True, help="output JSON report path")
    args = ap.parse_args()

    d = Path(args.golden)
    legit = load_urls(d / "legit_startups.csv")
    phish = load_urls(d / "phish_set.csv")

    out = {"runs": [], "summary": {}}
    stats = {"legit_ok": 0, "legit_bad": 0, "phish_ok": 0, "phish_missed": 0}

    for row in legit + phish:
        url, label = row["url"], row["label"].lower()
        try:
            js = scan(url)
            verdict = (js.get("verdict") or "").lower()
            ok = ((label == "legit" and verdict in ("legitimate","suspicious")) or
                  (label == "phish" and verdict == "phishing"))
            if label == "legit":
                stats["legit_ok" if ok else "legit_bad"] += 1
            else:
                stats["phish_ok" if ok else "phish_missed"] += 1
            out["runs"].append({
                "url": url, "label": label, "verdict": verdict,
                "confidence": js.get("confidence"),
                "category_scores": js.get("category_scores"),
                "structure": js.get("structure"),
                "behavior": js.get("behavior"),
            })
        except Exception as e:
            out["runs"].append({"url": url, "label": label, "error": type(e).__name__})

        time.sleep(0.2)

    out["summary"] = stats
    Path(args.write_report).parent.mkdir(parents=True, exist_ok=True)
    with open(args.write_report, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
