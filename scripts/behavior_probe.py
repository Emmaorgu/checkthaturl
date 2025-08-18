#!/usr/bin/env python3
import csv, json, time, os, sys
from pathlib import Path

# Make root importable for local dev
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

simulate = None
_import_err = None
try:
    # prefer package layout
    from app.replay_engine import simulate  # type: ignore
except Exception as e1:
    try:
        # fallback to root layout
        from replay_engine import simulate  # type: ignore
    except Exception as e2:
        _import_err = f"{type(e1).__name__}: {e1} ; {type(e2).__name__}: {e2}"

def load_urls(fp: str):
    rows = []
    with open(fp, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if "url" not in (r.fieldnames or []):
            raise SystemExit("Input CSV must have a 'url' header.")
        for row in r:
            u = (row.get("url") or "").strip()
            if u: rows.append(u)
    return rows

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Run behavior engine over a list of URLs (CSV).")
    ap.add_argument("--urls-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sleep", type=float, default=0.2)
    args = ap.parse_args()

    urls = load_urls(args.urls_file)
    out = {"runs": [], "summary": {"total": len(urls)}}

    if simulate is None:
        msg = f"behavior engine not available: {_import_err}"
        for u in urls:
            out["runs"].append({"url": u, "behavior": {"mode": "error", "score": 0.0, "events": [msg]}})
    else:
        for u in urls:
            try:
                res = simulate(u)
            except Exception as e:
                res = {"mode": "error", "score": 0.0, "events": [f"error:{type(e).__name__}"]}
            out["runs"].append({"url": u, "behavior": res})
            time.sleep(args.sleep)

    Path(os.path.dirname(args.out) or ".").mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {args.out}")
    for r in out["runs"]:
        b = r["behavior"]
        print(f"- {r['url']} :: mode={b.get('mode')} score={b.get('score')} "
              f"dom_mut={b.get('dom_mutation_score')} http={b.get('http_redirects')} "
              f"client={b.get('client_redirects')} post={b.get('post_action_redirects')}")

if __name__ == "__main__":
    main()
