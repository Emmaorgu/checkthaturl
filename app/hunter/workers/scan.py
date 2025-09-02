# app/hunter/workers/scan.py
from __future__ import annotations
import argparse, sys

from app.app import app as flask_app
from app.db import db
from app.hunter.models import DiscoveredURL, ScanRecord, URLStatus
from app.hunter.client.ctu import scan_url

def main(argv=None):
    parser = argparse.ArgumentParser(description="Hunter active scan worker (calls CTU /check)")
    parser.add_argument("--batch", type=int, default=50, help="how many ENRICHED rows to scan")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout per scan (seconds)")
    args = parser.parse_args(argv)

    inserted = 0
    skipped = 0
    errors = 0

    with flask_app.app_context():
        # pick ENRICHED rows with no ScanRecord yet
        # SELECT d.* FROM discovered d LEFT JOIN scans s ON s.url_id=d.id WHERE d.status='ENRICHED' AND s.id IS NULL LIMIT batch;
        q = (
            db.select(DiscoveredURL)
            .outerjoin(ScanRecord, ScanRecord.url_id == DiscoveredURL.id)
            .where(DiscoveredURL.status == URLStatus.ENRICHED, ScanRecord.id.is_(None))
            .limit(args.batch)
        )
        rows = db.session.execute(q).scalars().all()

        for row in rows:
            try:
                resp = scan_url(row.normalized, timeout=args.timeout)
                verdict = str(resp.get("verdict") or "Suspicious")
                score = float(resp.get("score") or 0.0)
                explanations = resp.get("explanations") or {}
                artifacts = resp.get("artifacts") or {}
                features = resp.get("features") or {}

                rec = ScanRecord(
                    url_id=row.id,
                    verdict=verdict.lower(),   # Normalize for consistency
                    score=score,
                    explanations_json=explanations,
                    artifacts_json=artifacts,
                    features_json=features,
                )
                db.session.add(rec)

                # mark URL as scanned regardless (we keep the record even if Suspicious/partial)
                row.status = URLStatus.SCANNED
                db.session.commit()
                inserted += 1
            except Exception:
                db.session.rollback()
                errors += 1

        print({"inserted": inserted, "skipped": skipped, "errors": errors, "batch": len(rows)})

if __name__ == "__main__":
    sys.exit(main())
