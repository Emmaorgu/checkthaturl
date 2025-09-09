# scripts/reset_to_pending.py
from __future__ import annotations
import os, sys, json, argparse
from pathlib import Path
from sqlalchemy import select

# Ensure project root is importable when run directly
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.app import app as flask_app, db  # noqa: E402
from app.hunter.models import Proposal    # noqa: E402

LEDGER_PATH = ROOT / "data" / "notified_ids.json"

def load_ledger() -> set[str]:
    if LEDGER_PATH.exists():
        try:
            return set(json.loads(LEDGER_PATH.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()

def save_ledger(s: set[str]) -> None:
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_PATH.write_text(json.dumps(sorted(list(s))), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Reset some proposals to pending and clear dedupe ledger for them.")
    ap.add_argument("--limit", type=int, default=3, help="How many to reset")
    ap.add_argument("--from-states", nargs="+", default=["approved", "denied"],
                    help="States to pull from (default: approved denied)")
    args = ap.parse_args()

    reset_ids: list[str] = []

    with flask_app.app_context():
        # Fetch ORM-mapped objects (NOT Row objects)
        stmt = (
            select(Proposal)
            .where(Proposal.state.in_(tuple(args.from_states)))
            .order_by(Proposal.id.desc())
            .limit(args.limit)
        )
        proposals = db.session.execute(stmt).scalars().all()

        for p in proposals:
            p.state = "pending"          # now valid: p is a Proposal instance
            reset_ids.append(str(p.id))
            db.session.add(p)

        db.session.commit()

    # Clear dedupe ledger for these IDs so they will be sent again
    ledger = load_ledger()
    before = len(ledger)
    for pid in reset_ids:
        ledger.discard(pid)
    save_ledger(ledger)
    removed = before - len(ledger)

    print({
        "reset_to_pending": len(reset_ids),
        "cleared_from_dedupe": removed,
        "ids": reset_ids
    })

if __name__ == "__main__":
    main()
