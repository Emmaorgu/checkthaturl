# scripts/add_triage_columns.py
from __future__ import annotations
import sys
from sqlalchemy import inspect, text
from app.app import app as flask_app, db
from app.hunter.models import Proposal  # ensures __tablename__ is correct

def add_col(engine, table: str, colname: str, sqla_type_sql: str):
    insp = inspect(engine)
    if not insp.has_table(table):
        print(f"[ERROR] Table {table} not found; aborting.")
        sys.exit(2)

    cols = [c["name"] for c in insp.get_columns(table)]
    if colname in cols:
        print(f"[SKIP] {table}.{colname} already exists")
        return

    ddl = f'ALTER TABLE {table} ADD COLUMN {colname} {sqla_type_sql}'
    print(f"[APPLY] {ddl}")
    with engine.begin() as conn:
        conn.execute(text(ddl))

def main():
    with flask_app.app_context():  # <<< critical fix
        engine = db.engine
        table = getattr(Proposal, "__tablename__", "proposals")
        dialect = engine.dialect.name

        if dialect == "postgresql":
            json_type = "JSONB"
            ts_type = "TIMESTAMPTZ"
        elif dialect in ("mysql", "mariadb"):
            json_type = "JSON"
            ts_type = "DATETIME"
        else:
            # sqlite / other: store JSON as TEXT and timestamp as TEXT (ISO)
            json_type = "TEXT"
            ts_type = "TEXT"

        add_col(engine, table, "bucket", "VARCHAR(16)")
        add_col(engine, table, "triage_reason_json", json_type)
        add_col(engine, table, "triaged_at", ts_type)
        # Optional future:
        # add_col(engine, table, "assignee", "VARCHAR(120)")

        print("[DONE] Columns ensured.")

if __name__ == "__main__":
    main()
