"""Add Agentic Hunter core tables

Revision ID: 19b37bbb8709
Revises:
Create Date: 2025-09-02 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "19b37bbb8709"
down_revision = None
branch_labels = None
depends_on = None


def _has_table(conn, name: str) -> bool:
    insp = sa.inspect(conn)
    try:
        return name in insp.get_table_names()
    except Exception:
        return False


def upgrade():
    conn = op.get_bind()

    # --- hunter_discovered_urls ---
    if not _has_table(conn, "hunter_discovered_urls"):
        op.create_table(
            "hunter_discovered_urls",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("domain", sa.Text(), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("first_seen", sa.DateTime(), nullable=False),
            sa.Column("url_hash", sa.String(length=64), nullable=False),
            sa.Column("normalized", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=8), nullable=False),
            sa.UniqueConstraint("url_hash", name="uq_hunter_urlhash"),
        )
        op.create_index("ix_hunter_domain", "hunter_discovered_urls", ["domain"])
        op.create_index("ix_hunter_status", "hunter_discovered_urls", ["status"])

    # --- hunter_enrichments ---
    if not _has_table(conn, "hunter_enrichments"):
        op.create_table(
            "hunter_enrichments",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "url_id",
                sa.Integer(),
                sa.ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("whois_json", sa.JSON(), nullable=True),
            sa.Column("dns_json", sa.JSON(), nullable=True),
            sa.Column("ssl_json", sa.JSON(), nullable=True),
            sa.Column("passive_score", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("ts", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_hunter_enrichment_url", "hunter_enrichments", ["url_id"])
        op.create_index("ix_hunter_enrichment_ts", "hunter_enrichments", ["ts"])

    # --- hunter_scans ---
    if not _has_table(conn, "hunter_scans"):
        op.create_table(
            "hunter_scans",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "url_id",
                sa.Integer(),
                sa.ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("verdict", sa.String(length=32), nullable=False),
            sa.Column("score", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("explanations_json", sa.JSON(), nullable=True),
            sa.Column("artifacts_json", sa.JSON(), nullable=True),
            sa.Column("features_json", sa.JSON(), nullable=True),
            sa.Column("ts", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_hunter_scan_url", "hunter_scans", ["url_id"])
        op.create_index("ix_hunter_scan_ts", "hunter_scans", ["ts"])

    # --- hunter_proposals ---
    if not _has_table(conn, "hunter_proposals"):
        op.create_table(
            "hunter_proposals",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "url_id",
                sa.Integer(),
                sa.ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("suggested_actions_json", sa.JSON(), nullable=False),
            sa.Column("ttl_minutes", sa.Integer(), nullable=False, server_default=sa.text("60")),
            sa.Column("state", sa.String(length=16), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("approver", sa.String(length=256), nullable=True),
            sa.Column("decision_ts", sa.DateTime(), nullable=True),
            sa.Column("audit_log_json", sa.JSON(), nullable=True),
            sa.Column("created_ts", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_hunter_proposal_state", "hunter_proposals", ["state"])
        op.create_index("ix_hunter_proposal_confidence", "hunter_proposals", ["confidence"])
        op.create_index("ix_hunter_proposal_created", "hunter_proposals", ["created_ts"])


def downgrade():
    # Drop in reverse order, ignore if already gone
    for ix, tbl in [
        ("ix_hunter_proposal_created", "hunter_proposals"),
        ("ix_hunter_proposal_confidence", "hunter_proposals"),
        ("ix_hunter_proposal_state", "hunter_proposals"),
        ("ix_hunter_scan_ts", "hunter_scans"),
        ("ix_hunter_scan_url", "hunter_scans"),
        ("ix_hunter_enrichment_ts", "hunter_enrichments"),
        ("ix_hunter_enrichment_url", "hunter_enrichments"),
        ("ix_hunter_status", "hunter_discovered_urls"),
        ("ix_hunter_domain", "hunter_discovered_urls"),
    ]:
        try:
            op.drop_index(ix, table_name=tbl)
        except Exception:
            pass

    for tbl in [
        "hunter_proposals",
        "hunter_scans",
        "hunter_enrichments",
        "hunter_discovered_urls",
    ]:
        try:
            op.drop_table(tbl)
        except Exception:
            pass
