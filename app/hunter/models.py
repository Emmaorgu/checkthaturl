# app/hunter/models.py
from __future__ import annotations
from datetime import datetime
import enum

from sqlalchemy import String, Text, Float, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.app import db  # single SQLAlchemy instance

class URLStatus(str, enum.Enum):
    NEW = "NEW"
    ENRICHED = "ENRICHED"
    SCANNED = "SCANNED"

class ProposalState(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    APPROVED_SHADOW = "approved_shadow"

class DiscoveredURL(db.Model):
    __tablename__ = "hunter_discovered_urls"
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    normalized: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default=URLStatus.NEW.value)

    enrichments: Mapped[list["Enrichment"]] = relationship(back_populates="durl", cascade="all, delete-orphan")
    scans: Mapped[list["ScanRecord"]] = relationship(back_populates="durl", cascade="all, delete-orphan")
    proposals: Mapped[list["Proposal"]] = relationship(back_populates="durl", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_hunter_domain", "domain"),
        Index("ix_hunter_status", "status"),
    )

class Enrichment(db.Model):
    __tablename__ = "hunter_enrichments"
    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    whois_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    dns_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    ssl_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    passive_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    durl: Mapped["DiscoveredURL"] = relationship(back_populates="enrichments")

    __table_args__ = (
        Index("ix_hunter_enrichment_ts", "ts"),
        Index("ix_hunter_enrichment_url", "url_id"),
    )

class ScanRecord(db.Model):
    __tablename__ = "hunter_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)  # 'phishing'|'suspicious'|'legitimate'
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    explanations_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    artifacts_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    features_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    durl: Mapped["DiscoveredURL"] = relationship(back_populates="scans")

    __table_args__ = (
        Index("ix_hunter_scan_ts", "ts"),
        Index("ix_hunter_scan_url", "url_id"),
    )

class Proposal(db.Model):
    __tablename__ = "hunter_proposals"
    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    suggested_actions_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    ttl_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=ProposalState.PENDING.value)
    approver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    audit_log_json: Mapped[dict | None] = mapped_column(db.JSON, nullable=True)
    created_ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    durl: Mapped["DiscoveredURL"] = relationship(back_populates="proposals")

    __table_args__ = (
        Index("ix_hunter_proposal_confidence", "confidence"),
        Index("ix_hunter_proposal_state", "state"),
        Index("ix_hunter_proposal_created", "created_ts"),
    )
