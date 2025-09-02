# app/hunter/models.py
from __future__ import annotations
from datetime import datetime
from hashlib import sha256
import enum
from typing import Optional, Dict, Any

from sqlalchemy import Index, UniqueConstraint, ForeignKey, JSON
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.db import db


class URLStatus(enum.Enum):
    NEW = "new"
    ENRICHED = "enriched"
    SCANNED = "scanned"
    CLOSED = "closed"


class ProposalState(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    APPROVED_SHADOW = "approved_shadow"  # used in later pilot mode


class DiscoveredURL(db.Model):
    __tablename__ = "hunter_discovered_urls"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(db.Text, nullable=False)              # as-seen URL
    domain: Mapped[str] = mapped_column(db.Text, nullable=False)           # registrable domain
    source: Mapped[str] = mapped_column(db.String(64), nullable=False)     # openphish/urlhaus/typosquat/…
    first_seen: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow, nullable=False)
    url_hash: Mapped[str] = mapped_column(db.String(64), nullable=False)   # sha256(normalized)
    normalized: Mapped[str] = mapped_column(db.Text, nullable=False)       # normalized URL
    status: Mapped[URLStatus] = mapped_column(db.Enum(URLStatus), default=URLStatus.NEW, nullable=False)

    enrichments = relationship("Enrichment", back_populates="url", cascade="all,delete-orphan")
    scans        = relationship("ScanRecord", back_populates="url", cascade="all,delete-orphan")
    proposals    = relationship("Proposal", back_populates="url", cascade="all,delete-orphan")

    __table_args__ = (
        UniqueConstraint("url_hash", name="uq_hunter_urlhash"),
        Index("ix_hunter_domain", "domain"),
        Index("ix_hunter_status", "status"),
    )

    @staticmethod
    def hash_url(u: str) -> str:
        return sha256((u or "").encode("utf-8", errors="ignore")).hexdigest()


class Enrichment(db.Model):
    __tablename__ = "hunter_enrichments"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    whois_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    dns_json:   Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    ssl_json:   Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    passive_score: Mapped[float] = mapped_column(db.Float, nullable=False, default=0.0)
    ts: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow, nullable=False)

    url = relationship("DiscoveredURL", back_populates="enrichments")

    __table_args__ = (
        Index("ix_hunter_enrichment_url", "url_id"),
        Index("ix_hunter_enrichment_ts", "ts"),
    )


class ScanRecord(db.Model):
    __tablename__ = "hunter_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    verdict: Mapped[str] = mapped_column(db.String(32), nullable=False)  # legitimate|suspicious|phishing
    score: Mapped[float] = mapped_column(db.Float, nullable=False, default=0.0)  # 0..1 (risk)
    explanations_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    artifacts_json:    Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)  # screenshot_path, html_hash, etc.
    features_json:     Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)  # CTU feature flags
    ts: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow, nullable=False)

    url = relationship("DiscoveredURL", back_populates="scans")

    __table_args__ = (
        Index("ix_hunter_scan_url", "url_id"),
        Index("ix_hunter_scan_ts", "ts"),
    )


class Proposal(db.Model):
    __tablename__ = "hunter_proposals"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("hunter_discovered_urls.id", ondelete="CASCADE"), nullable=False)
    confidence: Mapped[float] = mapped_column(db.Float, nullable=False)   # 0..1
    suggested_actions_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    ttl_minutes: Mapped[int] = mapped_column(db.Integer, default=60, nullable=False)
    state: Mapped["ProposalState"] = mapped_column(db.Enum(ProposalState), default=ProposalState.PENDING, nullable=False)
    approver: Mapped[Optional[str]] = mapped_column(db.String(256))
    decision_ts: Mapped[Optional[datetime]] = mapped_column(db.DateTime)
    audit_log_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    created_ts: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow, nullable=False)

    url = relationship("DiscoveredURL", back_populates="proposals")

    __table_args__ = (
        Index("ix_hunter_proposal_state", "state"),
        Index("ix_hunter_proposal_confidence", "confidence"),
        Index("ix_hunter_proposal_created", "created_ts"),
    )
