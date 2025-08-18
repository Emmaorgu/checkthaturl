# app/__init__.py
"""
Lightweight package init to avoid circular imports.
Re-exports common helpers from policy_utils so callers can keep using:
    from app import guarded_verdict, compute_category_scores, detect_urgency_timer
"""
from .policy_utils import guarded_verdict, compute_category_scores, detect_urgency_timer, clip01

__all__ = [
    "guarded_verdict",
    "compute_category_scores",
    "detect_urgency_timer",
    "clip01",
]
