# app/services/response_guard.py
from __future__ import annotations
from typing import Dict


def ensure_reasons_contract(verdict: str, reasons: Dict[str, list]) -> None:
    """
    Contract: Non-legit verdicts must list at least one concrete abnormality.
    Raises ValueError if violated so regressions are caught early in dev/CI.
    """
    if verdict in ("Phishing", "Suspicious"):
        total = sum(len(reasons.get(k, [])) for k in ("domain_risks", "content_risks", "link_risks", "behavior_risks"))
        if total == 0:
            raise ValueError("Non-legit verdict without concrete reasons — pipeline contract violated.")
