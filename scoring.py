"""
scoring.py
Combines individual Indicator weights into a bounded 0-100 risk score and
maps that score onto a human-readable risk level.
"""

from typing import List
from models import Indicator

# Risk level thresholds. Tune these based on desired sensitivity.
RISK_LEVELS = [
    (0, 14, "Low"),
    (15, 34, "Medium"),
    (35, 64, "High"),
    (65, 100, "Critical"),
]


def compute_risk_score(indicators: List[Indicator]) -> int:
    """
    Sums the weights of triggered indicators, then compresses the total with a
    soft cap so that a handful of severe signals can still reach the top of the
    scale without requiring every single indicator to fire.
    """
    raw_total = sum(i.weight for i in indicators if i.triggered)
    # Soft cap: anything at/above 100 raw points is already unambiguous.
    score = min(100, raw_total)
    return score


def score_to_level(score: int) -> str:
    for low, high, label in RISK_LEVELS:
        if low <= score <= high:
            return label
    return "Critical"  # fallback for scores above the defined table


def compute_confidence(indicators: List[Indicator]) -> str:
    """
    A rough confidence label based on how many checks could actually be
    performed (vs. skipped due to network/lookup failures).
    """
    total = len(indicators)
    checked = len([i for i in indicators if i.checked])
    if total == 0:
        return "Unknown"
    ratio = checked / total
    if ratio >= 0.9:
        return "High"
    if ratio >= 0.6:
        return "Medium"
    return "Low"
