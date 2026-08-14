"""
models.py
Shared data structures for the phishing detection system.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Indicator:
    """A single check result contributing to the overall risk score."""
    key: str                 # short machine-readable id, e.g. "ip_in_domain"
    label: str                # human-readable name
    triggered: bool           # did the suspicious condition fire?
    weight: int                # points added to risk score if triggered (0-100 scale contribution)
    category: str              # "structural" | "ssl" | "redirect" | "reputation"
    explanation: str           # why this matters / what was found
    checked: bool = True       # False if the check could not be performed (e.g. no network)


@dataclass
class AnalysisResult:
    url: str
    normalized_url: str
    host: str
    registrable_domain: str
    risk_score: int
    risk_level: str
    indicators: List[Indicator] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    errors: List[str] = field(default_factory=list)

    def triggered_indicators(self) -> List[Indicator]:
        return [i for i in self.indicators if i.triggered]

    def unchecked_indicators(self) -> List[Indicator]:
        return [i for i in self.indicators if not i.checked]
