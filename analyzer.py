"""
analyzer.py
Orchestrates structural + network indicator checks into a single AnalysisResult.
"""

from models import AnalysisResult
from url_utils import normalize_url, get_host, registrable_domain
from structural_checks import run_structural_checks
from network_checks import run_network_checks
from scoring import compute_risk_score, score_to_level
from report import build_recommendations


def analyze_url(raw_url: str, use_network: bool = True) -> AnalysisResult:
    normalized = normalize_url(raw_url)
    host = get_host(normalized)
    reg_domain = registrable_domain(host)

    errors = []
    indicators = run_structural_checks(normalized)

    if use_network:
        try:
            indicators.extend(run_network_checks(normalized))
        except Exception as e:  # last-resort guard so a bug in a single check
            errors.append(f"Network checks failed unexpectedly: {e}")
    else:
        errors.append("Network checks skipped (offline mode).")

    score = compute_risk_score(indicators)
    level = score_to_level(score)
    recommendations = build_recommendations(level, indicators)

    return AnalysisResult(
        url=raw_url,
        normalized_url=normalized,
        host=host,
        registrable_domain=reg_domain,
        risk_score=score,
        risk_level=level,
        indicators=indicators,
        recommendations=recommendations,
        errors=errors,
    )
