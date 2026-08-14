"""
report.py
Turns a risk level + triggered indicators into concrete, actionable
recommendations, and renders a readable text report for the CLI.
"""

from typing import List
from models import Indicator, AnalysisResult

BASE_RECOMMENDATIONS = {
    "Low": [
        "No strong phishing indicators were found, but no automated tool is "
        "a substitute for judgment - stay alert for anything that feels off.",
        "Still avoid entering credentials on this site if you arrived via an "
        "unsolicited email, SMS, or ad rather than typing the address yourself.",
    ],
    "Medium": [
        "Do not enter passwords, one-time codes, or payment details until you "
        "independently verify the site (e.g. type the known address directly "
        "into your browser instead of clicking the link again).",
        "Hover over links (or long-press on mobile) to preview the real "
        "destination before clicking anything further on this page.",
    ],
    "High": [
        "Treat this URL as untrusted. Do not log in, download attachments, or "
        "enter any personal or financial information.",
        "If this arrived via email or message, report it to your IT/security "
        "team or email provider's phishing-report feature.",
        "If you already entered credentials on this site, change that "
        "password immediately (and anywhere else you reused it) and enable "
        "multi-factor authentication.",
    ],
    "Critical": [
        "Do not interact with this URL at all - close the tab/page.",
        "Report the URL to your organization's security team and, if relevant, "
        "to the impersonated brand and services like Google Safe Browsing.",
        "If credentials, OTP codes, or payment info were already submitted, "
        "treat them as compromised: reset passwords, alert your bank/card "
        "issuer if payment data was involved, and monitor for fraud.",
    ],
}


def build_recommendations(risk_level: str, indicators: List[Indicator]) -> List[str]:
    recs = list(BASE_RECOMMENDATIONS.get(risk_level, []))

    triggered_keys = {i.key for i in indicators if i.triggered}

    if "brand_impersonation" in triggered_keys:
        recs.append(
            "This URL references a well-known brand outside its real domain. "
            "Navigate to that brand's site by typing the address yourself or "
            "using a saved bookmark rather than this link."
        )
    if "ssl_invalid_or_expired" in triggered_keys or "no_https" in triggered_keys:
        recs.append(
            "The connection is not properly secured/verified. Never submit "
            "sensitive data over this connection."
        )
    if "redirect_domain_mismatch" in triggered_keys:
        recs.append(
            "The link redirects somewhere different from where it appears to "
            "point. Confirm the final destination independently before trusting it."
        )
    if "url_shortener" in triggered_keys:
        recs.append(
            "Expand shortened links using a preview service before clicking, "
            "or ask the sender to share the full URL directly."
        )

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for r in recs:
        if r not in seen:
            deduped.append(r)
            seen.add(r)
    return deduped


def render_text_report(result: AnalysisResult) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(f"PHISHING RISK REPORT")
    lines.append("=" * 72)
    lines.append(f"URL analyzed : {result.url}")
    lines.append(f"Host         : {result.host}")
    lines.append(f"Domain       : {result.registrable_domain}")
    lines.append(f"Analyzed at  : {result.analyzed_at}")
    lines.append("-" * 72)
    lines.append(f"RISK SCORE   : {result.risk_score} / 100")
    lines.append(f"RISK LEVEL   : {result.risk_level}")
    lines.append("-" * 72)

    triggered = result.triggered_indicators()
    if triggered:
        lines.append(f"TRIGGERED INDICATORS ({len(triggered)}):")
        for ind in sorted(triggered, key=lambda i: -i.weight):
            lines.append(f"  [{ind.weight:>2} pts] ({ind.category}) {ind.label}")
            lines.append(f"           -> {ind.explanation}")
    else:
        lines.append("TRIGGERED INDICATORS: none found.")

    unchecked = result.unchecked_indicators()
    if unchecked:
        lines.append("-" * 72)
        lines.append(f"UNVERIFIED CHECKS ({len(unchecked)}) - could not be performed:")
        for ind in unchecked:
            lines.append(f"  - {ind.label}: {ind.explanation}")

    lines.append("-" * 72)
    lines.append("RECOMMENDED ACTIONS:")
    for i, rec in enumerate(result.recommendations, 1):
        lines.append(f"  {i}. {rec}")

    if result.errors:
        lines.append("-" * 72)
        lines.append("NOTES / ERRORS:")
        for e in result.errors:
            lines.append(f"  - {e}")

    lines.append("=" * 72)
    return "\n".join(lines)
