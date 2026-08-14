# Phishing Detection & Awareness System

A small Python CLI that analyzes a URL for common phishing indicators,
produces a weighted risk score (0-100) with a risk level (Low / Medium /
High / Critical), explains *why* each indicator fired, gives recommended
actions, and keeps a searchable history of everything you've checked.

This is a **heuristic awareness tool**, not a guarantee of safety - it's
meant to demonstrate URL/threat analysis techniques and help build
intuition for what phishing links look like. Always exercise judgment.

## Features

- **Structural analysis** (no network needed): raw-IP hosts, `@` tricks,
  excessive length, excessive subdomains, hyphen-heavy domains, Punycode
  homograph domains, high-abuse TLDs, known URL shorteners, credential/
  urgency keyword clusters, brand-impersonation detection, non-standard
  ports, heavy percent-encoding.
- **SSL/TLS checks** (network): HTTPS presence, certificate validity,
  hostname verification, certificate freshness.
- **Redirect chain analysis** (network): number of hops, whether the final
  domain differs from the original (cloaking), whether it lands on a raw IP.
- **Weighted risk scoring** with a confidence rating based on how many
  checks could actually be completed.
- **Plain-language explanations** for every triggered indicator.
- **Actionable recommendations** tailored to the risk level and the
  specific indicators found.
- **SQLite history** of every analysis, with filtering and CSV export.

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

Analyze a URL (full analysis, including live SSL/redirect checks):

```bash
python main.py check "http://paypal-secure.verify-login.xyz/webscr@confirm"
```

Skip network checks (useful when offline, or for pure heuristic testing):

```bash
python main.py check "http://192.168.1.5/login" --offline
```

Get machine-readable output:

```bash
python main.py check "https://example.com" --json
```

View history:

```bash
python main.py history --limit 10
python main.py history --level Critical
```

Export history to CSV:

```bash
python main.py export report.csv
```

Clear history:

```bash
python main.py clear-history
```

## How the score is built

Each check is an `Indicator` with a `weight` (points contributed if it
triggers) and a `category` (`structural`, `ssl`, `redirect`). The engine
sums the weights of all triggered indicators and caps the total at 100:

| Score | Level    |
|-------|----------|
| 0-14  | Low      |
| 15-34 | Medium   |
| 35-64 | High     |
| 65+   | Critical |

Network checks that can't be completed (host unreachable, DNS failure,
etc.) are marked `checked: False` and excluded from scoring rather than
silently counted as "safe" - the report calls these out separately so you
know the score is based on partial information.

## Project structure

```
phishing_detector/
├── main.py               # CLI entry point
├── analyzer.py            # Orchestrates all checks into one result
├── structural_checks.py   # No-network heuristic indicators
├── network_checks.py      # SSL/TLS + redirect chain indicators
├── scoring.py              # Risk score + level calculation
├── report.py                # Recommendations + text report rendering
├── history.py                # SQLite persistence
├── models.py                  # Indicator / AnalysisResult dataclasses
├── url_utils.py                # URL/domain parsing helpers
└── requirements.txt
```

## Extending it

- Swap the illustrative `HIGH_RISK_TLDS` / `SUSPICIOUS_KEYWORDS` /
  `COMMONLY_IMPERSONATED_BRANDS` sets in `structural_checks.py` for a live
  threat-intel feed.
- Add a WHOIS-based domain-age check in `network_checks.py` (guard it the
  same way as the existing checks: `checked=False` on failure).
- Wrap `analyzer.analyze_url()` in a small Flask/FastAPI app for a web UI -
  the `AnalysisResult` dataclass already serializes cleanly to JSON.
