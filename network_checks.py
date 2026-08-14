"""
network_checks.py
Live checks that require reaching the target host: SSL/TLS certificate
inspection and HTTP redirect chain analysis.

These are wrapped defensively - if the host is unreachable, DNS fails, or the
connection times out, the relevant Indicators are returned with checked=False
rather than raising, so the rest of the report still renders.
"""

import socket
import ssl
from datetime import datetime, timezone

import requests

from models import Indicator
from url_utils import parse_url, get_host, is_ip_address, registrable_domain

REQUEST_TIMEOUT = 6
MAX_REDIRECTS_ALLOWED = 10


def _indicator(key, label, triggered, weight, explanation, category, checked=True):
    return Indicator(
        key=key, label=label, triggered=triggered, weight=weight,
        category=category, explanation=explanation, checked=checked,
    )


def check_https_scheme(raw_url: str) -> Indicator:
    scheme = parse_url(raw_url).scheme
    triggered = scheme != "https"
    return _indicator(
        "no_https", "Site does not use HTTPS",
        triggered, 15,
        f"The URL uses '{scheme}://' rather than 'https://'. Without TLS, any "
        "data submitted (including credentials) travels unencrypted and the "
        "site's identity cannot be cryptographically verified."
        if triggered else "URL uses HTTPS.",
        category="ssl",
    )


def _get_certificate(host: str, port: int = 443, timeout: int = REQUEST_TIMEOUT):
    """Connect and retrieve the peer certificate + whether the chain validated."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return cert, True  # validated against system trust store


def check_ssl_certificate(host: str):
    """
    Returns a list of Indicators covering: reachability/validity, self-signed /
    hostname-mismatch detection, and certificate age.
    """
    results = []

    if is_ip_address(host):
        results.append(_indicator(
            "ssl_certificate", "TLS certificate validity",
            False, 0, "Skipped: host is a raw IP address.", "ssl", checked=False,
        ))
        return results

    try:
        cert, validated = _get_certificate(host)
        results.append(_indicator(
            "ssl_invalid_or_expired", "TLS certificate is invalid, expired, or mismatched",
            False, 0,
            "Certificate chain validated successfully against the system trust store, "
            "and the hostname matched.",
            "ssl",
        ))

        # Certificate freshness check - very recently issued certs are common
        # among fast-flux / disposable phishing infrastructure (not inherently
        # bad, but a meaningful signal in combination with other indicators).
        not_before = cert.get("notBefore")
        if not_before:
            try:
                issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                issued = issued.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - issued).days
                recent = age_days <= 14
                results.append(_indicator(
                    "cert_recently_issued", "TLS certificate was issued very recently",
                    recent, 10,
                    f"Certificate was issued {age_days} day(s) ago ({not_before}). "
                    "Extremely fresh certificates are common on quickly-stood-up "
                    "phishing infrastructure, though also normal for new legitimate sites."
                    if recent else f"Certificate age ({age_days} days) is not unusually recent.",
                    "ssl",
                ))
            except ValueError:
                results.append(_indicator(
                    "cert_recently_issued", "TLS certificate issue date",
                    False, 0, "Could not parse certificate issue date.", "ssl", checked=False,
                ))

    except ssl.SSLCertVerificationError as e:
        results.append(_indicator(
            "ssl_invalid_or_expired", "TLS certificate is invalid, expired, or mismatched",
            True, 25,
            f"Certificate verification failed: {e.verify_message if hasattr(e, 'verify_message') else e}. "
            "This means the browser cannot confirm the site is who it claims to be - "
            "a strong phishing/MITM signal.",
            "ssl",
        ))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        results.append(_indicator(
            "ssl_invalid_or_expired", "TLS certificate is invalid, expired, or mismatched",
            False, 0, f"Could not establish a connection to check the certificate ({e}).",
            "ssl", checked=False,
        ))

    return results


def check_redirect_chain(raw_url: str):
    """
    Follows redirects (bounded) and flags: long chains, and a final destination
    domain that differs from the original domain (classic cloaking pattern).
    """
    original_host = get_host(raw_url)
    original_reg_domain = registrable_domain(original_host)

    try:
        session = requests.Session()
        response = session.get(
            raw_url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (PhishingAwarenessTool/1.0)"},
        )
        history = response.history
        chain_len = len(history)
        final_host = get_host(response.url)
        final_reg_domain = registrable_domain(final_host)

        long_chain = chain_len > 2
        domain_mismatch = final_reg_domain.lower() != original_reg_domain.lower()
        redirects_to_ip = is_ip_address(final_host)

        indicators = [
            _indicator(
                "redirect_chain_long", "URL passes through many redirects before landing",
                long_chain, 10,
                f"Followed {chain_len} redirect(s) before reaching the final page. "
                "Long redirect chains are used to launder a link's reputation and "
                "evade simple blocklists."
                if long_chain else f"Redirect chain length ({chain_len}) is unremarkable.",
                "redirect",
            ),
            _indicator(
                "redirect_domain_mismatch", "Final destination domain differs from the original",
                domain_mismatch, 20,
                f"Started at '{original_reg_domain}' but ended at '{final_reg_domain}'. "
                "A mismatch between the link you were given and where it actually "
                "lands is one of the strongest phishing/cloaking signals."
                if domain_mismatch else "Final domain matches the originally requested domain.",
                "redirect",
            ),
            _indicator(
                "redirect_to_ip", "Redirect chain ends at a raw IP address",
                redirects_to_ip, 15,
                f"The final destination '{final_host}' is a raw IP address rather "
                "than a domain name."
                if redirects_to_ip else "Final destination is a normal domain name.",
                "redirect",
            ),
        ]
        return indicators, response.status_code, final_host

    except requests.exceptions.SSLError as e:
        return [_indicator(
            "redirect_chain_long", "Redirect chain analysis",
            False, 0, f"Could not follow redirects due to an SSL error: {e}",
            "redirect", checked=False,
        )], None, None
    except requests.exceptions.RequestException as e:
        return [_indicator(
            "redirect_chain_long", "Redirect chain analysis",
            False, 0, f"Could not reach the host to analyze redirects ({e}).",
            "redirect", checked=False,
        )], None, None


def run_network_checks(raw_url: str):
    """Runs all network-dependent checks and returns a flat list of Indicators."""
    host = get_host(raw_url)
    indicators = [check_https_scheme(raw_url)]
    indicators.extend(check_ssl_certificate(host))
    redirect_indicators, status_code, final_host = check_redirect_chain(raw_url)
    indicators.extend(redirect_indicators)
    return indicators
