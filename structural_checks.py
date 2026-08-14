"""
structural_checks.py
Heuristic checks that require no network access - pure URL/string analysis.
These are fast, always available, and form the backbone of the risk score
even when a target site can't be reached.
"""

import re
from urllib.parse import unquote

from models import Indicator
from url_utils import parse_url, get_host, is_ip_address, split_domain, registrable_domain

# Known URL shortener domains (not exhaustive - illustrative set for the demo)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id",
}

# TLDs that are disproportionately abused for phishing / low-cost bulk registration.
# This is illustrative, not authoritative - a real system would use live abuse feeds.
HIGH_RISK_TLDS = {
    "zip", "xyz", "top", "click", "work", "gq", "tk", "cf", "ml", "country",
    "kim", "loan", "men", "party", "review", "stream", "download", "racing",
    "win", "bid", "date",
}

# Keywords commonly used in phishing URLs/paths to imply urgency or legitimacy.
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "webscr", "banking", "billing", "suspend", "unlock", "password",
    "authenticate", "wallet", "invoice", "support",
}

# A small set of frequently-impersonated brand names. If one of these appears
# in the URL but is NOT part of the actual registrable domain, that's a strong
# signal of brand impersonation (e.g. "paypal-secure-login.xyz").
COMMONLY_IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "bankofamerica", "wellsfargo", "chase", "citibank", "dhl",
    "fedex", "ups", "irs", "usps", "coinbase", "binance", "outlook", "office365",
}


def _indicator(key, label, triggered, weight, explanation):
    return Indicator(
        key=key, label=label, triggered=triggered, weight=weight,
        category="structural", explanation=explanation, checked=True,
    )


def check_ip_in_domain(host: str) -> Indicator:
    triggered = is_ip_address(host)
    return _indicator(
        "ip_in_domain", "URL uses a raw IP address instead of a domain name",
        triggered, 25,
        f"The host '{host}' is a literal IP address rather than a registered domain. "
        "Legitimate services rarely link directly to bare IPs; this is a common way "
        "to hide the true owner of a site."
        if triggered else "The host is a domain name, not a raw IP address.",
    )


def check_at_symbol(raw_url: str) -> Indicator:
    triggered = "@" in raw_url
    return _indicator(
        "at_symbol", "URL contains an '@' symbol",
        triggered, 20,
        "Browsers ignore everything before an '@' in a URL's authority section, "
        "so attackers use it to make a malicious host look like a path on a "
        "trusted domain (e.g. 'https://yourbank.com@evil.tld')."
        if triggered else "No '@' symbol found in the URL.",
    )


def check_url_length(raw_url: str) -> Indicator:
    length = len(raw_url)
    triggered = length > 100
    weight = 15 if length > 150 else 8
    return _indicator(
        "excessive_length", "URL is unusually long",
        triggered, weight if triggered else 0,
        f"The URL is {length} characters long. Very long URLs are sometimes used "
        "to bury a suspicious domain deep in a query string or to overwhelm a "
        "user's ability to visually inspect the link."
        if triggered else f"URL length ({length} chars) is within a normal range.",
    )


def check_many_subdomains(host: str) -> Indicator:
    subs, root, suffix = split_domain(host)
    count = len(subs)
    triggered = count >= 3
    return _indicator(
        "many_subdomains", "Domain has an excessive number of subdomains",
        triggered, 12,
        f"Found {count} subdomain labels ('{'.'.join(subs)}'). Attackers often "
        "chain subdomains (e.g. 'login.secure.paypal.com.verify-user.xyz') to make "
        "a malicious domain visually resemble a trusted one."
        if triggered else f"Subdomain count ({count}) looks normal.",
    )


def check_hyphen_heavy_domain(host: str) -> Indicator:
    subs, root, suffix = split_domain(host)
    hyphens = root.count("-")
    triggered = hyphens >= 2
    return _indicator(
        "hyphen_heavy_domain", "Domain name contains multiple hyphens",
        triggered, 8,
        f"The registrable domain part ('{root}') contains {hyphens} hyphens. "
        "Phishing domains often use hyphens to splice a brand name with extra "
        "words, e.g. 'secure-login-paypal-account.com'."
        if triggered else "Domain does not show excessive hyphen use.",
    )


def check_punycode(host: str) -> Indicator:
    triggered = "xn--" in host.lower()
    return _indicator(
        "punycode_domain", "Domain uses Punycode (internationalized) encoding",
        triggered, 20,
        "The domain contains 'xn--', meaning it encodes non-ASCII characters. "
        "This is legitimate for many international sites, but it is also the "
        "mechanism behind homograph attacks, where look-alike characters "
        "(e.g. Cyrillic 'a') impersonate a trusted domain."
        if triggered else "No Punycode encoding detected in the domain.",
    )


def check_uncommon_tld(host: str) -> Indicator:
    subs, root, suffix = split_domain(host)
    tld = suffix.split(".")[-1] if suffix else ""
    triggered = tld in HIGH_RISK_TLDS
    return _indicator(
        "uncommon_tld", "Domain uses a top-level domain often associated with abuse",
        triggered, 10,
        f"The TLD '.{tld}' is frequently associated with low-cost bulk domain "
        "registration and disproportionately high phishing/spam rates."
        if triggered else f"TLD '.{tld}' is not on the elevated-risk list.",
    )


def check_url_shortener(host: str) -> Indicator:
    triggered = host.lower() in SHORTENER_DOMAINS
    return _indicator(
        "url_shortener", "URL uses a link-shortening service",
        triggered, 10,
        f"'{host}' is a known URL shortener. Shorteners hide the real "
        "destination until after a click, which attackers exploit to bypass "
        "visual inspection and some URL-reputation filters."
        if triggered else "URL is not from a known shortening service.",
    )


def check_suspicious_keywords(raw_url: str, host: str) -> Indicator:
    text = unquote(raw_url).lower()
    found = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in text})
    triggered = len(found) >= 2
    return _indicator(
        "suspicious_keywords", "URL contains multiple credential/urgency-themed keywords",
        triggered, 15,
        f"Found keywords {found} in the URL. Phishing pages frequently combine "
        "words like these to pressure users into re-entering credentials."
        if triggered else "No significant cluster of suspicious keywords found.",
    )


def check_brand_impersonation(raw_url: str, host: str) -> Indicator:
    reg_domain = registrable_domain(host).lower()
    text = unquote(raw_url).lower()
    impersonated = []
    for brand in COMMONLY_IMPERSONATED_BRANDS:
        if brand in text and brand not in reg_domain:
            impersonated.append(brand)
    triggered = len(impersonated) > 0
    return _indicator(
        "brand_impersonation", "Known brand name appears outside the actual domain",
        triggered, 25,
        f"The brand name(s) {sorted(impersonated)} appear in the URL, but the "
        f"actual registrable domain is '{reg_domain}', which does not belong to "
        "that brand. This is a classic impersonation pattern."
        if triggered else "No mismatched brand-name references detected.",
    )


def check_non_standard_port(raw_url: str) -> Indicator:
    parsed = parse_url(raw_url)
    port = parsed.port
    triggered = port is not None and port not in (80, 443)
    return _indicator(
        "non_standard_port", "URL specifies a non-standard port",
        triggered, 8,
        f"The URL explicitly targets port {port}, which is unusual for normal "
        "web browsing and can indicate an ad-hoc or throwaway phishing server."
        if triggered else "URL uses a standard web port (or none specified).",
    )


def check_encoded_characters(raw_url: str) -> Indicator:
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    triggered = len(encoded_matches) >= 4
    return _indicator(
        "heavy_percent_encoding", "URL contains heavy percent-encoding",
        triggered, 10,
        f"Found {len(encoded_matches)} percent-encoded sequences. Excessive "
        "encoding is sometimes used to obscure keywords or characters from "
        "quick visual review and from naive filters."
        if triggered else "No unusual amount of percent-encoding found.",
    )


def run_structural_checks(raw_url: str):
    host = get_host(raw_url)
    return [
        check_ip_in_domain(host),
        check_at_symbol(raw_url),
        check_url_length(raw_url),
        check_many_subdomains(host),
        check_hyphen_heavy_domain(host),
        check_punycode(host),
        check_uncommon_tld(host),
        check_url_shortener(host),
        check_suspicious_keywords(raw_url, host),
        check_brand_impersonation(raw_url, host),
        check_non_standard_port(raw_url),
        check_encoded_characters(raw_url),
    ]
