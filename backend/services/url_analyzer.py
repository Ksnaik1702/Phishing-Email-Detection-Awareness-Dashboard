"""
FILE NAME: url_analyzer.py
FILE PATH: backend/services/url_analyzer.py
PURPOSE: Static string-level URL analyzer for cybersecurity risk inspection.
         IMPORTANT DEFENSIVE SAFETY PROTOCOL:
         This module NEVER opens, resolves, or sends HTTP requests to suspicious URLs.
         All inspection is strictly static, deterministic, and string-based.
"""

import re
from urllib.parse import urlparse
from typing import List, Tuple
from backend.models.schemas import URLAnalysisResult, Finding

# Known URL shortener services often used to obscure real landing pages
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly"
}

# Suspicious high-risk TLDs commonly seen in spam and phishing campaigns
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "country", "gq", "work", "top", "cam", "xyz", "stream", "cfd"
}

# Keywords frequently embedded in deceptive URLs
HIGH_RISK_URL_KEYWORDS = [
    "verify", "login", "signin", "auth", "account", "secure", "update",
    "banking", "password", "renew", "session", "confirm", "portal", "support"
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def analyze_url(url_str: str) -> URLAnalysisResult:
    """
    Performs safe static inspection of a URL string without making any network requests.
    Returns URLAnalysisResult with risk score and defensive findings.
    """
    findings: List[Finding] = []
    risk_score = 0.0
    
    url_clean = (url_str or "").strip()
    if not url_clean:
        return URLAnalysisResult(
            url="",
            scheme="",
            hostname="",
            path="",
            url_length=0,
            hostname_length=0,
            subdomain_count=0,
            is_ip_address=False,
            is_https=False,
            suspicious_keywords_found=[],
            is_shortened_pattern=False,
            risk_score=0.0,
            findings=[]
        )

    # Normalize url if scheme missing
    parse_target = url_clean
    if not parse_target.startswith(("http://", "https://", "ftp://")):
        parse_target = "http://" + parse_target
        
    try:
        parsed = urlparse(parse_target)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        scheme = "unknown"
        hostname = url_clean
        path = ""
        query = ""

    url_length = len(url_clean)
    hostname_length = len(hostname)
    
    # 1. Raw IP Address Check (e.g., http://198.51.100.10/verify)
    is_ip = bool(IP_PATTERN.match(hostname))
    if is_ip:
        risk_score += 35.0
        findings.append(Finding(
            indicator_type="URL",
            description=f"Raw IP address used as hostname ('{hostname}'). Legitimate organizations rarely use bare IPs.",
            severity="CRITICAL",
            weight=35.0
        ))

    # 2. Scheme & HTTPS Context
    is_https = (scheme == "https")
    if not is_https and not is_ip:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="URL",
            description="Non-HTTPS connection scheme (plain HTTP). Sensitive data is transmitted in cleartext.",
            severity="MEDIUM",
            weight=15.0
        ))
    elif is_https:
        findings.append(Finding(
            indicator_type="URL",
            description="HTTPS detected. NOTE: HTTPS guarantees transport encryption, NOT legitimacy or trustworthiness.",
            severity="INFO",
            weight=0.0
        ))

    # 3. Subdomain Depth
    subdomain_parts = hostname.split(".")
    subdomain_count = max(0, len(subdomain_parts) - 2)
    if subdomain_count >= 3 and not is_ip:
        risk_score += 20.0
        findings.append(Finding(
            indicator_type="URL",
            description=f"Excessive subdomains ({subdomain_count}) detected in hostname '{hostname}'.",
            severity="HIGH",
            weight=20.0
        ))

    # 4. URL Shortener Service Check
    is_shortener = hostname in URL_SHORTENERS
    if is_shortener:
        risk_score += 20.0
        findings.append(Finding(
            indicator_type="URL",
            description=f"URL shortening service '{hostname}' obscures the true destination endpoint.",
            severity="HIGH",
            weight=20.0
        ))

    # 5. Suspicious TLD Check
    tld = subdomain_parts[-1] if len(subdomain_parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="URL",
            description=f"Uncommon/High-risk Top-Level Domain (.{tld}) with high historical abuse rates.",
            severity="MEDIUM",
            weight=15.0
        ))

    # 6. High-Risk Keywords in Path/Query
    keywords_found = []
    combined_target = f"{path}?{query}"
    for kw in HIGH_RISK_URL_KEYWORDS:
        if kw in combined_target:
            keywords_found.append(kw)
            
    if keywords_found:
        risk_score += min(25.0, len(keywords_found) * 10.0)
        findings.append(Finding(
            indicator_type="URL",
            description=f"High-risk authentication/security keywords found in URL path: {', '.join(keywords_found)}.",
            severity="HIGH",
            weight=min(25.0, len(keywords_found) * 10.0)
        ))

    # 7. Abnormal Length
    if url_length > 100:
        risk_score += 10.0
        findings.append(Finding(
            indicator_type="URL",
            description=f"Unusually long URL structure ({url_length} characters), potentially concealing payloads or tracking.",
            severity="LOW",
            weight=10.0
        ))

    capped_score = min(100.0, max(0.0, risk_score))
    
    return URLAnalysisResult(
        url=url_clean,
        scheme=scheme,
        hostname=hostname,
        path=path,
        url_length=url_length,
        hostname_length=hostname_length,
        subdomain_count=subdomain_count,
        is_ip_address=is_ip,
        is_https=is_https,
        suspicious_keywords_found=keywords_found,
        is_shortened_pattern=is_shortener,
        risk_score=capped_score,
        findings=findings
    )
