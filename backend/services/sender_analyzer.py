"""
FILE NAME: sender_analyzer.py
FILE PATH: backend/services/sender_analyzer.py
PURPOSE: Performs deep defensive analysis on the sender's email address, domain structure,
         lookalike/typosquatting cues, and display-name to domain alignment.
"""

import re
from typing import Optional, List
from backend.models.schemas import SenderAnalysisResult, Finding
from backend.services.preprocessor import EmailPreprocessor

# Well-known brands frequently targeted in lookalike domain attacks
LOOKALIKE_PATTERNS = [
    (r"paypa[l1i]", "PayPal"),
    (r"micr0soft|micros0ft|m1crosoft", "Microsoft"),
    (r"amaz0n|arnazon", "Amazon"),
    (r"app[l1]e-id|app1e", "Apple"),
    (r"g00gle|go0gle", "Google"),
    (r"netf[l1]ix", "Netflix"),
    (r"chase-sec|chase-auth", "Chase Bank"),
    (r"wellsfarg0", "Wells Fargo"),
    (r"1ogin|l0gin", "Login/Auth Portal"),
    (r"supp0rt|cust0mer", "Customer Support")
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "verify", "secure", "update", "portal", "auth", "login",
    "account", "billing", "settlement", "service-alert", "security-check"
]

def analyze_sender(sender: str, display_name: Optional[str] = None) -> SenderAnalysisResult:
    """
    Analyzes sender characteristics for phishing and spoofing indicators.
    Returns structured SenderAnalysisResult with risk score and findings.
    """
    findings: List[Finding] = []
    risk_score = 0.0
    
    sender_clean = (sender or "").strip()
    domain = EmailPreprocessor.extract_domain(sender_clean)
    
    if not sender_clean:
        findings.append(Finding(
            indicator_type="SENDER",
            description="Sender email is missing or empty.",
            severity="MEDIUM",
            weight=15.0
        ))
        return SenderAnalysisResult(
            sender="",
            domain="",
            display_name=display_name,
            domain_length=0,
            subdomain_count=0,
            has_lookalike_patterns=False,
            has_mismatched_display_name=False,
            is_suspicious_domain=True,
            risk_score=15.0,
            findings=findings
        )

    # 1. Domain length and subdomain depth
    subdomains = domain.split(".")
    subdomain_count = max(0, len(subdomains) - 2)
    domain_length = len(domain)
    
    if subdomain_count >= 3:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="SENDER",
            description=f"Sender domain has excessive subdomains ({subdomain_count}), often used to disguise actual origins.",
            severity="HIGH",
            weight=15.0
        ))
    elif subdomain_count == 2:
        risk_score += 5.0
        findings.append(Finding(
            indicator_type="SENDER",
            description=f"Sender domain contains multiple subdomains ({subdomain_count}).",
            severity="LOW",
            weight=5.0
        ))
        
    if domain_length > 30:
        risk_score += 10.0
        findings.append(Finding(
            indicator_type="SENDER",
            description=f"Unusually long domain name ({domain_length} characters).",
            severity="MEDIUM",
            weight=10.0
        ))

    # 2. Lookalike / Typosquatting Analysis
    has_lookalike = False
    domain_lower = domain.lower()
    for pattern, brand in LOOKALIKE_PATTERNS:
        if re.search(pattern, domain_lower):
            has_lookalike = True
            risk_score += 25.0
            findings.append(Finding(
                indicator_type="SENDER",
                description=f"Domain exhibits lookalike/typosquatting pattern mimicking '{brand}'.",
                severity="CRITICAL",
                weight=25.0
            ))
            break

    # 3. Suspicious Keywords in Domain
    is_suspicious_domain = False
    for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
        if kw in domain_lower and not domain_lower.endswith(".edu") and not domain_lower.endswith(".gov"):
            is_suspicious_domain = True
            risk_score += 10.0
            findings.append(Finding(
                indicator_type="SENDER",
                description=f"Domain name contains high-risk keyword '{kw}' commonly used in lure infrastructure.",
                severity="MEDIUM",
                weight=10.0
            ))
            break

    # 4. Display Name vs Domain Alignment Check
    has_mismatched_display = False
    if display_name and display_name.strip():
        dn_lower = display_name.strip().lower()
        # Common organization names in display name
        common_orgs = ["microsoft", "google", "apple", "paypal", "amazon", "it support", "help desk", "payroll"]
        for org in common_orgs:
            if org in dn_lower and org not in domain_lower:
                has_mismatched_display = True
                risk_score += 20.0
                findings.append(Finding(
                    indicator_type="SENDER",
                    description=f"Display name claims to be '{display_name}', but domain '{domain}' does not match.",
                    severity="HIGH",
                    weight=20.0
                ))
                break

    # Cap risk score between 0 and 100
    capped_score = min(100.0, max(0.0, risk_score))
    
    return SenderAnalysisResult(
        sender=sender_clean,
        domain=domain,
        display_name=display_name,
        domain_length=domain_length,
        subdomain_count=subdomain_count,
        has_lookalike_patterns=has_lookalike,
        has_mismatched_display_name=has_mismatched_display,
        is_suspicious_domain=is_suspicious_domain,
        risk_score=capped_score,
        findings=findings
    )
