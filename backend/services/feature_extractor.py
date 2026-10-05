"""
FILE NAME: feature_extractor.py
FILE PATH: backend/services/feature_extractor.py
PURPOSE: Extracts a structured numerical and categorical feature dictionary from an email.
         Used by both the rule-based heuristic engine and the machine learning pipeline.
"""

from typing import Dict, Any, List
from backend.services.preprocessor import EmailPreprocessor
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment

def extract_email_features(
    sender: str,
    subject: str,
    body: str,
    urls_str: str = "",
    attachment_name: str = "",
    display_name: str = ""
) -> Dict[str, Any]:
    """
    Extracts a comprehensive, explainable feature dictionary from email components.
    
    Feature Descriptions:
    - urgent_keyword_count: Frequency of urgent pressure terms
    - credential_keyword_count: Indicators of login/password requests
    - financial_keyword_count: References to invoices, money transfers, fees
    - threat_keyword_count: Mentions of suspension, termination, legal action
    - url_count: Total distinct URLs identified
    - suspicious_url_count: URLs containing high-risk flags (IP, shortener, bad TLD)
    - has_ip_url: Binary flag (1/0) indicating presence of raw IP links
    - has_shortened_url_pattern: Binary flag (1/0) indicating URL shortener usage
    - sender_domain_length: Character length of the sender's domain
    - subdomain_count: Number of subdomains in the sender address
    - has_lookalike_sender: Binary flag for typosquatting/lookalike patterns
    - suspicious_attachment: Binary flag for executable/double-extension attachments
    - generic_greeting: Binary flag for impersonal greetings ('Dear Customer')
    - contains_password_request: Binary flag for credential verification language
    - contains_personal_info_request: Binary flag for SSN/banking/identity requests
    - exclamation_count: Total exclamation marks across subject and body
    - uppercase_ratio: Proportion of uppercase characters in the text
    - body_length: Total character count of the body text
    - subject_length: Total character count of the subject line
    """
    sender_res = analyze_sender(sender, display_name=display_name)
    content_res = analyze_email_content(subject, body)
    
    # URL extraction & analysis
    extracted_urls = EmailPreprocessor.extract_urls(f"{body} {urls_str}")
    url_results = [analyze_url(u) for u in extracted_urls]
    
    suspicious_url_count = sum(1 for ur in url_results if ur.risk_score >= 20.0)
    has_ip_url = int(any(ur.is_ip_address for ur in url_results))
    has_shortener = int(any(ur.is_shortened_pattern for ur in url_results))
    
    # Attachment analysis
    attach_res = analyze_attachment(attachment_name)
    suspicious_attachment = int(attach_res.is_suspicious) if attach_res else 0
    
    # Text metrics
    metrics = EmailPreprocessor.compute_text_metrics(f"{subject}\n{body}")
    
    features = {
        "urgent_keyword_count": int(content_res.urgency_detected),
        "credential_keyword_count": int(content_res.credential_request_detected),
        "financial_keyword_count": int(content_res.financial_pressure_detected),
        "threat_keyword_count": int(content_res.fear_threat_detected),
        "reward_keyword_count": int(content_res.reward_prize_detected),
        "url_count": len(extracted_urls),
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip_url,
        "has_shortened_url_pattern": has_shortener,
        "sender_domain_length": sender_res.domain_length,
        "subdomain_count": sender_res.subdomain_count,
        "has_lookalike_sender": int(sender_res.has_lookalike_patterns),
        "has_mismatched_display_name": int(sender_res.has_mismatched_display_name),
        "suspicious_attachment": suspicious_attachment,
        "generic_greeting": int(content_res.generic_greeting_detected),
        "contains_password_request": int(content_res.credential_request_detected),
        "contains_personal_info_request": int(content_res.personal_info_detected),
        "exclamation_count": metrics["exclamation_count"],
        "uppercase_ratio": metrics["uppercase_ratio"],
        "body_length": len(body or ""),
        "subject_length": len(subject or "")
    }
    
    return features
