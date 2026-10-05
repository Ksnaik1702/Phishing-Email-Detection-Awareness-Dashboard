"""
FILE NAME: content_analyzer.py
FILE PATH: backend/services/content_analyzer.py
PURPOSE: Natural Language & Heuristic Content Analyzer for psychological manipulation,
         urgency, fear, financial cues, credential harvesting requests, and generic greetings.
"""

import re
from typing import List
from backend.models.schemas import ContentAnalysisResult, Finding
from backend.services.preprocessor import EmailPreprocessor

# Regex Patterns for Social Engineering Indicators
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\baction required\b",
    r"\bwithin 24 hours\b", r"\bwithin 48 hours\b", r"\basap\b", r"\bdeadline\b",
    r"\bfinal notice\b", r"\blast warning\b", r"\btime sensitive\b", r"\bprompt attention\b"
]

FEAR_PATTERNS = [
    r"\baccount suspended\b", r"\baccount suspension\b", r"\bpermanently terminated\b",
    r"\blegal action\b", r"\blawsuit\b", r"\bcollections escalation\b", r"\bunauthorized access\b",
    r"\bsecurity compromise\b", r"\baccount locked\b", r"\brestricted access\b", r"\bdeactivation\b"
]

FINANCIAL_PATTERNS = [
    r"\boutstanding invoice\b", r"\bpayment due\b", r"\bwire transfer\b", r"\bholding fee\b",
    r"\bpenalties\b", r"\boverdue payment\b", r"\bsettlement\b", r"\bdirect deposit\b",
    r"\bbank instructions\b", r"\bbilling department\b", r"\bprocess payment\b"
]

CREDENTIAL_PATTERNS = [
    r"\bverify your password\b", r"\benter your password\b", r"\bconfirm your login\b",
    r"\bupdate your credentials\b", r"\brenew session\b", r"\bkeep current password\b",
    r"\bsubmit your login\b", r"\botp\b", r"\bsecurity pin\b", r"\blogin credentials\b",
    r"\bverify credentials\b", r"\bpassword expiration\b"
]

REWARD_PATTERNS = [
    r"\byou have won\b", r"\bwon \$[\d,]+\b", r"\bgrand winner\b", r"\blottery draw\b",
    r"\bcash prize\b", r"\bclaim your reward\b", r"\bcongratulations winner\b", r"\bfree gift\b"
]

PERSONAL_INFO_PATTERNS = [
    r"\bsocial security\b", r"\bssn\b", r"\bdate of birth\b", r"\bcard details\b",
    r"\bcredit card\b", r"\bcvv\b", r"\bpersonal details\b", r"\bbank account number\b"
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b", r"\bdear user\b", r"\bdear client\b", r"\bvalued customer\b",
    r"\bdear account holder\b", r"\bdear winner\b", r"\battention accounts payable\b",
    r"\bhello team\b", r"\bdear student\b"
]

def analyze_email_content(subject: str, body: str) -> ContentAnalysisResult:
    """
    Analyzes email subject and body for psychological manipulation and phishing cues.
    Returns structured ContentAnalysisResult with category flags and findings.
    """
    findings: List[Finding] = []
    risk_score = 0.0
    
    full_text = f"{subject or ''}\n{body or ''}"
    text_lower = full_text.lower()
    
    # Check Urgency
    urgency_detected = any(re.search(p, text_lower) for p in URGENCY_PATTERNS)
    if urgency_detected:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Urgency cues detected (e.g. 'immediately', 'act now', 'action required').",
            severity="HIGH",
            weight=15.0
        ))
        
    # Check Fear / Threats
    fear_detected = any(re.search(p, text_lower) for p in FEAR_PATTERNS)
    if fear_detected:
        risk_score += 20.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Fear/Threat language detected (e.g. 'account suspended', 'legal action', 'permanently terminated').",
            severity="HIGH",
            weight=20.0
        ))
        
    # Check Financial Pressure
    financial_detected = any(re.search(p, text_lower) for p in FINANCIAL_PATTERNS)
    if financial_detected:
        risk_score += 15.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Financial pressure/urgency detected (e.g. 'wire transfer', 'overdue invoice', 'holding fee').",
            severity="MEDIUM",
            weight=15.0
        ))
        
    # Check Credential Harvesting Requests
    credential_detected = any(re.search(p, text_lower) for p in CREDENTIAL_PATTERNS)
    if credential_detected:
        risk_score += 25.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Credential request detected (e.g. 'verify password', 'renew session', 'confirm login').",
            severity="CRITICAL",
            weight=25.0
        ))
        
    # Check Rewards / Lottery Claims
    reward_detected = any(re.search(p, text_lower) for p in REWARD_PATTERNS)
    if reward_detected:
        risk_score += 25.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Lure reward/lottery claim detected (e.g. 'you have won', 'cash prize').",
            severity="CRITICAL",
            weight=25.0
        ))
        
    # Check Personal Information Requests
    personal_info_detected = any(re.search(p, text_lower) for p in PERSONAL_INFO_PATTERNS)
    if personal_info_detected:
        risk_score += 20.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Personal sensitive information request detected (e.g. 'social security', 'card details', 'cvv').",
            severity="CRITICAL",
            weight=20.0
        ))
        
    # Check Generic Greetings (Non-personalized)
    generic_greeting_detected = any(re.search(p, text_lower) for p in GENERIC_GREETING_PATTERNS)
    if generic_greeting_detected:
        risk_score += 5.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description="Impersonal or generic greeting detected (e.g. 'Dear Customer', 'Dear User').",
            severity="LOW",
            weight=5.0
        ))
        
    # Check Casing & Exclamation metrics
    metrics = EmailPreprocessor.compute_text_metrics(full_text)
    high_caps = metrics["uppercase_ratio"] > 0.25 and metrics["length"] > 30
    excessive_exclamation = metrics["exclamation_count"] >= 3
    
    if high_caps:
        risk_score += 10.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description=f"High uppercase character ratio ({int(metrics['uppercase_ratio']*100)}%), indicating artificial pressure.",
            severity="MEDIUM",
            weight=10.0
        ))
        
    if excessive_exclamation:
        risk_score += 5.0
        findings.append(Finding(
            indicator_type="CONTENT",
            description=f"Multiple exclamation marks detected ({metrics['exclamation_count']} instances), common in lure messages.",
            severity="LOW",
            weight=5.0
        ))
        
    capped_score = min(100.0, max(0.0, risk_score))
    
    return ContentAnalysisResult(
        urgency_detected=urgency_detected,
        fear_threat_detected=fear_detected,
        financial_pressure_detected=financial_detected,
        credential_request_detected=credential_detected,
        reward_prize_detected=reward_detected,
        personal_info_detected=personal_info_detected,
        generic_greeting_detected=generic_greeting_detected,
        high_caps_ratio_detected=high_caps,
        excessive_exclamation_detected=excessive_exclamation,
        risk_score=capped_score,
        findings=findings
    )
