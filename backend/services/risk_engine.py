"""
FILE NAME: risk_engine.py
FILE PATH: backend/services/risk_engine.py
PURPOSE: Rule-based phishing risk scoring engine.
         Aggregates weighted indicator findings into an interpretable score (0-100)
         and maps to calibrated risk classifications with explainable security advice.
"""

from typing import List, Tuple, Dict, Any
from backend.config import settings
from backend.models.schemas import (
    SenderAnalysisResult,
    ContentAnalysisResult,
    URLAnalysisResult,
    AttachmentAnalysisResult,
    Finding
)

def calculate_phishing_score(
    sender_res: SenderAnalysisResult,
    content_res: ContentAnalysisResult,
    url_results: List[URLAnalysisResult],
    attachment_res: AttachmentAnalysisResult = None
) -> Tuple[float, str, List[Finding], List[str], List[str]]:
    """
    Computes calibrated phishing risk score, classification, consolidated indicators,
    explainability bullets, and actionable recommendations.
    
    Returns:
    (risk_score, classification, all_indicators, explanations, recommendations)
    """
    all_indicators: List[Finding] = []
    raw_score = 0.0
    
    # 1. Collect Sender Findings
    all_indicators.extend(sender_res.findings)
    raw_score += sender_res.risk_score * 0.35
    
    # 2. Collect Content Findings
    all_indicators.extend(content_res.findings)
    raw_score += content_res.risk_score * 0.40
    
    # 3. Collect URL Findings
    if url_results:
        max_url_risk = max((u.risk_score for u in url_results), default=0.0)
        avg_url_risk = sum(u.risk_score for u in url_results) / len(url_results)
        combined_url_risk = (max_url_risk * 0.7) + (avg_url_risk * 0.3)
        raw_score += combined_url_risk * 0.45
        for u in url_results:
            all_indicators.extend(u.findings)
            
    # 4. Collect Attachment Findings
    if attachment_res:
        all_indicators.extend(attachment_res.findings)
        raw_score += attachment_res.risk_score * 0.45
        
    # Cap score between 0 and 100
    final_score = round(min(100.0, max(0.0, raw_score)), 1)
    
    # Classification Thresholding
    if final_score <= settings.THRESHOLD_LOW:
        if final_score <= 10.0:
            classification = "SAFE"
        else:
            classification = "LOW RISK"
    elif final_score <= settings.THRESHOLD_MODERATE:
        classification = "LOW RISK"
    elif final_score <= settings.THRESHOLD_SUSPICIOUS:
        classification = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"
        
    # Generate Explainability "WHY?" Bullets
    explanations: List[str] = []
    for ind in all_indicators:
        if ind.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            explanations.append(f"[{ind.severity}] {ind.description}")
            
    if not explanations:
        explanations.append("No high-risk phishing indicators or malicious patterns were identified in this email.")
        
    # Generate Context-Aware Security Recommendations
    recommendations: List[str] = []
    
    if classification in ("HIGH RISK / LIKELY PHISHING", "SUSPICIOUS"):
        recommendations.append("Do NOT click any embedded links or copy-paste them into your browser.")
        if attachment_res and attachment_res.is_suspicious:
            recommendations.append(f"Do NOT download or execute the attachment ('{attachment_res.filename}').")
        if content_res.credential_request_detected:
            recommendations.append("Never submit passwords, MFA tokens, or PINs in response to email requests.")
        if content_res.financial_pressure_detected:
            recommendations.append("Verify all payment or invoice requests out-of-band via phone or official internal directory.")
        recommendations.append("Forward this email to your organization's Security Operations Center (SOC) or Phishing Report mailbox.")
        recommendations.append("Access the service only by typing the official, verified web address directly into your browser.")
    elif classification == "LOW RISK":
        recommendations.append("Email exhibits minor unusual traits but no overt phishing lures. Exercise routine vigilance.")
        recommendations.append("Verify the sender's address if this message asks for unexpected documents or actions.")
    else: # SAFE
        recommendations.append("Standard business/academic communication patterns detected.")
        recommendations.append("Maintain good cybersecurity hygiene and always verify unexpected requests.")
        
    return final_score, classification, all_indicators, explanations, recommendations
