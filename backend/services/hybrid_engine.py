"""
FILE NAME: hybrid_engine.py
FILE PATH: backend/services/hybrid_engine.py
PURPOSE: Hybrid Detection Engine combining rule-based deterministic heuristics with
         machine learning probability inference for explainable, high-precision detection.
"""

import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional

from backend.config import settings
from backend.database import get_db
from backend.models.schemas import (
    EmailAnalyzeRequest,
    EmailAnalyzeResponse,
    SenderAnalysisResult,
    ContentAnalysisResult,
    URLAnalysisResult,
    AttachmentAnalysisResult
)
from backend.services.preprocessor import EmailPreprocessor
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.feature_extractor import extract_email_features
from backend.services.risk_engine import calculate_phishing_score
from ml.predict import predictor

def run_hybrid_analysis(request: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
    """
    Executes complete defensive phishing analysis pipeline on an incoming email.
    """
    analysis_id = f"ANALYSIS-{uuid.uuid4().hex[:8].upper()}"
    
    # 1. Sender Analysis
    sender_res = analyze_sender(request.sender, display_name=request.display_name)
    
    # 2. Content & Social Engineering Analysis
    content_res = analyze_email_content(request.subject, request.body)
    
    # 3. URL Extraction & Static Inspection
    extracted_urls = EmailPreprocessor.extract_urls(f"{request.body} {request.urls or ''}")
    url_results = [analyze_url(u) for u in extracted_urls]
    
    # 4. Attachment Analysis
    attachment_res = analyze_attachment(request.attachment_name)
    
    # 5. Rule-Based Heuristic Scoring
    rule_score, rule_classification, all_indicators, explanations, recommendations = calculate_phishing_score(
        sender_res=sender_res,
        content_res=content_res,
        url_results=url_results,
        attachment_res=attachment_res
    )
    
    # 6. ML Inference (if enabled and loaded)
    ml_score = None
    feature_vector = None
    if settings.ENABLE_ML:
        ml_prob, ml_label, feature_vector = predictor.predict(
            sender=request.sender,
            subject=request.subject,
            body=request.body,
            urls_str=request.urls,
            attachment_name=request.attachment_name,
            display_name=request.display_name
        )
        ml_score = round(ml_prob * 100.0, 1)
        
        # Hybrid Weighted Combination: 55% Heuristics + 45% Machine Learning
        combined_score = round((rule_score * 0.55) + (ml_score * 0.45), 1)
        
        # Determine Hybrid Classification
        if combined_score <= settings.THRESHOLD_LOW:
            final_class = "SAFE" if combined_score <= 10.0 else "LOW RISK"
        elif combined_score <= settings.THRESHOLD_MODERATE:
            final_class = "LOW RISK"
        elif combined_score <= settings.THRESHOLD_SUSPICIOUS:
            final_class = "SUSPICIOUS"
        else:
            final_class = "HIGH RISK / LIKELY PHISHING"
            
        final_risk_score = combined_score
        classification = final_class
    else:
        final_risk_score = rule_score
        classification = rule_classification

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 7. Safe Database Storage (Stores metadata and indicator summaries, not raw body)
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO analyses (
                analysis_id, sender, sender_domain, subject, risk_score, rule_score,
                ml_score, classification, has_attachment, attachment_name, url_count,
                explanation, recommendations, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                request.sender,
                sender_res.domain,
                request.subject,
                final_risk_score,
                rule_score,
                ml_score,
                classification,
                1 if attachment_res else 0,
                request.attachment_name or "",
                len(url_results),
                json.dumps(explanations),
                json.dumps(recommendations),
                created_at
            ))
            
            # Insert Indicator Details
            for ind in all_indicators:
                cursor.execute("""
                INSERT INTO indicators (analysis_id, indicator_type, description, severity, weight)
                VALUES (?, ?, ?, ?, ?)
                """, (analysis_id, ind.indicator_type, ind.description, ind.severity, ind.weight))
                
            # Insert URL Analysis Details
            for ur in url_results:
                cursor.execute("""
                INSERT INTO url_analyses (analysis_id, url_safe_representation, risk_score, findings)
                VALUES (?, ?, ?, ?)
                """, (
                    analysis_id,
                    ur.url,
                    ur.risk_score,
                    json.dumps([f.description for f in ur.findings])
                ))
                
            conn.commit()
    except Exception as e:
        print(f"[-] Database insertion error: {e}")

    return EmailAnalyzeResponse(
        analysis_id=analysis_id,
        sender_domain=sender_res.domain,
        subject=request.subject,
        risk_score=final_risk_score,
        rule_score=rule_score,
        ml_score=ml_score,
        classification=classification,
        explanation=explanations,
        recommendations=recommendations,
        sender_analysis=sender_res,
        content_analysis=content_res,
        url_analyses=url_results,
        attachment_analysis=attachment_res,
        indicators=all_indicators,
        feature_vector=feature_vector,
        created_at=created_at
    )
