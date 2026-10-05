"""
FILE NAME: schemas.py
FILE PATH: backend/models/schemas.py
PURPOSE: Pydantic schemas for request validation, structured responses, and API contracts.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# Authentication Models
class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, description="Analyst username")
    password: str = Field(..., min_length=6, description="Account password")
    role: Optional[str] = Field("SOC Analyst", description="User role, e.g. SOC Analyst or Security Engineer")

class UserLoginRequest(BaseModel):
    username: str = Field(..., description="Analyst username")
    password: str = Field(..., description="Account password")

class UserAuthResponse(BaseModel):
    message: str
    token: str
    user_id: int
    username: str
    role: str

# Single Indicator Finding
class Finding(BaseModel):
    indicator_type: str = Field(..., description="Category of the indicator (e.g. SENDER, CONTENT, URL, ATTACHMENT)")
    description: str = Field(..., description="Human-readable explanation of why this was flagged")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    weight: float = Field(0.0, description="Risk weight contributed to overall score")

# URL Analysis Detail
class URLAnalysisResult(BaseModel):
    url: str
    scheme: str
    hostname: str
    path: str
    url_length: int
    hostname_length: int
    subdomain_count: int
    is_ip_address: bool
    is_https: bool
    suspicious_keywords_found: List[str]
    is_shortened_pattern: bool
    risk_score: float
    findings: List[Finding]

# Attachment Analysis Detail
class AttachmentAnalysisResult(BaseModel):
    filename: str
    extension: str
    is_suspicious: bool
    is_executable_or_script: bool
    is_double_extension: bool
    risk_score: float
    findings: List[Finding]

# Sender Analysis Detail
class SenderAnalysisResult(BaseModel):
    sender: str
    domain: str
    display_name: Optional[str] = None
    domain_length: int
    subdomain_count: int
    has_lookalike_patterns: bool
    has_mismatched_display_name: bool
    is_suspicious_domain: bool
    risk_score: float
    findings: List[Finding]

# Content Analysis Detail
class ContentAnalysisResult(BaseModel):
    urgency_detected: bool
    fear_threat_detected: bool
    financial_pressure_detected: bool
    credential_request_detected: bool
    reward_prize_detected: bool
    personal_info_detected: bool
    generic_greeting_detected: bool
    high_caps_ratio_detected: bool
    excessive_exclamation_detected: bool
    risk_score: float
    findings: List[Finding]

# Email Analysis Input Request
class EmailAnalyzeRequest(BaseModel):
    sender: str = Field(..., description="Sender email address, e.g. support@example.com")
    display_name: Optional[str] = Field(None, description="Optional sender display name, e.g. 'IT Support'")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Email body content text")
    urls: Optional[str] = Field("", description="Optional space or comma separated URLs extracted or provided")
    attachment_name: Optional[str] = Field("", description="Optional filename of email attachment")

# Single URL Analyze Request
class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL string to analyze statically")

# Comprehensive Email Analysis Response
class EmailAnalyzeResponse(BaseModel):
    analysis_id: str
    sender_domain: str
    subject: str
    risk_score: float
    rule_score: float
    ml_score: Optional[float] = None
    classification: str
    explanation: List[str]
    recommendations: List[str]
    sender_analysis: SenderAnalysisResult
    content_analysis: ContentAnalysisResult
    url_analyses: List[URLAnalysisResult]
    attachment_analysis: Optional[AttachmentAnalysisResult] = None
    indicators: List[Finding]
    feature_vector: Optional[Dict[str, Any]] = None
    created_at: str

# Dashboard Analytics Statistics
class DashboardStats(BaseModel):
    total_emails_analyzed: int
    likely_phishing_count: int
    suspicious_count: int
    low_risk_count: int
    safe_count: int
    average_risk_score: float
    top_indicators: List[Dict[str, Any]]
    recent_trend: List[Dict[str, Any]]
    classification_distribution: Dict[str, int]
