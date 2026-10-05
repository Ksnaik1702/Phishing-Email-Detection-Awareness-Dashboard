"""
FILE NAME: app.py
FILE PATH: backend/app.py
PURPOSE: Main FastAPI REST API server and static frontend host.
         Provides security analysis endpoints, telemetry aggregation,
         educational awareness content, user authentication, and safe simulation data.
"""

import json
import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.config import settings
from backend.database import init_db, get_db
from backend.models.schemas import (
    EmailAnalyzeRequest,
    EmailAnalyzeResponse,
    URLAnalyzeRequest,
    URLAnalysisResult,
    DashboardStats,
    UserRegisterRequest,
    UserLoginRequest,
    UserAuthResponse
)
from backend.services.hybrid_engine import run_hybrid_analysis
from backend.services.url_analyzer import analyze_url
from backend.utils.helpers import sanitize_text
from backend.utils.auth import (
    hash_password,
    verify_password,
    create_session,
    get_session_user,
    delete_session
)

# Initialize application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Defensive Cybersecurity Phishing Detection & Awareness System."
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    """Initializes SQLite tables on server startup."""
    init_db()
    # Create default demo analyst user if none exists
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("analyst", hash_password("analyst123"), "Senior SOC Analyst")
            )
            conn.commit()
    print("[+] Database tables initialized & demo analyst created.")

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================

@app.post("/api/auth/register", response_model=UserAuthResponse, tags=["Authentication"])
def register_user(request: UserRegisterRequest):
    """Registers a new cybersecurity analyst or investigator."""
    clean_username = request.username.strip()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (clean_username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already registered.")
            
        pwd_hash = hash_password(request.password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (clean_username, pwd_hash, request.role or "SOC Analyst")
        )
        conn.commit()
        user_id = cursor.lastrowid
        
    token = create_session(user_id, clean_username, request.role or "SOC Analyst")
    return UserAuthResponse(
        message="Registration successful.",
        token=token,
        user_id=user_id,
        username=clean_username,
        role=request.role or "SOC Analyst"
    )

@app.post("/api/auth/login", response_model=UserAuthResponse, tags=["Authentication"])
def login_user(request: UserLoginRequest):
    """Authenticates an analyst and generates a session token."""
    clean_username = request.username.strip()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, password_hash, role FROM users WHERE username = ?", (clean_username,))
        user = cursor.fetchone()
        
    if not user or not verify_password(user["password_hash"], request.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
        
    token = create_session(user["user_id"], user["username"], user["role"])
    return UserAuthResponse(
        message="Login successful.",
        token=token,
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"]
    )

@app.post("/api/auth/logout", tags=["Authentication"])
def logout_user(authorization: Optional[str] = Header(None)):
    """Terminates the active analyst session."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        delete_session(token)
    return {"message": "Logged out successfully."}

@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user(authorization: Optional[str] = Header(None)):
    """Validates session token and returns active analyst profile."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"authenticated": False, "user": None}
        
    token = authorization.split(" ")[1]
    user = get_session_user(token)
    if not user:
        return {"authenticated": False, "user": None}
        
    return {"authenticated": True, "user": user}

# ==========================================
# ANALYSIS REST API ENDPOINTS
# ==========================================

@app.get("/api/health", tags=["System"])
def health_check():
    """Returns application health and configuration status."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "ml_enabled": settings.ENABLE_ML,
        "model_file_exists": os.path.exists(settings.MODEL_PATH)
    }

@app.post("/api/analyze", response_model=EmailAnalyzeResponse, tags=["Analysis"])
def analyze_email(request: EmailAnalyzeRequest):
    """
    Main ingestion endpoint: Performs sender, content, URL, attachment, and ML analysis.
    Stores safe audit metadata in SQLite database.
    """
    if not request.subject.strip() and not request.body.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Subject and body cannot both be empty."
        )
    return run_hybrid_analysis(request)

@app.post("/api/analyze/url", response_model=URLAnalysisResult, tags=["Analysis"])
def analyze_single_url(request: URLAnalyzeRequest):
    """
    Dedicated static URL string analyzer.
    Safe inspection: Never resolves DNS or establishes network connections.
    """
    if not request.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty."
        )
    return analyze_url(request.url)

@app.get("/api/analyses", tags=["History"])
def get_analysis_history(
    limit: int = Query(50, ge=1, le=200),
    classification: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    """Retrieves safe historical analysis records with optional filtering."""
    query = "SELECT * FROM analyses WHERE 1=1"
    params = []
    
    if classification:
        query += " AND classification = ?"
        params.append(classification)
        
    if search:
        query += " AND (subject LIKE ? OR sender_domain LIKE ? OR sender LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])
        
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        results = []
        for r in rows:
            results.append({
                "analysis_id": r["analysis_id"],
                "sender": r["sender"],
                "sender_domain": r["sender_domain"],
                "subject": r["subject"],
                "risk_score": r["risk_score"],
                "rule_score": r["rule_score"],
                "ml_score": r["ml_score"],
                "classification": r["classification"],
                "has_attachment": bool(r["has_attachment"]),
                "attachment_name": r["attachment_name"],
                "url_count": r["url_count"],
                "explanation": json.loads(r["explanation"]) if r["explanation"] else [],
                "recommendations": json.loads(r["recommendations"]) if r["recommendations"] else [],
                "created_at": r["created_at"]
            })
            
    return results

@app.get("/api/analyses/{analysis_id}", tags=["History"])
def get_analysis_detail(analysis_id: str):
    """Fetches complete breakdown and indicator details for a specific analysis record."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Analysis record not found.")
            
        cursor.execute("SELECT * FROM indicators WHERE analysis_id = ?", (analysis_id,))
        indicator_rows = cursor.fetchall()
        
        cursor.execute("SELECT * FROM url_analyses WHERE analysis_id = ?", (analysis_id,))
        url_rows = cursor.fetchall()
        
        return {
            "analysis_id": row["analysis_id"],
            "sender": row["sender"],
            "sender_domain": row["sender_domain"],
            "subject": row["subject"],
            "risk_score": row["risk_score"],
            "rule_score": row["rule_score"],
            "ml_score": row["ml_score"],
            "classification": row["classification"],
            "has_attachment": bool(row["has_attachment"]),
            "attachment_name": row["attachment_name"],
            "url_count": row["url_count"],
            "explanation": json.loads(row["explanation"]) if row["explanation"] else [],
            "recommendations": json.loads(row["recommendations"]) if row["recommendations"] else [],
            "indicators": [
                {
                    "indicator_type": ir["indicator_type"],
                    "description": ir["description"],
                    "severity": ir["severity"],
                    "weight": ir["weight"]
                } for ir in indicator_rows
            ],
            "url_analyses": [
                {
                    "url": ur["url_safe_representation"],
                    "risk_score": ur["risk_score"],
                    "findings": json.loads(ur["findings"]) if ur["findings"] else []
                } for ur in url_rows
            ],
            "created_at": row["created_at"]
        }

@app.delete("/api/analyses/{analysis_id}", tags=["History"])
def delete_analysis(analysis_id: str):
    """Deletes an analysis record and associated indicators from SQLite."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Analysis record not found.")
        conn.commit()
    return {"message": f"Analysis {analysis_id} successfully removed."}

@app.get("/api/dashboard/stats", tags=["Dashboard"])
def get_dashboard_stats():
    """Aggregates security metrics, KPI cards, classification counts, and 7-day trend."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Overall Counts
        cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM analyses")
        total_row = cursor.fetchone()
        total_count = total_row[0] or 0
        avg_score = round(total_row[1] or 0.0, 1)
        
        # Distribution by Classification
        cursor.execute("SELECT classification, COUNT(*) FROM analyses GROUP BY classification")
        class_rows = cursor.fetchall()
        class_dist = {
            "SAFE": 0,
            "LOW RISK": 0,
            "SUSPICIOUS": 0,
            "HIGH RISK / LIKELY PHISHING": 0
        }
        for cr in class_rows:
            if cr[0] in class_dist:
                class_dist[cr[0]] = cr[1]
                
        # Top Indicator Types
        cursor.execute("""
        SELECT indicator_type, COUNT(*) as cnt
        FROM indicators
        GROUP BY indicator_type
        ORDER BY cnt DESC
        LIMIT 5
        """)
        top_ind_rows = cursor.fetchall()
        top_indicators = [{"type": ir[0], "count": ir[1]} for ir in top_ind_rows]
        
        # 7-Day Trend
        cursor.execute("""
        SELECT date(created_at) as day, COUNT(*) as total,
               SUM(CASE WHEN classification = 'HIGH RISK / LIKELY PHISHING' THEN 1 ELSE 0 END) as phish_count
        FROM analyses
        GROUP BY date(created_at)
        ORDER BY day DESC
        LIMIT 7
        """)
        trend_rows = cursor.fetchall()
        trend = [
            {"date": tr[0], "total": tr[1], "phishing": tr[2] or 0}
            for tr in reversed(trend_rows)
        ]
        
        return {
            "total_emails_analyzed": total_count,
            "likely_phishing_count": class_dist["HIGH RISK / LIKELY PHISHING"],
            "suspicious_count": class_dist["SUSPICIOUS"],
            "low_risk_count": class_dist["LOW RISK"],
            "safe_count": class_dist["SAFE"],
            "average_risk_score": avg_score,
            "top_indicators": top_indicators,
            "recent_trend": trend,
            "classification_distribution": class_dist
        }

@app.get("/api/awareness/lessons", tags=["Awareness"])
def get_awareness_lessons():
    """Returns curated micro-lessons and the 'Before You Click' checklist."""
    return {
        "checklist": [
            "1. Verify Sender Domain: Inspect the domain after the @ symbol for subtle typosquatting.",
            "2. Scrutinize Urgent Language: Real organizations rarely demand immediate password resets in 15 minutes.",
            "3. Inspect Links Statically: Hover over URLs to verify destination domains before clicking.",
            "4. Never Share Passwords or MFA: Legitimate IT personnel never ask for your private password or OTP.",
            "5. Verify Unexpected Invoices: Confirm billing changes via official phone numbers or internal directories.",
            "6. Beware of Double Extensions: Files like 'invoice.pdf.exe' are executable malware masquerading as documents."
        ],
        "micro_lessons": [
            {
                "id": "lesson_1",
                "title": "Hover-to-Verify & URL Anatomy",
                "duration": "2 min read",
                "content": "Attackers disguise hyperlinks using benign display text. Always inspect the hostname. Remember that HTTPS only encrypts the traffic—it does not prove the website is honest or safe!"
            },
            {
                "id": "lesson_2",
                "title": "Lookalike Domains & Typosquatting",
                "duration": "2 min read",
                "content": "Adversaries register domains with swapped characters (e.g., 'micr0soft.com' or 'paypa1.com') to trick inattentive users. Double-check all characters before trusting sender addresses."
            },
            {
                "id": "lesson_3",
                "title": "Psychological Manipulation & Pressure",
                "duration": "3 min read",
                "content": "Phishing relies heavily on fear (account suspension), greed (lottery prizes), or urgency (immediate wire transfer) to bypass rational skepticism. Pause when an email induces stress."
            },
            {
                "id": "lesson_4",
                "title": "Executive Impersonation (CEO Fraud / BEC)",
                "duration": "3 min read",
                "content": "Business Email Compromise often features a spoofed executive asking for urgent gift cards or confidential wire transfers. Always verify through standard internal channels."
            },
            {
                "id": "lesson_5",
                "title": "Attachment Danger & Double Extensions",
                "duration": "2 min read",
                "content": "Never open unexpected .exe, .scr, .vbs, or double-extended files like .pdf.exe. Treat macro-enabled office files (.docm, .xlsm) with extreme caution."
            },
            {
                "id": "lesson_6",
                "title": "Out-of-Band Verification Protocol",
                "duration": "2 min read",
                "content": "When in doubt, contact the alleged sender using contact info from the company's official public website or corporate intranet—never use the phone number or link inside the suspicious email."
            }
        ]
    }

@app.get("/api/simulation/templates", tags=["Awareness"])
def get_simulation_templates():
    """Provides safe, educational simulation templates with prefilled safe examples."""
    return [
        {
            "id": "sim_urgent_suspension",
            "name": "Synthetic Bank Suspension Lure",
            "type": "Phishing Lure",
            "sender": "security-alert@account-check.invalid.test",
            "display_name": "Account Security Team",
            "subject": "URGENT: Immediate Account Suspension Notice - Action Required",
            "body": "Dear Customer,\n\nYour account has been flagged for immediate suspension due to suspicious login attempts. You must verify your password and personal credentials within 24 hours or your access will be permanently terminated.\n\nClick below immediately to restore your account.",
            "urls": "http://198.51.100.10/verify-account-portal/login.php",
            "attachment_name": ""
        },
        {
            "id": "sim_fake_invoice",
            "name": "Synthetic Overdue Invoice Lure",
            "type": "Phishing Lure",
            "sender": "billing-dept@invoice-settlement.invalid.test",
            "display_name": "Accounts Payable",
            "subject": "Overdue Invoice #INV-990184 - Final Notice Before Legal Action",
            "body": "Attention Accounts Payable,\n\nPlease find attached the outstanding invoice payment. Failure to settle this invoice immediately will result in financial penalties and collections escalation. Open the attached invoice to verify details.",
            "urls": "http://invoice-settlement.invalid.test/download/invoice_doc?id=990184",
            "attachment_name": "overdue_invoice_march.pdf.exe"
        },
        {
            "id": "sim_legit_university",
            "name": "Legitimate University Course Notice",
            "type": "Legitimate Email",
            "sender": "registrar@university.example.edu",
            "display_name": "University Registrar",
            "subject": "Semester Course Registration Window Open",
            "body": "Dear Student,\n\nThe course registration window for the upcoming spring semester is now open. Please review your degree audit and select your courses through the standard campus portal.\n\nAcademic Advising Office",
            "urls": "https://university.example.edu/portal/courses",
            "attachment_name": "course_catalog.pdf"
        },
        {
            "id": "sim_legit_hr",
            "name": "Legitimate HR Benefits Information",
            "type": "Legitimate Email",
            "sender": "hr-benefits@corp.example.com",
            "display_name": "Corporate HR",
            "subject": "Annual Open Enrollment Benefits Information",
            "body": "Hello Team,\n\nOur open enrollment period begins next Monday. Please review the attached summary of medical, dental, and retirement plan options for the next fiscal year.\n\nBest regards,\nHuman Resources Department",
            "urls": "https://corp.example.com/intranet/benefits",
            "attachment_name": "benefits_summary_2026.pdf"
        }
    ]

# Serve Frontend static assets
if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serves the frontend single page dashboard."""
    if os.path.exists("frontend/index.html"):
        return FileResponse("frontend/index.html")
    return {"message": "Phishing Email Detection & Awareness API is running. Visit /docs for API documentation."}
