"""
FILE NAME: config.py
FILE PATH: backend/config.py
PURPOSE: Central configuration settings for the Phishing Detection application.
"""

import os
from pydantic import BaseModel

class AppSettings(BaseModel):
    APP_NAME: str = "Phishing Email Detection & Awareness Dashboard"
    VERSION: str = "1.0.0"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1")
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "phishing_detection.db")
    DATASET_PATH: str = os.getenv("DATASET_PATH", "data/phishing_email_dataset.csv")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/phishing_model.joblib")
    ENABLE_ML: bool = os.getenv("ENABLE_ML", "True").lower() in ("true", "1")
    
    # Risk Score Classification Thresholds (Calibrated Assumptions)
    THRESHOLD_LOW: int = 20
    THRESHOLD_MODERATE: int = 40
    THRESHOLD_SUSPICIOUS: int = 70
    
    # Static Rule Weight Contributions
    WEIGHT_CREDENTIAL_REQUEST: int = 25
    WEIGHT_SUSPICIOUS_ATTACHMENT: int = 25
    WEIGHT_SUSPICIOUS_URL: int = 20
    WEIGHT_RAW_IP_URL: int = 20
    WEIGHT_SUSPICIOUS_SENDER: int = 15
    WEIGHT_URGENCY_FEAR: int = 15
    WEIGHT_FINANCIAL_PRESSURE: int = 15
    WEIGHT_GENERIC_GREETING: int = 5
    WEIGHT_EXCESSIVE_CAPS: int = 5

settings = AppSettings()
