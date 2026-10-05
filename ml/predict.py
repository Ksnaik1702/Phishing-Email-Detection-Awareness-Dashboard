"""
FILE NAME: predict.py
FILE PATH: ml/predict.py
PURPOSE: ML inference module. Loads the trained model bundle and generates
         phishing probability scores (0.0 - 1.0) for arbitrary emails.
"""

import os
import sys
import joblib
import numpy as np
from typing import Tuple, Dict, Any, Optional

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.config import settings
from backend.services.feature_extractor import extract_email_features

class PhishingPredictor:
    _instance = None
    
    def __init__(self, model_path: str = None):
        path = model_path or settings.MODEL_PATH
        self.model_path = path
        self.bundle = None
        self.is_loaded = False
        self.load_model()
        
    def load_model(self):
        """Loads saved joblib model artifact if available."""
        if os.path.exists(self.model_path):
            try:
                self.bundle = joblib.load(self.model_path)
                self.model = self.bundle["model"]
                self.tfidf = self.bundle["tfidf"]
                self.model_name = self.bundle.get("model_name", "ML Model")
                self.is_loaded = True
            except Exception as e:
                print(f"[-] Warning: Failed to load model artifact ({e}).")
                self.is_loaded = False
        else:
            self.is_loaded = False

    def predict(
        self,
        sender: str,
        subject: str,
        body: str,
        urls_str: str = "",
        attachment_name: str = "",
        display_name: str = ""
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Runs inference on an email.
        Returns: (phish_probability, predicted_label, extracted_features)
        """
        feats = extract_email_features(
            sender=sender,
            subject=subject,
            body=body,
            urls_str=urls_str,
            attachment_name=attachment_name,
            display_name=display_name
        )
        
        if not self.is_loaded or self.bundle is None:
            # Fallback if model not trained yet: use heuristic proxy
            heuristic_prob = 0.85 if (feats["has_ip_url"] or feats["credential_keyword_count"]) else 0.15
            return heuristic_prob, int(heuristic_prob >= 0.5), feats
            
        # Transform text
        combined_text = f"{subject or ''} {body or ''}"
        X_text = self.tfidf.transform([combined_text]).toarray()
        
        # Structured vector
        vec = [
            feats["urgent_keyword_count"],
            feats["credential_keyword_count"],
            feats["financial_keyword_count"],
            feats["threat_keyword_count"],
            feats["reward_keyword_count"],
            feats["url_count"],
            feats["suspicious_url_count"],
            feats["has_ip_url"],
            feats["has_shortened_url_pattern"],
            feats["sender_domain_length"],
            feats["subdomain_count"],
            feats["has_lookalike_sender"],
            feats["has_mismatched_display_name"],
            feats["suspicious_attachment"],
            feats["generic_greeting"],
            feats["contains_password_request"],
            feats["contains_personal_info_request"],
            feats["exclamation_count"],
            feats["uppercase_ratio"]
        ]
        X_struct = np.array([vec])
        
        # Combined matrix
        X = np.hstack([X_text, X_struct])
        
        if hasattr(self.model, "predict_proba"):
            proba = float(self.model.predict_proba(X)[0, 1])
        else:
            pred = int(self.model.predict(X)[0])
            proba = 1.0 if pred == 1 else 0.0
            
        label = int(proba >= 0.5)
        return round(proba, 4), label, feats

# Singleton instance
predictor = PhishingPredictor()
