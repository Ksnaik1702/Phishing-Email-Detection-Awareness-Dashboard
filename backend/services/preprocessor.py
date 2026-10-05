"""
FILE NAME: preprocessor.py
FILE PATH: backend/services/preprocessor.py
PURPOSE: Safe email text preprocessing, normalization, and token/URL extraction.
         IMPORTANT DEFENSIVE CYBERSECURITY NOTE:
         Aggressive text cleaning (e.g., stripping all punctuation, numbers, or uppercase letters)
         destroys crucial phishing indicators such as urgency signals (e.g., 'URGENT!', 'ACT NOW!!!'),
         IP addresses (e.g., '198.51.100.10'), and lookalike domains (e.g., 'micr0soft.com').
         This preprocessor preserves casing metrics and structural artifacts for detection.
"""

import re
from typing import List, Dict, Any

# Regex to detect URLs (http, https, ftp, raw ip links)
URL_REGEX = re.compile(
    r'(?:https?://|ftp://|www\.)[^\s<>"\'{}|\\^`]+|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>"\'{}|\\^`]*)?',
    re.IGNORECASE
)

# Email address extraction
EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+', re.IGNORECASE)

class EmailPreprocessor:
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Safely extracts all unique URLs and IP addresses present in the text."""
        if not text:
            return []
        found = URL_REGEX.findall(text)
        cleaned_urls = []
        for u in found:
            u_clean = u.strip().rstrip(".,;)>]\"'")
            if u_clean and u_clean not in cleaned_urls:
                cleaned_urls.append(u_clean)
        return cleaned_urls

    @staticmethod
    def extract_domain(sender_str: str) -> str:
        """Extracts the domain portion from an email address or string."""
        if not sender_str:
            return ""
        sender_str = sender_str.strip().lower()
        if "<" in sender_str and ">" in sender_str:
            match = re.search(r'<([^>]+)>', sender_str)
            if match:
                sender_str = match.group(1)
        if "@" in sender_str:
            return sender_str.split("@")[-1].strip()
        return sender_str

    @staticmethod
    def extract_attachment_extension(filename: str) -> Dict[str, Any]:
        """
        Extracts extension metadata, including detection of suspicious double extensions.
        e.g. 'invoice.pdf.exe' -> ext='.exe', base_ext='.pdf', is_double=True
        """
        if not filename:
            return {"extension": "", "is_double": False, "parts": []}
            
        parts = filename.strip().split(".")
        if len(parts) > 2:
            return {
                "extension": f".{parts[-1].lower()}",
                "is_double": True,
                "parts": [f".{p.lower()}" for p in parts[1:]]
            }
        elif len(parts) == 2:
            return {
                "extension": f".{parts[-1].lower()}",
                "is_double": False,
                "parts": [f".{parts[-1].lower()}"]
            }
        return {"extension": "", "is_double": False, "parts": []}

    @staticmethod
    def compute_text_metrics(text: str) -> Dict[str, Any]:
        """Calculates casing ratios, exclamation frequency, and length metrics without stripping evidence."""
        if not text:
            return {
                "length": 0,
                "uppercase_count": 0,
                "uppercase_ratio": 0.0,
                "exclamation_count": 0,
                "question_count": 0
            }
        
        length = len(text)
        upper_cnt = sum(1 for c in text if c.isupper())
        upper_ratio = (upper_cnt / length) if length > 0 else 0.0
        excl_cnt = text.count("!")
        ques_cnt = text.count("?")
        
        return {
            "length": length,
            "uppercase_count": upper_cnt,
            "uppercase_ratio": round(upper_ratio, 4),
            "exclamation_count": excl_cnt,
            "question_count": ques_cnt
        }
