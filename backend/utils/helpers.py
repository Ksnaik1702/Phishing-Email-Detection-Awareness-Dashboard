"""
FILE NAME: helpers.py
FILE PATH: backend/utils/helpers.py
PURPOSE: Security utility helpers, defensive string escaping, and input validation.
"""

import html
import re

def sanitize_text(input_str: str) -> str:
    """Escapes HTML characters to prevent Stored or Reflected XSS in the dashboard."""
    if not input_str:
        return ""
    return html.escape(input_str.strip())

def defang_url(url_str: str) -> str:
    """
    Defangs a URL or IP for safe visual display in reports without accidental clicks.
    e.g., http://198.51.100.10 -> hxxp://198[.]51[.]100[.]10
    """
    if not url_str:
        return ""
    defanged = url_str.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged

def is_valid_email_syntax(email_str: str) -> bool:
    """Checks basic structural validity of an email address."""
    if not email_str:
        return False
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email_str.strip()))
