"""
FILE NAME: auth.py
FILE PATH: backend/utils/auth.py
PURPOSE: Secure password hashing, token generation, and authentication utilities.
         Uses standard library hashlib with PBKDF2-HMAC-SHA256 and salt for zero external crypto bloat.
"""

import hashlib
import os
import secrets
from typing import Tuple

# In-memory active session store (token -> {user_id, username, role})
ACTIVE_SESSIONS = {}

def hash_password(password: str) -> str:
    """Hashes a password with a unique cryptographic salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations=100000
    )
    return f"{salt}:{key.hex()}"

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verifies a password against the stored salt:hash string."""
    try:
        salt, key_hex = stored_hash.split(":")
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations=100000
        )
        return secrets.compare_digest(new_key.hex(), key_hex)
    except Exception:
        return False

def create_session(user_id: int, username: str, role: str) -> str:
    """Creates a secure session token for an authenticated user."""
    token = f"sess_{secrets.token_urlsafe(32)}"
    ACTIVE_SESSIONS[token] = {
        "user_id": user_id,
        "username": username,
        "role": role
    }
    return token

def get_session_user(token: str):
    """Retrieves session user payload if token is valid."""
    return ACTIVE_SESSIONS.get(token)

def delete_session(token: str):
    """Terminates a session token."""
    if token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
