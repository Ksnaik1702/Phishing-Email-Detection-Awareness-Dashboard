"""
FILE NAME: database.py
FILE PATH: backend/database.py
PURPOSE: SQLite database schema, table creation, and connection manager.
         Stores safe email metadata, findings, URL analyses, and statistics.
         Avoids storing sensitive raw email bodies by default to preserve privacy.
"""

import sqlite3
import os
import json
from contextlib import contextmanager
from backend.config import settings

def init_db(db_path: str = None):
    """Initializes the database schema if tables do not exist."""
    path = db_path or settings.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    
    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()
        
        # 1. Main Analyses Table (Metadata and Scores)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            sender TEXT,
            sender_domain TEXT,
            subject TEXT,
            risk_score REAL NOT NULL,
            rule_score REAL,
            ml_score REAL,
            classification TEXT NOT NULL,
            has_attachment INTEGER DEFAULT 0,
            attachment_name TEXT,
            url_count INTEGER DEFAULT 0,
            explanation TEXT,
            recommendations TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # 2. Indicators Breakdown Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            weight REAL NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
        )
        """)
        
        # 3. URL Analyses Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_analyses (
            url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            url_safe_representation TEXT NOT NULL,
            risk_score REAL NOT NULL,
            findings TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
        )
        """)
        
        # 4. Optional Users / Analysts Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()

@contextmanager
def get_db(db_path: str = None):
    """Context manager for obtaining a database connection with dict-like row factories."""
    path = db_path or settings.DATABASE_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    print("[+] Database initialized successfully.")
