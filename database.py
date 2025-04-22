import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            website TEXT UNIQUE,
            username TEXT,
            password TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT,
            success BOOLEAN
        )
    """)
    conn.commit()

def log_event(action: str, success: bool):
    conn = sqlite3.connect("vault.db")
    conn.execute("INSERT INTO audit_log (action, success) VALUES (?, ?)", (action, success))
    conn.commit()