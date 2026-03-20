"""
utils/database.py - SQLite database management for all app data
"""
import sqlite3
import bcrypt
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "phishguard.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT,
            scan_count INTEGER DEFAULT 0
        )
    """)

    # URL scan history
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            risk_score REAL,
            verdict TEXT,
            features TEXT,
            scanned_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Email scan history
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_subject TEXT,
            risk_score REAL,
            verdict TEXT,
            phishing_indicators TEXT,
            scanned_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Phishing reports
    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            report_reason TEXT,
            additional_info TEXT,
            status TEXT DEFAULT 'pending',
            reported_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Threat intelligence (local cache)
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            threat_type TEXT,
            confidence REAL,
            source TEXT,
            last_updated TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.commit()

    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        pw_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        c.execute("""
            INSERT INTO users (username, password_hash, email, role)
            VALUES ('admin', ?, 'admin@phishguard.ai', 'admin')
        """, (pw_hash,))
        conn.commit()

    conn.close()


# ── Auth ──────────────────────────────────────────────────────────────────────

def register_user(username, password, email):
    conn = get_connection()
    c = conn.cursor()
    try:
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?,?,?)",
                  (username, pw_hash, email))
        conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()


def login_user(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        c.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
        return True, dict(user)
    conn.close()
    return False, None


# ── Scan History ──────────────────────────────────────────────────────────────

def save_url_scan(user_id, url, risk_score, verdict, features):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO scan_history (user_id, url, risk_score, verdict, features)
        VALUES (?,?,?,?,?)
    """, (user_id, url, risk_score, verdict, json.dumps(features)))
    c.execute("UPDATE users SET scan_count = scan_count + 1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()


def get_scan_history(user_id=None, limit=100):
    conn = get_connection()
    c = conn.cursor()
    if user_id:
        c.execute("""
            SELECT s.*, u.username FROM scan_history s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id=? ORDER BY s.scanned_at DESC LIMIT ?
        """, (user_id, limit))
    else:
        c.execute("""
            SELECT s.*, u.username FROM scan_history s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.scanned_at DESC LIMIT ?
        """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def save_email_scan(user_id, subject, risk_score, verdict, indicators):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO email_scans (user_id, email_subject, risk_score, verdict, phishing_indicators)
        VALUES (?,?,?,?,?)
    """, (user_id, subject, risk_score, verdict, json.dumps(indicators)))
    conn.commit()
    conn.close()


def get_email_history(user_id=None, limit=50):
    conn = get_connection()
    c = conn.cursor()
    if user_id:
        c.execute("SELECT * FROM email_scans WHERE user_id=? ORDER BY scanned_at DESC LIMIT ?",
                  (user_id, limit))
    else:
        c.execute("SELECT * FROM email_scans ORDER BY scanned_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ── Reports ───────────────────────────────────────────────────────────────────

def submit_report(user_id, url, reason, info):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO reports (user_id, url, report_reason, additional_info)
        VALUES (?,?,?,?)
    """, (user_id, url, reason, info))
    conn.commit()
    conn.close()


def get_reports(status=None):
    conn = get_connection()
    c = conn.cursor()
    if status:
        c.execute("""
            SELECT r.*, u.username FROM reports r
            JOIN users u ON r.user_id = u.id
            WHERE r.status=? ORDER BY r.reported_at DESC
        """, (status,))
    else:
        c.execute("""
            SELECT r.*, u.username FROM reports r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.reported_at DESC
        """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def update_report_status(report_id, status):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE reports SET status=? WHERE id=?", (status, report_id))
    conn.commit()
    conn.close()


# ── Admin Stats ───────────────────────────────────────────────────────────────

def get_admin_stats():
    conn = get_connection()
    c = conn.cursor()
    stats = {}
    c.execute("SELECT COUNT(*) as cnt FROM users WHERE role='user'")
    stats["total_users"] = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM scan_history")
    stats["total_scans"] = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM scan_history WHERE verdict='Phishing'")
    stats["phishing_detected"] = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM reports WHERE status='pending'")
    stats["pending_reports"] = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM email_scans")
    stats["email_scans"] = c.fetchone()["cnt"]
    c.execute("SELECT AVG(risk_score) as avg FROM scan_history")
    avg = c.fetchone()["avg"]
    stats["avg_risk"] = round(avg, 1) if avg else 0
    conn.close()
    return stats


def get_all_users():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at, last_login, scan_count FROM users ORDER BY created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows
