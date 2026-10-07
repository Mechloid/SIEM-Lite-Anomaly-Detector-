import sqlite3
import pandas as pd
from datetime import datetime

DB_NAME = "siem_alerts.db"

def init_db():
    """Creates the alerts table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            username TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(ip, username, alert_type, severity, message):
    """Call this from your Rule / ML Engine when an anomaly triggers."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (ip_address, username, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)
    ''', (ip, username, alert_type, severity, message))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=100):
    """Fetches the latest alerts for display."""
    conn = sqlite3.connect(DB_NAME)
    query = "SELECT timestamp, ip_address, username, alert_type, severity, message FROM alerts ORDER BY id DESC LIMIT ?"
    df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df
