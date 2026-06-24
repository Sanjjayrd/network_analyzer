import sqlite3
import os
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT_DIR, "cvip.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Scans table (history of scan runs)
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            intensity TEXT NOT NULL,
            start_time TEXT NOT NULL,
            scan_time_seconds REAL,
            status TEXT NOT NULL
        )
    ''')
    
    # Hosts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            state TEXT,
            os TEXT,
            os_family TEXT,
            mac TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    ''')
    
    # Services table
    c.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            version_string TEXT,
            cpe_raw TEXT,
            cpe TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
    ''')
    
    # Vulnerabilities table
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            service_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            severity TEXT,
            cvss_score REAL,
            published TEXT,
            description TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
        )
    ''')
    
    # Remediation table
    c.execute('''
        CREATE TABLE IF NOT EXISTS remediations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            advisory TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize DB on import
init_db()
