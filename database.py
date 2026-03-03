# ============================================================
# database.py — SQLite Database Functions
# Threat Intelligence Dashboard
# ============================================================
# This file handles ALL database operations:
#   - Creating tables
#   - Inserting IOC data
#   - Searching IOCs
#   - Getting statistics for charts
# ============================================================

import sqlite3
import pandas as pd
from datetime import datetime

# ─────────────────────────────────────────────
# DATABASE FILE PATH
# SQLite stores everything in a single .db file
# ─────────────────────────────────────────────
DB_PATH = "threat_intel.db"


def get_connection():
    """
    Creates and returns a connection to the SQLite database.
    
    Think of this like opening a file — you need a connection
    before you can read/write anything.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name (e.g., row["source"])
    return conn


def initialize_database():
    """
    Creates all required tables if they don't already exist.
    
    This is called once when the app starts.
    Tables:
      - iocs       → stores malicious IPs, domains, hashes
      - cve_feed   → stores CVE vulnerability data
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── IOC Table ──────────────────────────────────────────
    # Stores Indicators of Compromise (IOCs)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_value TEXT NOT NULL,          -- e.g., "192.168.1.1" or "malware.com"
            indicator_type  TEXT NOT NULL,          -- "IP", "Domain", or "Hash"
            threat_category TEXT,                   -- e.g., "malware", "phishing", "botnet"
            source          TEXT,                   -- "AbuseIPDB", "AlienVault OTX", "URLhaus"
            country         TEXT,                   -- Country of origin (for map)
            confidence_score INTEGER DEFAULT 0,     -- 0-100 confidence this is malicious
            date_added      TEXT DEFAULT (datetime('now')),
            UNIQUE(indicator_value, source)         -- Prevent duplicate entries
        )
    """)

    # ── CVE Table ──────────────────────────────────────────
    # Stores CVE (Common Vulnerabilities and Exposures) data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_feed (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT UNIQUE NOT NULL,   -- e.g., "CVE-2024-1234"
            description     TEXT,
            severity        TEXT,                   -- "CRITICAL", "HIGH", "MEDIUM", "LOW"
            cvss_score      REAL,                   -- Numeric score e.g. 9.8
            published_date  TEXT,
            date_added      TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()
    print("[✓] Database initialized successfully.")


def insert_ioc(indicator_value, indicator_type, threat_category, source,
               country=None, confidence_score=0):
    """
    Inserts a single IOC record into the database.
    
    Uses INSERT OR IGNORE so duplicate entries are silently skipped
    (same indicator from the same source won't be inserted twice).
    
    Parameters:
        indicator_value   : The actual IOC (IP address, domain, hash)
        indicator_type    : "IP", "Domain", or "Hash"
        threat_category   : Type of threat (malware, phishing, etc.)
        source            : Which API provided this data
        country           : Country code (e.g., "US", "CN", "RU")
        confidence_score  : How confident the source is (0-100)
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO iocs
            (indicator_value, indicator_type, threat_category, source, country, confidence_score)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (indicator_value, indicator_type, threat_category, source, country, confidence_score))

    conn.commit()
    conn.close()


def insert_cve(cve_id, description, severity, cvss_score, published_date):
    """
    Inserts a CVE vulnerability record into the database.
    Uses INSERT OR IGNORE to avoid duplicate CVE IDs.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO cve_feed
            (cve_id, description, severity, cvss_score, published_date)
        VALUES (?, ?, ?, ?, ?)
    """, (cve_id, description, severity, cvss_score, published_date))

    conn.commit()
    conn.close()


def get_all_iocs():
    """
    Fetches all IOC records from the database.
    Returns a pandas DataFrame — easy to display in Streamlit.
    
    DataFrame columns:
        id, indicator_value, indicator_type, threat_category,
        source, country, confidence_score, date_added
    """
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM iocs ORDER BY date_added DESC", conn)
    conn.close()
    return df


def search_ioc(query):
    """
    Searches IOCs by indicator_value (partial match).
    
    Example: search_ioc("192.168") returns all IPs containing "192.168"
    
    Uses SQL LIKE operator with wildcards (%) for partial matching.
    """
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM iocs WHERE indicator_value LIKE ? ORDER BY date_added DESC",
        conn,
        params=(f"%{query}%",)
    )
    conn.close()
    return df


def get_ioc_stats():
    """
    Returns statistics used for charts:
    
    1. threat_category_counts — how many IOCs per threat type
    2. source_counts          — how many IOCs per data source
    3. type_counts            — how many IPs vs Domains vs Hashes
    4. timeline_data          — IOCs added per day (for timeline chart)
    5. country_counts         — IOCs per country (for map)
    """
    conn = get_connection()

    # Count by threat category
    threat_df = pd.read_sql_query("""
        SELECT threat_category, COUNT(*) as count
        FROM iocs
        WHERE threat_category IS NOT NULL
        GROUP BY threat_category
        ORDER BY count DESC
    """, conn)

    # Count by source
    source_df = pd.read_sql_query("""
        SELECT source, COUNT(*) as count
        FROM iocs
        GROUP BY source
        ORDER BY count DESC
    """, conn)

    # Count by indicator type
    type_df = pd.read_sql_query("""
        SELECT indicator_type, COUNT(*) as count
        FROM iocs
        GROUP BY indicator_type
    """, conn)

    # Timeline — IOCs added per day
    timeline_df = pd.read_sql_query("""
        SELECT DATE(date_added) as date, COUNT(*) as count
        FROM iocs
        GROUP BY DATE(date_added)
        ORDER BY date ASC
    """, conn)

    # Country counts for map
    country_df = pd.read_sql_query("""
        SELECT country, COUNT(*) as count
        FROM iocs
        WHERE country IS NOT NULL AND country != ''
        GROUP BY country
        ORDER BY count DESC
    """, conn)

    conn.close()

    return {
        "threat_categories": threat_df,
        "sources": source_df,
        "types": type_df,
        "timeline": timeline_df,
        "countries": country_df
    }


def get_all_cves():
    """
    Fetches all CVE records from the database.
    Returns a pandas DataFrame.
    """
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM cve_feed ORDER BY published_date DESC", conn
    )
    conn.close()
    return df


def get_total_ioc_count():
    """Returns total number of IOCs stored in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM iocs")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def clear_all_iocs():
    """Deletes all IOC records. Useful for resetting/testing."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM iocs")
    conn.commit()
    conn.close()
