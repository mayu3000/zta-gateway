"""Idempotent migration for portal-gate tables/columns.

Safe to run multiple times. Uses CREATE TABLE IF NOT EXISTS and checks
PRAGMA table_info before ALTER TABLE.

Usage:
    python add_portal_gate.py
"""
import os
import sqlite3

DEFAULT_DB = os.path.join(os.path.dirname(__file__), "db", "zta.db")


def migrate(db_path=DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # --- Device.user_id and Device.granted_at ---
    cols = {row[1] for row in cur.execute("PRAGMA table_info(device)")}
    if "user_id" not in cols:
        cur.execute(
            "ALTER TABLE device ADD COLUMN user_id INTEGER "
            "REFERENCES user(id)"
        )
        print("Added device.user_id")
    if "granted_at" not in cols:
        cur.execute(
            "ALTER TABLE device ADD COLUMN granted_at DATETIME"
        )
        print("Added device.granted_at")

    # --- PortalSession table ---
    cur.execute(
        """CREATE TABLE IF NOT EXISTS portal_session (
            id INTEGER PRIMARY KEY,
            mac VARCHAR(20) REFERENCES device(mac),
            username VARCHAR(80),
            state VARCHAR(20) DEFAULT 'granted',
            granted_at DATETIME,
            last_activity DATETIME,
            expires_at DATETIME
        )"""
    )
    print("portal_session ready")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    migrate(path)
