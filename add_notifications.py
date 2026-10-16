"""Idempotent migration for the Phase 10 notification tables/columns.

Safe to run multiple times. Uses CREATE TABLE IF NOT EXISTS and checks
PRAGMA table_info before ALTER TABLE.

Usage:
    python add_notifications.py
"""
import os
import sqlite3

DEFAULT_DB = os.path.join(os.path.dirname(__file__), "db", "zta.db")


def migrate(db_path=DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # --- Device.notify_email ---
    cols = {row[1] for row in cur.execute("PRAGMA table_info(device)")}
    if "notify_email" not in cols:
        cur.execute("ALTER TABLE device ADD COLUMN notify_email VARCHAR(120)")
        print("Added device.notify_email")
    if "medium_streak" not in cols:
        cur.execute("ALTER TABLE device ADD COLUMN medium_streak INTEGER DEFAULT 0")
        print("Added device.medium_streak")

    # --- Notification table ---
    cur.execute(
        """CREATE TABLE IF NOT EXISTS notification (
            id INTEGER PRIMARY KEY,
            mac VARCHAR(20) REFERENCES device(mac),
            recipient VARCHAR(120),
            kind VARCHAR(20),
            score INTEGER,
            reason VARCHAR(200),
            status VARCHAR(20),
            error VARCHAR(300),
            created_at DATETIME
        )"""
    )
    print("notification ready")

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    migrate(path)
