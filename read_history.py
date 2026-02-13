import sqlite3
import json

conn = sqlite3.connect('instance/visionx.db')
c = conn.cursor()

c.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = c.fetchall()
print("Tables:", tables)

if ('scan_history',) in tables:
    c.execute("SELECT id, scan_type, target, risk_score, risk_level, reasons, created_at FROM scan_history ORDER BY id DESC LIMIT 5")
    rows = c.fetchall()

    print("--- Recent Scans ---")
    for row in rows:
        print(f"ID: {row[0]}")
        print(f"Type: {row[1]}")
        print(f"Target: {row[2]}")
        print(f"Score: {row[3]}")
        print(f"Level: {row[4]}")
        print(f"Reasons: {row[5]}")
        print(f"Time: {row[6]}")
        print("-" * 20)
else:
    print("scan_history table not found.")

conn.close()
