import sqlite3

conn = sqlite3.connect("history.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    status TEXT,
    confidence INTEGER,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()