from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import re
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "history.db")


# =========================================================
# DATABASE
# =========================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_history(url, status, confidence):
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        INSERT INTO history (url, status, confidence, time)
        VALUES (?, ?, ?, ?)
    """, (
        url,
        status,
        confidence,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    signals = []

    # -----------------------------------------------------
    # Basic URL validation
    # -----------------------------------------------------

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
    except Exception:
        return {
            "status": "Phishing",
            "confidence": 95,
            "signals": ["Invalid URL"]
        }

    # -----------------------------------------------------
    # 1. HTTP instead of HTTPS
    # -----------------------------------------------------

    if parsed.scheme != "https":
        score += 15
        signals.append("No HTTPS")

    # -----------------------------------------------------
    # 2. IP address instead of domain
    # -----------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain.split(":")[0]):
        score += 25
        signals.append("IP address used instead of domain")

    # -----------------------------------------------------
    # 3. Suspicious keywords
    # -----------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "bank",
        "wallet",
        "payment",
        "claim",
        "free",
        "gift",
        "bonus",
        "urgent",
        "suspended",
        "unlock"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in full_url:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(len(found_keywords) * 7, 28)
        signals.append(
            "Suspicious keywords: " + ", ".join(found_keywords[:5])
        )

    # -----------------------------------------------------
    # 4. URL length
    # -----------------------------------------------------

    if len(url) > 100:
        score += 10
        signals.append("Very long URL")

    if len(url) > 180:
        score += 10
        signals.append("Extremely long URL")

    # -----------------------------------------------------
    # 5. Too many subdomains
    # -----------------------------------------------------

    subdomain_count = max(domain.count(".") - 1, 0)

    if subdomain_count >= 3:
        score += 15
        signals.append("Too many subdomains")

    # -----------------------------------------------------
    # 6. @ symbol
    # -----------------------------------------------------

    if "@" in url:
        score += 20
        signals.append("Suspicious @ symbol")

    # -----------------------------------------------------
    # 7. Hyphens
    # -----------------------------------------------------

    if domain.count("-") >= 3:
        score += 10
        signals.append("Multiple hyphens in domain")

    # -----------------------------------------------------
    # 8. Suspicious TLDs
    # -----------------------------------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".shop",
        ".online",
        ".site",
        ".live",
        ".icu",
        ".buzz",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    ]

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 15
        signals.append("Suspicious domain extension")

    # -----------------------------------------------------
    # 9. Encoded characters
    # -----------------------------------------------------

    if "%" in url:
        score += 8
        signals.append("Encoded URL characters")

    # -----------------------------------------------------
    # 10. Double slash in path
    # -----------------------------------------------------

    if "//" in path:
        score += 8
        signals.append("Suspicious URL path")

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    score = min(score, 100)

    if score >= 45:
        status = "Phishing"
        confidence = max(score, 70)
    else:
        status = "Safe"
        confidence = max(100 - score, 60)

    if not signals:
        signals.append("No major phishing indicators detected")

    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "url": url
    }


# =========================================================
# FRONTEND
# =========================================================

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/style.css")
def style():
    return send_from_directory(BASE_DIR, "style.css")


@app.route("/script.js")
def script():
    return send_from_directory(BASE_DIR, "script.js")


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "online",
        "message": "AI Phishing Detection Backend is running",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "history": "/history"
        }
    })


# =========================================================
# SCAN URL
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "status": "Error",
                "message": "URL is required"
            }), 400

        url = data["url"].strip()

        if not url:
            return jsonify({
                "status": "Error",
                "message": "URL is empty"
            }), 400

        result = analyze_url(url)

        save_history(
            result["url"],
            result["status"],
            result["confidence"]
        )

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "status": "Error",
            "message": str(e)
        }), 500


# =========================================================
# HISTORY
# =========================================================

@app.route("/history", methods=["GET"])
def history():

    try:

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT url, status, confidence, time
            FROM history
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

        conn.close()

        result = []

        for row in rows:
            result.append({
                "url": row["url"],
                "status": row["status"],
                "confidence": row["confidence"],
                "time": row["time"]
            })

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# =========================================================
# START SERVER
# =========================================================

init_db()


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )