from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import re
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# Allow Vercel / browser frontend to access Render backend
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "history.db")


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=10,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    try:
        conn = get_db()

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

        print("Database initialized successfully")

    except Exception as e:
        print("Database initialization error:", e)


def save_history(url, status, confidence):
    conn = None

    try:
        conn = get_db()

        conn.execute("""
            INSERT INTO history
            (url, status, confidence, time)
            VALUES (?, ?, ?, ?)
        """, (
            url,
            status,
            int(confidence),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()

    except Exception as e:
        print("History save error:", e)

    finally:
        if conn:
            conn.close()


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(original_url):

    url = str(original_url).strip()

    if not url:
        return {
            "status": "Error",
            "confidence": 0,
            "signals": ["URL is empty"],
            "url": url
        }

    # Add HTTPS if user doesn't enter protocol
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        domain = parsed.hostname or ""
        domain = domain.lower()

        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()

        # Invalid URL
        if not domain or "." not in domain:
            return {
                "status": "Phishing",
                "confidence": 95,
                "signals": ["Invalid or suspicious domain"],
                "url": url
            }

    except Exception:
        return {
            "status": "Phishing",
            "confidence": 95,
            "signals": ["Invalid URL"],
            "url": url
        }

    score = 0
    signals = []


    # =====================================================
    # 1. HTTP instead of HTTPS
    # =====================================================

    if parsed.scheme.lower() != "https":
        score += 15
        signals.append("No HTTPS")


    # =====================================================
    # 2. IP address instead of domain
    # =====================================================

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain):
        score += 25
        signals.append("IP address used instead of domain")


    # =====================================================
    # 3. Suspicious keywords
    # =====================================================

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
        score += min(len(found_keywords) * 6, 24)

        signals.append(
            "Suspicious keywords: " +
            ", ".join(found_keywords[:5])
        )


    # =====================================================
    # 4. Very long URL
    # =====================================================

    if len(url) > 100:
        score += 10
        signals.append("Very long URL")

    if len(url) > 180:
        score += 10
        signals.append("Extremely long URL")


    # =====================================================
    # 5. Too many subdomains
    # =====================================================

    parts = domain.split(".")

    if len(parts) >= 5:
        score += 15
        signals.append("Too many subdomains")


    # =====================================================
    # 6. @ symbol
    # =====================================================

    if "@" in url:
        score += 20
        signals.append("Suspicious @ symbol")


    # =====================================================
    # 7. Multiple hyphens
    # =====================================================

    if domain.count("-") >= 3:
        score += 10
        signals.append("Multiple hyphens in domain")


    # =====================================================
    # 8. Suspicious TLD
    # =====================================================

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
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


    # =====================================================
    # 9. Encoded characters
    # =====================================================

    if "%" in url:
        score += 8
        signals.append("Encoded URL characters")


    # =====================================================
    # 10. Suspicious double slash in path
    # =====================================================

    if "//" in path:
        score += 8
        signals.append("Suspicious URL path")


    # =====================================================
    # 11. Suspicious query parameters
    # =====================================================

    suspicious_query_words = [
        "password",
        "passwd",
        "token",
        "verify",
        "verification",
        "login"
    ]

    query_found = []

    for word in suspicious_query_words:
        if word in query:
            query_found.append(word)

    if query_found:
        score += min(len(query_found) * 5, 15)
        signals.append(
            "Suspicious query parameters: " +
            ", ".join(query_found[:5])
        )


    # =====================================================
    # FINAL SCORE
    # =====================================================

    score = min(score, 100)

    if score >= 45:
        status = "Phishing"
        confidence = max(score, 70)
    else:
        status = "Safe"
        confidence = max(100 - score, 60)

    if not signals:
        signals.append(
            "No major phishing indicators detected"
        )

    return {
        "status": status,
        "confidence": int(confidence),
        "signals": signals,
        "url": url
    }


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():

    try:
        return send_from_directory(BASE_DIR, "index.html")

    except Exception as e:
        return jsonify({
            "status": "online",
            "message": "Backend is running",
            "error": str(e)
        })


# =========================================================
# HEALTH
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
# SCAN
# =========================================================

@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():

    # Browser CORS preflight
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    try:

        # Accept JSON safely
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "status": "Error",
                "message": "JSON request body is required"
            }), 400

        url = data.get("url")

        if url is None:
            return jsonify({
                "status": "Error",
                "message": "URL is required"
            }), 400

        url = str(url).strip()

        if not url:
            return jsonify({
                "status": "Error",
                "message": "URL cannot be empty"
            }), 400

        # Analyze
        result = analyze_url(url)

        # Save history
        save_history(
            result["url"],
            result["status"],
            result["confidence"]
        )

        # Return result
        return jsonify(result), 200

    except Exception as e:

        print("SCAN ERROR:", repr(e))

        return jsonify({
            "status": "Error",
            "message": "Unable to scan URL",
            "error": str(e)
        }), 500


# =========================================================
# HISTORY
# =========================================================

@app.route("/history", methods=["GET"])
def history():

    conn = None

    try:

        conn = get_db()

        rows = conn.execute("""
            SELECT url, status, confidence, time
            FROM history
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

        result = []

        for row in rows:
            result.append({
                "url": row["url"],
                "status": row["status"],
                "confidence": row["confidence"],
                "time": row["time"]
            })

        return jsonify(result), 200

    except Exception as e:

        print("HISTORY ERROR:", repr(e))

        return jsonify({
            "status": "Error",
            "message": str(e),
            "history": []
        }), 500

    finally:

        if conn:
            conn.close()


# =========================================================
# TEST SCAN
# =========================================================

@app.route("/test", methods=["GET"])
def test():

    result = analyze_url("https://www.google.com")

    return jsonify({
        "message": "Scan engine working",
        "test": result
    })


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_db()


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    print("========================================")
    print("AI PHISHING DETECTOR")
    print("Server starting...")
    print("Port:", port)
    print("========================================")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )