from flask import Flask, request, jsonify, send_from_directory
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return send_from_directory(".", "index.html")


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "message": "AI Phishing Detection Server is running"
    })


# =========================================================
# PHISHING URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []
    signals = []

    # -----------------------------------------------------
    # Basic URL validation
    # -----------------------------------------------------

    if not url:
        return {
            "status": "ERROR",
            "score": 0,
            "reasons": ["URL is empty"],
            "signals": []
        }

    # Add scheme if missing
    test_url = url

    if not re.match(r"^https?://", test_url, re.IGNORECASE):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    hostname = hostname.lower()

    # -----------------------------------------------------
    # HTTPS CHECK
    # -----------------------------------------------------

    if url.lower().startswith("https://"):

        signals.append({
            "name": "HTTPS Encryption",
            "status": "PASS"
        })

    else:

        score += 20

        reasons.append("Website does not use HTTPS")

        signals.append({
            "name": "HTTPS Encryption",
            "status": "WARNING"
        })


    # -----------------------------------------------------
    # IP ADDRESS CHECK
    # -----------------------------------------------------

    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):

        score += 25

        reasons.append("URL uses a raw IP address instead of a domain")

        signals.append({
            "name": "IP Address Check",
            "status": "WARNING"
        })

    else:

        signals.append({
            "name": "IP Address Check",
            "status": "PASS"
        })


    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_keywords = [

        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "password",
        "bank",
        "banking",
        "wallet",
        "payment",
        "confirm",
        "credential",
        "unlock",
        "free",
        "winner",
        "reward",
        "gift",
        "bonus"

    ]

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in hostname:

            found_keywords.append(keyword)

    if found_keywords:

        score += min(len(found_keywords) * 10, 30)

        for keyword in found_keywords:

            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )

        signals.append({
            "name": "Suspicious Keywords",
            "status": "WARNING"
        })

    else:

        signals.append({
            "name": "Suspicious Keywords",
            "status": "PASS"
        })


    # -----------------------------------------------------
    # @ REDIRECT TRICK
    # -----------------------------------------------------

    if "@" in url:

        score += 25

        reasons.append(
            "URL contains @ symbol which may be used for redirection"
        )

        signals.append({
            "name": "URL Redirect Trick",
            "status": "WARNING"
        })


    # -----------------------------------------------------
    # DOMAIN STRUCTURE
    # -----------------------------------------------------

    dot_count = hostname.count(".")

    hyphen_count = hostname.count("-")

    if dot_count >= 4:

        score += 10

        reasons.append(
            "Unusually many subdomains detected"
        )

        signals.append({
            "name": "Domain Structure",
            "status": "WARNING"
        })

    elif hyphen_count >= 3:

        score += 8

        reasons.append(
            "Excessive hyphens detected in domain"
        )

        signals.append({
            "name": "Domain Structure",
            "status": "WARNING"
        })

    else:

        signals.append({
            "name": "Domain Structure",
            "status": "PASS"
        })


    # -----------------------------------------------------
    # URL LENGTH
    # -----------------------------------------------------

    if len(url) > 150:

        score += 10

        reasons.append(
            "Unusually long URL detected"
        )

        signals.append({
            "name": "URL Length",
            "status": "WARNING"
        })

    else:

        signals.append({
            "name": "URL Length",
            "status": "PASS"
        })


    # -----------------------------------------------------
    # SHORTENER DETECTION
    # -----------------------------------------------------

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "ow.ly"

    ]

    if hostname in shorteners:

        score += 15

        reasons.append(
            "URL shortener detected; final destination is hidden"
        )

        signals.append({
            "name": "URL Shortener",
            "status": "WARNING"
        })


    # -----------------------------------------------------
    # FINAL RISK LEVEL
    # -----------------------------------------------------

    if score >= 60:

        status = "PHISHING"

    elif score >= 30:

        status = "SUSPICIOUS"

    else:

        status = "SAFE"


    # -----------------------------------------------------
    # LIMIT SCORE
    # -----------------------------------------------------

    score = min(score, 100)


    # -----------------------------------------------------
    # DEFAULT REASON
    # -----------------------------------------------------

    if not reasons:

        reasons.append(
            "No major phishing indicators detected"
        )


    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    return {

        "status": status,

        "score": score,

        "url": url,

        "hostname": hostname,

        "reasons": reasons,

        "signals": signals,

        "ml_probability": round(score / 100, 2)

    }


# =========================================================
# SCAN API
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json(silent=True)

        if not data:

            return jsonify({
                "error": "No JSON data received"
            }), 400


        url = data.get("url", "").strip()


        if not url:

            return jsonify({
                "error": "Please enter a URL"
            }), 400


        result = analyze_url(url)


        return jsonify(result), 200


    except Exception as e:

        print("SCAN ERROR:", e)

        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    print("")
    print("==========================================")
    print("      AI PHISHING DETECTOR")
    print("==========================================")
    print("")
    print("Server starting...")
    print("Open: http://127.0.0.1:5000")
    print("API:  http://127.0.0.1:5000/scan")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )