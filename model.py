def detect_phishing(url):

    phishing_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "paypal"
    ]

    score = 95

    for word in phishing_keywords:

        if word in url.lower():

            return {
                "status":"Phishing",
                "confidence":score
            }

    return {
        "status":"Safe",
        "confidence":98
    }