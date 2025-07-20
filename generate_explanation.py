def generate_explanation(features, prediction):
    if prediction == 0:
        return ["No phishing patterns detected."]

    explanation = []

    if features["has_ip"]:
        explanation.append("Uses an IP address instead of a domain.")
    if features["has_at_symbol"]:
        explanation.append("Contains an '@' symbol, often used in phishing URLs.")
    if features["has_multiple_slashes"]:
        explanation.append("Has multiple '//' which may indicate redirection.")
    if features["form_count"] > 1:
        explanation.append("Contains multiple forms, which is suspicious.")
    if features["keyword_score"] > 2:
        explanation.append("Contains phishing-related keywords.")
    if features["url_entropy"] > 4.0:
        explanation.append("URL has high entropy, indicating randomness.")
    if features["suspicious_tld"]:
        explanation.append("Uses a suspicious top-level domain.")
    if 0 <= features["domain_age_days"] < 180:
        explanation.append("Domain is very new.")

    return explanation if explanation else ["Phishing patterns detected."]
