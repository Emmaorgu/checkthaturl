from extract_features import extract_features

def extract_features_from_url(url):
    features = extract_features(url)

    # Ensure only the required numeric fields are returned
    return {
        "url_length": features.get("url_length", 0),
        "num_dots": features.get("num_dots", 0),
        "has_https": features.get("has_https", 0),
        "num_subdomains": features.get("num_subdomains", 0),
        "has_ip": features.get("has_ip", 0),
        "has_at_symbol": features.get("has_at_symbol", 0),
        "has_dash": features.get("has_dash", 0),
        "has_multiple_slashes": features.get("has_multiple_slashes", 0),
        "domain_age_days": features.get("domain_age_days", -1),
        "form_count": features.get("form_count", 0),
        "keyword_score": features.get("keyword_score", 0),
        "favicon_match": features.get("favicon_match", 0),
        "url_entropy": features.get("url_entropy", 0),
        "suspicious_tld": features.get("suspicious_tld", 0),
    }
