import re
import requests
import socket
import whois
import math
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter
import tldextract

HIGH_RISK_KEYWORDS = [
    "you have won a prize", "your account will be suspended", "immediate action required",
    "tax refund pending", "we are experiencing a temporary disruption", "exclusive offer",
    "win", "good news!", "you have been selected!", "withdraw my cash", "withdraw your cash",
    "congratulations", "apply now", "application closes", "apply here", "bvn", "quick loan", "urgent", "gift", "verification", "payment", "discount",
    "your account has been hacked", "start your application", "start your application below",
    "start application here", "enter your account number", "enter account number here", "dear valued member",
    "dear account holder", "free", "withdraw cash"
]


SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'}

def keyword_analysis(html_text):
    text = html_text.lower()
    high_risk_found = [kw for kw in HIGH_RISK_KEYWORDS if kw.lower() in text]
    contextual_found = [kw for kw in CONTEXTUAL_KEYWORDS if kw.lower() in text]
    return len(high_risk_found), len(contextual_found), high_risk_found, contextual_found

def compute_entropy(url: str) -> float:
    if not url:
        return 0.0
    counter = Counter(url)
    length = len(url)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return round(entropy, 4)

def is_suspicious_tld(url: str) -> int:
    try:
        netloc = urlparse(url).netloc.lower()
        return int(any(netloc.endswith(tld) for tld in SUSPICIOUS_TLDS))
    except:
        return 0

def extract_features(url):
    features = {}
    try:
        response = requests.get(url, timeout=10)
        html_content = response.text
    except Exception:
        html_content = ""

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ext = tldextract.extract(url)
    hostname = ext.domain + "." + ext.suffix

    features.update({
        "url": url,
        "url_length": len(url),
        "num_dots": url.count('.'),
        "has_https": int(parsed_url.scheme == "https"),
        "num_subdomains": len(ext.subdomain.split('.')) if ext.subdomain else 0,
        "has_ip": int(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain))),
        "has_at_symbol": int("@" in url),
        "has_dash": int("-" in domain),
        "has_multiple_slashes": int(url.count("//") > 1),
        "url_entropy": compute_entropy(url),
        "suspicious_tld": is_suspicious_tld(url)
    })

    # WHOIS info
    try:
        whois_info = whois.whois(hostname)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days if isinstance(creation_date, datetime) else -1
        registrar = whois_info.registrar or "unknown"
        country = whois_info.country or "unknown"
    except:
        domain_age = -1
        registrar = "unknown"
        country = "unknown"

    features["domain_age_days"] = domain_age
    features["whois_registrar"] = registrar.lower()
    features["whois_country"] = country.lower()

    # Form tag detection
    features["form_count"] = html_content.lower().count("<form")

    # Keyword detection
    high_risk_count, contextual_count, high_risk_matched, contextual_matched = keyword_analysis(html_content)
    features["high_risk_keyword_count"] = high_risk_count
    features["contextual_keyword_count"] = contextual_count
    features["high_risk_keywords"] = ", ".join(high_risk_matched)
    features["contextual_keywords"] = ", ".join(contextual_matched)

    # Placeholder for favicon match
    features["favicon_match"] = 0

    return features
