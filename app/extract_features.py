import os
import re
import math
import json
import base64
import socket
import requests
import joblib
import tldextract
import numpy as np

from io import BytesIO
from PIL import Image
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
import pytesseract
import whois
from datetime import datetime

# === Playwright (optional, for JS-heavy sites) ===
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# === Set global socket timeout ===
socket.setdefaulttimeout(10)

# === Config paths ===
COMMON_PHRASES_PATH = os.path.join(os.path.dirname(__file__), 'phishing_phrases.json')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'tfidf_vectorizer.pkl')

# === Load vectorizer ===
if os.path.exists(VECTORIZER_PATH):
    vectorizer = joblib.load(VECTORIZER_PATH)
else:
    vectorizer = TfidfVectorizer(stop_words='english', max_features=20, ngram_range=(1, 2))

# === Load common phrases ===
if os.path.exists(COMMON_PHRASES_PATH):
    with open(COMMON_PHRASES_PATH, 'r', encoding='utf-8') as f:
        COMMON_PHRASES = json.load(f)
else:
    COMMON_PHRASES = []

# === Keywords ===
PHISHING_KEYWORDS = [
    "you have won a prize", "your account will be suspended", "immediate action required",
    "tax refund pending", "temporary disruption", "exclusive offer", "win", "good news",
    "you have been selected", "withdraw my cash", "bvn", "quick loan", "urgent", "gift",
    "verification", "payment", "discount", "your account has been hacked",
    "start your application", "enter your account number", "dear valued member",
    "free", "get my money now", "accept grants", "fast payment", "click to continue",
    "select below", "claim the grant funds"
]

# === New Countdown Timer Detection ===
def detect_js_timer(html_content):
    js_patterns = [
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"new\s+Date\s*\(",
        r"Date\.now\s*\(",
        r"countdown\s*\(",
        r"\.getTime\s*\(",
    ]
    return int(any(re.search(p, html_content, re.IGNORECASE) for p in js_patterns))

def detect_html_timer_elements(html_content):
    patterns = [
        r'id=["\']?(countdown|timer)["\']?',
        r'class=["\']?(countdown|timer)["\']?',
        r"\d{1,2}:\d{2}(:\d{2})?",  # 00:59 or 00:59:59
        r"(only\s+\d+\s+(seconds?|minutes?)\s+left)",
        r"(hurry\s*up|expires\s+in)",
    ]
    return int(any(re.search(p, html_content, re.IGNORECASE) for p in patterns))


def entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])


def get_domain_info(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {
        'domain': domain,
        'subdomain': ext.subdomain,
        'path': parsed.path,
        'scheme': parsed.scheme,
        'netloc': parsed.netloc
    }


def normalize_text(text):
    return re.sub(r'\s+', ' ', text).strip().lower()


def fetch_html_requests(url, timeout=10):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, timeout=timeout, headers=headers)
        res.raise_for_status()
        return res.text
    except Exception as e:
        print(f"[Requests Error] {e}")
        return ""


def fetch_html_playwright(url, timeout=10000):
    if not PLAYWRIGHT_AVAILABLE:
        return ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=timeout)
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        print(f"[Playwright Error] {e}")
        return ""


def extract_whois_features(url):
    domain = urlparse(url).netloc
    features = {
        'domain_age_days': 0,
        'registrar_name': '',
        'is_new_domain': 0
    }
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.utcnow() - creation).days
            features['domain_age_days'] = age_days
            features['is_new_domain'] = int(age_days < 30)
        if w.registrar:
            features['registrar_name'] = w.registrar
    except Exception:
        pass
    return features


def extract_features(url, html_content=None):
    if html_content is None:
        html_content = fetch_html_requests(url)
        if not html_content and PLAYWRIGHT_AVAILABLE:
            print("[!] Falling back to Playwright.")
            html_content = fetch_html_playwright(url)

    features = {}
    domain_info = get_domain_info(url)
    domain = domain_info['domain']

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_https'] = int(url.startswith('https://'))
    features['suspicious_tld'] = int(domain.endswith(('.xyz', '.top', '.loan', '.gq')))
    features['domain_length'] = len(domain)
    features['domain_entropy'] = round(entropy(domain), 4)

    soup = BeautifulSoup(html_content, 'html.parser')
    text = normalize_text(soup.get_text(separator=' ', strip=True))
    word_count = len(text.split()) or 1

    keyword_count = sum(text.count(kw) for kw in PHISHING_KEYWORDS)
    features['keyword_density'] = round(keyword_count / word_count, 4)
    features['suspicious_keyword_found'] = int(keyword_count > 0)

    inputs = soup.find_all('input')
    forms = soup.find_all('form')
    password_field = any('password' in (i.get('type') or '') for i in inputs)
    suspicious_keywords = ['login', 'verify', 'secure', 'account']
    form_suspicious = any(any(kw in form.get_text(strip=True).lower() for kw in suspicious_keywords) for form in forms)

    features['has_password_field'] = int(password_field)
    features['form_with_suspicious_keywords'] = int(form_suspicious)
    features['num_forms'] = len(forms)
    features['num_inputs'] = len(inputs)

    try:
        tfidf_vector = vectorizer.transform([text]).toarray().flatten()
    except Exception:
        tfidf_vector = np.zeros(vectorizer.max_features)

    for i, val in enumerate(tfidf_vector):
        features[f'tfidf_{i}'] = round(val, 5)

    features['duplicate_phrases'] = sum(1 for phrase in COMMON_PHRASES if text.count(phrase.lower()) > 1)

    anchors = soup.find_all('a')
    total_anchors = len(anchors)
    external_links = sum(1 for a in anchors if a.get('href') and domain not in a.get('href'))
    mismatched_links = sum(1 for a in anchors if a.get('href') and a.get_text().strip().lower() not in a.get('href', '').lower())

    features['link_density'] = round(total_anchors / word_count, 4)
    features['external_link_ratio'] = round(external_links / total_anchors, 4) if total_anchors else 0
    features['mismatched_anchor_ratio'] = round(mismatched_links / total_anchors, 4) if total_anchors else 0

    # === New Countdown Timer Features ===
    features["has_js_timer"] = detect_js_timer(html_content)
    features["has_html_timer"] = detect_html_timer_elements(html_content)
    features["timer_urgency_score"] = features["has_js_timer"] + features["has_html_timer"]

    # === OCR on images ===
    features.update({
        'large_suspicious_image': 0,
        'base64_image_detected': 0,
        'ocr_alert_text_detected': 0,
        'alert_image_followed_by_form_or_link': 0
    })

    suspicious_img_keywords = ['credit alert', '₦', 'bvn', 'debit', 'payment', 'congratulations']
    images = soup.find_all('img')

    for img in images:
        src = img.get('src', '')
        if not src:
            continue
        try:
            if 'base64,' in src:
                features['base64_image_detected'] = 1
                img_data = base64.b64decode(src.split('base64,')[-1])
            elif src.startswith('http'):
                img_data = requests.get(src, timeout=5).content
            else:
                continue

            image = Image.open(BytesIO(img_data))
            width, height = image.size
            if width > 200 and height > 100:
                features['large_suspicious_image'] = 1

            ocr_txt = pytesseract.image_to_string(image).lower()
            if any(kw in ocr_txt for kw in suspicious_img_keywords):
                features['ocr_alert_text_detected'] = 1

        except Exception:
            continue

        parent = img.find_parent()
        if parent and (parent.find('form') or parent.find('a')):
            features['alert_image_followed_by_form_or_link'] = 1

    features.update(extract_whois_features(url))
    return features


def safe_extract(url, label):
    try:
        features = extract_features(url)
        features['label'] = label
        return features
    except Exception as e:
        print(f"[✗] Failed to extract from {url}: {e}")
        return None
