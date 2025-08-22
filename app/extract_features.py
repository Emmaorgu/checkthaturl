# app/extract_features.py
import os, re, math, json, base64, socket, requests, joblib, numpy as np
from io import BytesIO
from PIL import Image
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

# --- stop tldextract from downloading in prod ---
import tldextract
_TLD_CACHE = os.environ.get("TLDEXTRACT_CACHE", "/tmp/tldcache")
os.makedirs(_TLD_CACHE, exist_ok=True)
# Disable network updates; force offline PSL
tldextract.extract("example.com", cache_dir=_TLD_CACHE, suffix_list_urls=None)

from sklearn.feature_extraction.text import TfidfVectorizer

# Hybrid NLP scorer (BERT optional, regex fallback)
try:
    from app.hybrid_nlp import get_phish_context_score
except Exception:
    from hybrid_nlp import get_phish_context_score

# Optional deps (graceful fallbacks)
try:
    import pytesseract
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

SELF_HOSTED = os.getenv("CTU_SELF_HOSTED", "0") == "1"
WHOIS_CACHE_PATH = os.getenv(
    "CTU_WHOIS_CACHE",
    os.path.join(os.path.dirname(__file__), "..", "data", "whois_cache.json")
)
SKIP_EXTERNAL_IMAGE_FETCH = SELF_HOSTED

# Playwright (optional)
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

socket.setdefaulttimeout(10)

COMMON_PHRASES_PATH = os.path.join(os.path.dirname(__file__), 'phishing_phrases.json')
VECTORIZER_PATH     = os.path.join(os.path.dirname(__file__), 'tfidf_vectorizer.pkl')

# Vectorizer
if os.path.exists(VECTORIZER_PATH):
    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
    except Exception:
        vectorizer = TfidfVectorizer(stop_words='english', max_features=20, ngram_range=(1, 2))
else:
    vectorizer = TfidfVectorizer(stop_words='english', max_features=20, ngram_range=(1, 2))

# Common phrases
if os.path.exists(COMMON_PHRASES_PATH):
    try:
        with open(COMMON_PHRASES_PATH, 'r', encoding='utf-8') as f:
            COMMON_PHRASES = json.load(f) or []
    except Exception:
        COMMON_PHRASES = []
else:
    COMMON_PHRASES = []

PHISHING_KEYWORDS = [
    "you have won a prize","your account will be suspended","immediate action required",
    "tax refund pending","temporary disruption","exclusive offer","win","good news",
    "you have been selected","withdraw my cash","bvn","quick loan","urgent","gift",
    "verification","payment","discount","your account has been hacked",
    "start your application","enter your account number","dear valued member",
    "free","get my money now","accept grants","fast payment","click to continue",
    "select below","claim the grant funds"
]

STARTUP_TLDS = (".io",".app",".dev",".ai",".page",".site")
STARTUP_LANDING_PHRASES = [
    "coming soon","beta access","waitlist","join the waitlist",
    "early access","launching soon","we're hiring","careers","subscribe for updates"
]
HOSTED_PLATFORM_FOOTPRINTS = [
    "cdn.shopify.com","myshopify.com","checkout.shopify.com",
    "static.wixstatic.com","wixsite.com","squarespace.com",
    "stripe.com","js.stripe.com","paypalobjects.com"
]

def detect_js_timer(html: str) -> int:
    html = html or ""
    pats = [r"setTimeout\s*\(", r"setInterval\s*\(", r"new\s+Date\s*\(",
            r"Date\.now\s*\(", r"countdown\s*\(", r"\.getTime\s*\("]
    return int(any(re.search(p, html, re.I) for p in pats))

def detect_html_timer_elements(html: str) -> int:
    html = html or ""
    pats = [
        r'id=["\']?(countdown|timer)["\']?', r'class=["\']?(countdown|timer)["\']?',
        r"\d{1,2}:\d{2}(:\d{2})?", r"(only\s+\d+\s+(seconds?|minutes?)\s+left)", r"(hurry\s*up|expires\s+in)"
    ]
    return int(any(re.search(p, html, re.I) for p in pats))

def entropy(s: str) -> float:
    if not s: return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p*math.log(p, 2) for p in probs)

# Fetchers
def fetch_html_requests(url: str, timeout: int = 10) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, timeout=timeout, headers=headers)
        res.raise_for_status()
        return res.text
    except Exception:
        return ""

def fetch_html_playwright(url: str, timeout: int = 10000) -> str:
    if not PLAYWRIGHT_AVAILABLE: return ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=timeout)
            html = page.content()
            browser.close()
            return html
    except Exception:
        return ""

def get_domain_info(url: str):
    parsed = urlparse(url)
    ext = tldextract.extract(url)  # offline PSL used
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {"domain": registered, "subdomain": ext.subdomain, "path": parsed.path,
            "scheme": parsed.scheme, "netloc": parsed.netloc}

def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()

_whois_cache = None
def _load_whois_cache():
    global _whois_cache
    if _whois_cache is not None: return _whois_cache
    _whois_cache = {}
    try:
        if WHOIS_CACHE_PATH and os.path.exists(WHOIS_CACHE_PATH):
            with open(WHOIS_CACHE_PATH, "r", encoding="utf-8") as f:
                _whois_cache = json.load(f) or {}
    except Exception:
        _whois_cache = {}
    return _whois_cache

def _whois_from_cache(domain: str):
    cache = _load_whois_cache()
    return cache.get(domain) or cache.get(domain.lower())

def extract_whois_features(url: str) -> dict:
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    out = {"domain_age_days": 0, "registrar_name": "", "is_new_domain": 0}

    if SELF_HOSTED:
        entry = _whois_from_cache(domain)
        if not entry: return out
        try:
            creation_str = entry.get("creation_date")
            registrar = entry.get("registrar") or ""
            if creation_str:
                c = datetime.fromisoformat(creation_str.replace("Z","+00:00"))
                age = (datetime.utcnow() - c.replace(tzinfo=None)).days
                out["domain_age_days"] = max(age, 0)
                out["is_new_domain"] = int(age < 30)
            if registrar: out["registrar_name"] = str(registrar)
        except Exception: pass
        return out

    if not WHOIS_AVAILABLE: return out
    try:
        w = whois.whois(domain)
        creation = None
        if hasattr(w, "creation_date"):
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if creation:
            try:
                c = creation
                if isinstance(c, str): c = datetime.fromisoformat(c.replace("Z","+00:00"))
                if getattr(c, "tzinfo", None) is not None: c = c.astimezone(tz=None).replace(tzinfo=None)
                age = (datetime.utcnow() - c).days
                out["domain_age_days"] = max(age, 0)
                out["is_new_domain"] = int(age < 30)
            except Exception: pass
        if getattr(w, "registrar", None):
            out["registrar_name"] = str(w.registrar)
    except Exception:
        pass
    return out

def extract_features(url: str, html_content: str | None = None) -> dict:
    if html_content is None:
        html_content = fetch_html_requests(url)
        if not html_content and PLAYWRIGHT_AVAILABLE:
            html_content = fetch_html_playwright(url)

    feats = {}
    di = get_domain_info(url)
    domain = di["domain"]

    feats["url_length"] = len(url)
    feats["num_dots"] = url.count(".")
    feats["has_https"] = int(url.startswith("https://"))
    feats["suspicious_tld"] = int(domain.endswith((".xyz",".top",".loan",".gq")))
    feats["domain_length"] = len(domain)
    feats["domain_entropy"] = round(entropy(domain), 4)
    feats["startup_like_tld"] = int(any(domain.endswith(tld) for tld in STARTUP_TLDS))

    soup = BeautifulSoup(html_content or "", "html.parser")
    text = normalize_text(soup.get_text(separator=" ", strip=True))
    word_count = len(text.split()) or 1

    feats["phish_context_score"] = round(float(get_phish_context_score(text)), 4)
    feats["startup_landing_copy"] = int(any(p in text for p in STARTUP_LANDING_PHRASES))
    html_low = (html_content or "").lower()
    feats["hosted_platform_fp"] = int(any(fp in html_low for fp in HOSTED_PLATFORM_FOOTPRINTS))

    keyword_count = sum(text.count(kw) for kw in PHISHING_KEYWORDS)
    feats["keyword_density"] = round(keyword_count / word_count, 4)
    feats["suspicious_keyword_found"] = int(keyword_count > 0)

    inputs = soup.find_all("input")
    forms = soup.find_all("form")
    password_field = any("password" in (i.get("type") or "") for i in inputs)
    suspicious_keywords = ["login","verify","secure","account"]
    form_suspicious = any(any(kw in (frm.get_text(strip=True).lower()) for kw in suspicious_keywords) for frm in forms)
    feats["has_password_field"] = int(password_field)
    feats["form_with_suspicious_keywords"] = int(form_suspicious)
    feats["num_forms"] = len(forms)
    feats["num_inputs"] = len(inputs)

    try:
        tfidf_vector = vectorizer.transform([text]).toarray().flatten()
    except Exception:
        tfidf_vector = np.zeros(getattr(vectorizer, "max_features", 20))
    for i, val in enumerate(tfidf_vector):
        feats[f"tfidf_{i}"] = round(float(val), 5)

    feats["duplicate_phrases"] = sum(1 for phrase in COMMON_PHRASES if text.count(phrase.lower()) > 1)

    anchors = soup.find_all("a")
    total_anchors = len(anchors)
    external_links = sum(1 for a in anchors if a.get("href") and domain not in a.get("href"))
    mismatched_links = sum(1 for a in anchors if a.get("href") and a.get_text().strip().lower() not in (a.get("href","").lower()))
    feats["link_density"] = round(total_anchors / word_count, 4)
    feats["external_link_ratio"] = round(external_links / total_anchors, 4) if total_anchors else 0
    feats["mismatched_anchor_ratio"] = round(mismatched_links / total_anchors, 4) if total_anchors else 0

    feats["has_js_timer"] = detect_js_timer(html_content or "")
    feats["has_html_timer"] = detect_html_timer_elements(html_content or "")
    feats["timer_urgency_score"] = feats["has_js_timer"] + feats["has_html_timer"]

    feats.update({
        "large_suspicious_image": 0,
        "base64_image_detected": 0,
        "ocr_alert_text_detected": 0,
        "alert_image_followed_by_form_or_link": 0,
    })
    if OCR_AVAILABLE:
        suspicious_img_keywords = ["credit alert","₦","bvn","debit","payment","congratulations"]
        for img in soup.find_all("img"):
            src = img.get("src", "")
            if not src: continue
            try:
                img_bytes = None
                if "base64," in src:
                    feats["base64_image_detected"] = 1
                    img_bytes = base64.b64decode(src.split("base64,")[-1])
                elif src.startswith("http"):
                    if SKIP_EXTERNAL_IMAGE_FETCH: continue
                    img_bytes = requests.get(src, timeout=5).content
                else:
                    continue
                image = Image.open(BytesIO(img_bytes))
                w, h = image.size
                if w > 200 and h > 100: feats["large_suspicious_image"] = 1
                try:
                    ocr_txt = (pytesseract.image_to_string(image) or "").lower()
                    if any(kw in ocr_txt for kw in suspicious_img_keywords):
                        feats["ocr_alert_text_detected"] = 1
                except Exception:
                    pass
            except Exception:
                continue
            parent = img.find_parent()
            if parent and (parent.find("form") or parent.find("a")):
                feats["alert_image_followed_by_form_or_link"] = 1

    feats.update(extract_whois_features(url))

    content_flags = 0; link_flags = 0
    content_flags += int(feats.get("suspicious_keyword_found", 0) == 1)
    content_flags += int(feats.get("has_password_field", 0) == 1)
    content_flags += int(feats.get("form_with_suspicious_keywords", 0) == 1)
    content_flags += int(feats.get("keyword_density", 0) > 0.02)
    content_flags += int(feats.get("duplicate_phrases", 0) > 1)
    content_flags += int(feats.get("has_js_timer", 0) == 1 or feats.get("has_html_timer", 0) == 1)
    content_flags += int(feats.get("ocr_alert_text_detected", 0) == 1)

    link_flags += int(feats.get("mismatched_anchor_ratio", 0) > 0.6)
    link_flags += int(feats.get("link_density", 0) > 0.8)
    link_flags += int(feats.get("external_link_ratio", 0) > 0.8)

    feats["content_red_flags"] = content_flags
    feats["link_red_flags"] = link_flags
    feats["non_surface_red_flags"] = content_flags + link_flags
    feats["startup_like"] = int(
        feats.get("startup_like_tld", 0) == 1 or
        feats.get("startup_landing_copy", 0) == 1 or
        feats.get("hosted_platform_fp", 0) == 1
    )
    return feats

def safe_extract(url: str, label: str) -> dict | None:
    try:
        d = extract_features(url); d["label"] = label; return d
    except Exception as e:
        print(f"[✗] Failed to extract from {url}: {e}"); return None
