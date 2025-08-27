# app/app.py
import os
import sys
import time
import glob
import math
import socket
import re
import requests
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse, urlunparse, urljoin

# ------------------------------------------------------------------------------
# Flexible imports (works as `python -m app.app` or `python app/app.py`)
# ------------------------------------------------------------------------------
if __package__ in (None, "",):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from app.extract_features import extract_features
    from app.replay_engine import simulate as simulate_behavior
    from app.dom_diff import structure_similarity
    from app.policy_utils import (
        guarded_verdict, compute_category_scores, detect_urgency_timer, clip01
    )
    try:
        from app.visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str):
            return {"score": 0.0, "closest": None, "distance": None}
    try:
        from app.feedback import feedback_bp
    except Exception:
        feedback_bp = None
else:
    from .extract_features import extract_features
    from .replay_engine import simulate as simulate_behavior
    from .dom_diff import structure_similarity
    from .policy_utils import (
        guarded_verdict, compute_category_scores, detect_urgency_timer, clip01
    )
    try:
        from .visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str):
            return {"score": 0.0, "closest": None, "distance": None}
    try:
        from .feedback import feedback_bp
    except Exception:
        feedback_bp = None


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Prefer ./app/templates if it exists (your layout), otherwise fallback to ./templates
CANDIDATE_TEMPLATES = [
    os.path.join(BASE_DIR, "templates"),
    os.path.join(BASE_DIR, "app", "templates"),
    os.path.join(os.path.dirname(BASE_DIR), "app", "templates"),
]
for p in CANDIDATE_TEMPLATES:
    if os.path.exists(os.path.join(p, "index.html")):
        TEMPLATE_DIR = p
        break
else:
    TEMPLATE_DIR = CANDIDATE_TEMPLATES[0]

# Static directory detection
CANDIDATE_STATIC = [
    os.path.join(BASE_DIR, "static"),
    os.path.join(BASE_DIR, "app", "static"),
    os.path.join(os.path.dirname(BASE_DIR), "app", "static"),
]
for p in CANDIDATE_STATIC:
    if os.path.exists(p):
        STATIC_DIR = p
        break
else:
    STATIC_DIR = CANDIDATE_STATIC[0]

# ------------------------------------------------------------------------------
# Flask
# ------------------------------------------------------------------------------
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)
if feedback_bp:
    app.register_blueprint(feedback_bp)

# ------------------------------------------------------------------------------
# Tunables / policy
# ------------------------------------------------------------------------------
PHISHING_THRESHOLD = float(os.getenv("PHISHING_THRESHOLD", "0.70"))
LEGIT_THRESHOLD    = float(os.getenv("LEGIT_THRESHOLD", "0.30"))

STRICT_SURFACE_GUARD      = os.getenv("STRICT_SURFACE_GUARD", "1") not in {"0","false","no"}
STARTUP_EXCEPTION_GUARD   = os.getenv("STARTUP_EXCEPTION_GUARD", "1") not in {"0","false","no"}
DOMAIN_ONLY_CAN_PHISH     = os.getenv("DOMAIN_ONLY_CAN_PHISH", "0") in {"1","true","yes"}

CTU_BEHAVIOR_MODE         = os.getenv("CTU_BEHAVIOR_MODE", "auto").lower()
CTU_SOFT_WHITELIST_SELF   = os.getenv("CTU_SOFT_WHITELIST_SELF", "1") == "1"
OUR_HOSTS                 = {"checkthaturl.com", "www.checkthaturl.com"}

# Networking budgets (override via env if needed)
CONNECT_TIMEOUT = float(os.getenv("CTU_CONNECT_TIMEOUT", "2.0"))
READ_TIMEOUT    = float(os.getenv("CTU_READ_TIMEOUT", "3.0"))
REQUEST_BUDGET  = float(os.getenv("CTU_REQUEST_BUDGET", "18.0"))   # whole /check request
LEGAL_BUDGET    = float(os.getenv("CTU_LEGAL_PROBE_BUDGET", "4.0"))
BEHAVIOR_BUDGET = float(os.getenv("CTU_BEHAVIOR_BUDGET", "6.0"))   # if behavior is enabled

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
BROWSER_ACCEPT = "text/html,application/xhtml+xml"
BROWSER_LANG = "en,en-NG;q=0.9,en-GB;q=0.8"

DEFAULT_PSP = (
    "paypal.com,stripe.com,paystack.com,flutterwave.com,interswitchgroup.com,monnify.com,"
    "accounts.google.com,google.com,live.com,microsoftonline.com,apple.com,amazon.com"
)
CTU_TRUSTED_PSP = {d.strip().lower() for d in os.getenv("CTU_TRUSTED_PSP", DEFAULT_PSP).split(",") if d.strip()}
CTU_TRUSTED_DOMAINS = {d.strip().lower() for d in os.getenv("CTU_TRUSTED_DOMAINS", "").split(",") if d.strip()}
CTU_FETCH_LEGAL = os.getenv("CTU_FETCH_LEGAL", "1") == "1"

# Files
LOCAL_TEMPLATE_INDEX = os.path.join(os.path.dirname(__file__), "templates", "index.html")
STRUCTURE_BENIGN_PREFIXES   = ("ctu_", "benign_", "safe_", "homepage_")
STRUCTURE_IGNORE_TEMPLATES  = {"ctu_home"}

# ------------------------------------------------------------------------------
# Requests session (fail-fast, small retries)
# ------------------------------------------------------------------------------
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def _make_session():
    s = requests.Session()
    retry = Retry(
        total=1, connect=1, read=0, backoff_factor=0.2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["HEAD","GET"])
    )
    s.mount("http://", HTTPAdapter(max_retries=retry, pool_maxsize=32))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=32))
    s.headers.update({"User-Agent": "CheckThatURL/1.0 (+https://www.checkthaturl.com/bot)"})
    return s

SESSION = _make_session()

def _safe_req(method, url, *, timeout=None, allow_redirects=True, headers=None):
    try:
        return SESSION.request(
            method, url,
            timeout=timeout or (CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=allow_redirects,
            headers=headers or {},
            stream=False,
        )
    except Exception:
        return None

# ------------------------------------------------------------------------------
# Model
# ------------------------------------------------------------------------------
def _latest_model_path():
    model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model'))
    versioned = glob.glob(os.path.join(model_dir, "phish_rf_model_*.pkl"))

    def ts(fp):
        from datetime import datetime as _dt
        base = os.path.basename(fp).replace("phish_rf_model_", "").replace(".pkl", "")
        try:
            return _dt.strptime(base, "%Y%m%d_%H%M%S")
        except ValueError:
            return _dt.min

    if versioned:
        latest = max(versioned, key=ts)
        print(f"[INFO] Loaded latest model: {os.path.basename(latest)}")
        return latest

    fallback = os.path.join(model_dir, "phish_rf_model.pkl")
    print("[WARN] No versioned model found. Falling back to:", os.path.basename(fallback))
    return fallback

MODEL_PATH = _latest_model_path()
model = joblib.load(MODEL_PATH)

# ------------------------------------------------------------------------------
# Jinja globals
# ------------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    now = datetime.utcnow()
    return {"year": now.year, "now": now.strftime("%Y-%m-%d")}

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _host(u: str) -> str:
    try: return urlparse(u).netloc.split(":")[0].lower()
    except Exception: return ""

def _registrable_domain(u: str) -> str:
    try:
        h = _host(u)
        parts = h.split(".")
        if len(parts) < 2: return h
        last2, last3 = ".".join(parts[-2:]), ".".join(parts[-3:])
        MULTI = ("co.uk","org.uk","gov.uk","ac.uk","com.au","net.au","org.au","com.br","com.mx","com.tr","com.ng","co.jp")
        if any(last3.endswith(t) for t in MULTI) and len(parts) >= 3: return last3
        return last2
    except Exception:
        return ""

def _is_our_domain(u: str) -> bool:
    try: return _host(u) in OUR_HOSTS
    except Exception: return False

def to_http(u: str) -> str:
    p = urlparse(u)
    return urlunparse(("http", p.netloc, p.path, p.params, p.query, p.fragment)) if p.scheme == "https" else u

def resolve_url(raw_url: str | None) -> str | None:
    if not raw_url: return None
    u = raw_url.strip()
    if u.startswith(("http://","https://")): return u
    if u.startswith("//"): return "https:" + u
    return "https://" + u

def choose_verdict(p_phish: float) -> str:
    if p_phish >= PHISHING_THRESHOLD: return "Phishing"
    if p_phish <= LEGIT_THRESHOLD:    return "Legitimate"
    return "Suspicious"

def align_to_model(df: pd.DataFrame, mdl) -> pd.DataFrame:
    if hasattr(mdl, "feature_names_in_"):
        need = list(mdl.feature_names_in_)
        for c in need:
            if c not in df.columns: df[c] = 0.0
        df = df[need]
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]): df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df

# --------------------------- Diagnostics ----------------------
def dns_preflight(u: str) -> dict:
    try:
        host = urlparse(u).netloc.split(":")[0]
        socket.getaddrinfo(host, 443)
        socket.getaddrinfo(host, 80)
        return {"ok": True, "label": ""}
    except socket.gaierror:
        return {"ok": False, "label": "DNS didn’t resolve (NXDOMAIN)"}
    except Exception:
        return {"ok": False, "label": "DNS error"}

# --------------------------- Legal probe (with time budget) ---
ANCHOR_RE = re.compile(r"<a\b[^>]*href=[\'\"]([^\'\"#]+)[\'\"][^>]*>(.*?)</a>", re.I | re.S)

LEGAL_GUESS_BASENAMES = [
    "privacy", "privacy-policy", "policy/privacy", "policies/privacy", "legal/privacy",
    "terms", "terms-and-conditions", "terms-of-service", "terms-conditions", "terms_of_use",
    "legal", "legal/terms", "legal/privacy-policy",
    "cookies", "cookie-policy", "policies/cookies", "policy/cookies",
    "policies", "disclosure", "imprint"
]

LEGAL_MAX_TOTAL_CHECKS = 24

def _looks_like_policy_url(u: str) -> bool:
    low = (u or "").lower()
    return any(k in low for k in ("privacy", "terms", "cookie", "policy", "legal", "imprint"))

def _looks_like_policy(html: str, u: str = "") -> bool:
    low = (html or "").lower()
    wc = len(re.findall(r"\w+", low))
    has_priv = ("privacy" in low and "policy" in low)
    has_terms = ("terms" in low and ("conditions" in low or "service" in low or "use" in low))
    has_cookies = ("cookie" in low and "policy" in low)
    has_legal = ("legal" in low and ("agreement" in low or "notice" in low or "imprint" in low))
    if wc >= 180 and (has_priv or has_terms or has_cookies or has_legal):
        return True
    if _looks_like_policy_url(u) and wc >= 20:
        return True
    if wc >= 60 and sum([has_priv, has_terms, has_cookies, has_legal]) >= 2:
        return True
    return False

def _find_footer_legal_links(html: str, base_url: str) -> list[str]:
    if not html:
        return []
    out = []
    for href, inner in ANCHOR_RE.findall(html):
        text = re.sub(r"<[^>]+>", "", inner or "").strip().lower()
        if any(k in text for k in ("privacy","terms","conditions","policy","cookies","legal","imprint")):
            absu = urljoin(base_url, href)
            if _registrable_domain(absu) == _registrable_domain(base_url):
                out.append(absu)
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq

_COUNTRY_HINTS = {
    "nigeria": "ng",
    "united kingdom": "uk",
    "united states": "us",
    "ghana": "gh",
    "kenya": "ke",
}

def _locale_prefixes_from_html(html: str) -> list[str]:
    prefs = set()
    for m in re.findall(r'href=["\']\/([a-z]{2})(?:\/|["\'])', html or "", flags=re.I):
        prefs.add(m.lower())
    low = (html or "").lower()
    for k, cc in _COUNTRY_HINTS.items():
        if k in low:
            prefs.add(cc)
    for extra in ("en", "en-ng", "ng-en"):
        prefs.add(extra)
    return [""] + sorted(prefs)

def _origin_variants(base_url: str) -> list[str]:
    p = urlparse(base_url)
    host = p.netloc.split(":")[0]
    alts = {f"{p.scheme}://{host}"}
    if host.startswith("www."):
        alts.add(f"{p.scheme}://{host[4:]}")
    else:
        alts.add(f"{p.scheme}://www.{host}")
    return sorted(alts)

def _legal_headers(referer: str) -> dict:
    return {
        "User-Agent": BROWSER_UA,
        "Accept": BROWSER_ACCEPT,
        "Accept-Language": BROWSER_LANG,
        "Referer": referer,
        "Connection": "keep-alive",
    }

def probe_legal_pages(html: str, base_url: str, *, time_left=lambda: 1.0):
    debug = {"candidates": [], "hits": [], "prefixes": [], "origins": []}
    if not CTU_FETCH_LEGAL:
        return {"ok": 0, "pages": [], "debug": debug}

    candidates = _find_footer_legal_links(html, base_url)
    prefixes = _locale_prefixes_from_html(html)
    origins = _origin_variants(base_url)
    debug["prefixes"] = prefixes
    debug["origins"] = origins

    for origin in origins:
        for pre in prefixes:
            pre = pre.strip("/")
            for base_name in LEGAL_GUESS_BASENAMES:
                base_name = base_name.strip("/")
                path = f"/{pre}/{base_name}" if pre else f"/{base_name}"
                candidates.append(origin + path)

    reg = _registrable_domain(base_url)
    norm, seen = [], set()
    for u in candidates:
        if _registrable_domain(u) != reg:
            continue
        if u not in seen:
            seen.add(u); norm.append(u)

    norm = norm[:LEGAL_MAX_TOTAL_CHECKS]
    headers = _legal_headers(base_url)
    good = []
    spent = 0.0
    start = time.monotonic()

    for u in norm:
        if time_left() <= 0 or (spent >= LEGAL_BUDGET):
            break
        entry = {"url": u}
        try:
            r = _safe_req("GET", u, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True, headers=headers)
            spent = time.monotonic() - start
            entry["status"] = getattr(r, "status_code", None)
            accept = False
            if r and 200 <= r.status_code < 400:
                accept = _looks_like_policy(r.text or "", getattr(r, "url", u)) or _looks_like_policy_url(getattr(r, "url", u))
            elif r and r.status_code in (401, 403) and _looks_like_policy_url(getattr(r, "url", u)):
                accept = True
            if not accept and time_left() > 0 and spent < LEGAL_BUDGET:
                h = _safe_req("HEAD", u, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True, headers=headers)
                entry["head_status"] = getattr(h, "status_code", None)
                if h and (200 <= h.status_code < 400 or h.status_code in (401,403)) and _looks_like_policy_url(getattr(h, "url", u)):
                    r2 = _safe_req("GET", getattr(h, "url", u), timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True, headers=headers)
                    entry["status2"] = getattr(r2, "status_code", None)
                    if r2 and (200 <= r2.status_code < 400 or r2.status_code in (401,403)):
                        accept = True
            if accept:
                good.append(getattr(r, "url", u))
                entry["accepted"] = True
                debug["hits"].append(getattr(r, "url", u))
        except Exception as e:
            entry["error"] = type(e).__name__
        debug["candidates"].append(entry)

    return {"ok": 1 if good else 0, "pages": good, "debug": debug}

# --------------------------- Behavior helpers -----------------
def _behavior_enabled() -> bool:
    return CTU_BEHAVIOR_MODE not in {"off","disabled","0","false"}

def _behavior_feature_block(b: dict) -> dict:
    events = b.get("events") or []
    js_cross  = int(b.get("js_redirects_cross_site") or b.get("js_redirects_detected") or 0)
    client_cross = int(b.get("client_redirects_cross_site") or b.get("client_redirects") or 0)
    post_form = int(b.get("post_action_redirects_form") or 0)
    return {
        "score": float(b.get("score") or 0.0),
        "dom_mutation": float(b.get("dom_mutation_score") or 0.0),
        "js_redirects": js_cross,
        "client_redirects": client_cross,
        "post_redirects": post_form,
        "timer_decreasing": 1 if ("timer_decreasing_confirmed" in events) else 0,
        "timer_hint": 1 if ("timer_hint_detected" in events) else 0,
    }

def _blend_risk(model_prob_phish: float, behv: dict) -> float:
    bp = float(behv.get("score") or 0.0)
    bonus = 0.0
    if behv.get("timer_decreasing"): bonus += 0.08
    soft_redirs = behv.get("js_redirects", 0) + behv.get("client_redirects", 0)
    if soft_redirs >= 1: bonus += min(0.08, 0.04 * soft_redirs)
    if behv.get("post_redirects", 0) >= 1: bonus += 0.10
    if (behv.get("dom_mutation") or 0.0) > 0.6: bonus += 0.04
    base = 0.80 * float(model_prob_phish) + 0.20 * bp
    return clip01(base + bonus)

def _prune_explanations(verdict: str, reasons: list[str], behv: dict, timer_hint_present: bool = False) -> list[str]:
    """
    Keep timer/urgency reasons if *any* hint exists (markup, NLP, or behavior).
    Do not inject fallback reasons for Legitimate.
    """
    out = []
    for r in reasons or []:
        txt = (r or "").lower()
        # Only drop timer-ish text if there were no timer hints at all
        if ("timer" in txt or "countdown" in txt or "urgency" in txt) and not timer_hint_present:
            continue
        if verdict == "Legitimate":
            if any(k in txt for k in ["credential","countdown","urgency","verify now","password","2fa","otp","seed phrase","transfer"]):
                continue
        out.append(r)

    if not out:
        if verdict == "Phishing":
            out = ["Multiple high-risk behavioral or content signals observed."]
        elif verdict == "Suspicious":
            out = ["Some risk signals observed; further checks recommended."]
        else:
            out = []  # Legitimate => no grouped reasons
    return out

# ------------------------------------------------------------------------------
# UI redaction helpers
# ------------------------------------------------------------------------------
LEGAL_SENTENCE_RE = re.compile(
    r'\b(legal\s*pages?|privacy(?:\s+policy| policies)?|terms(?:\s*&\s*conditions| of service| and conditions)?)\b',
    re.IGNORECASE
)

def _redact_explanation(text: str) -> str:
    if not text:
        return text
    parts = re.split(r'(?<=[\.\!\?])\s+', text)
    parts = [s for s in parts if not LEGAL_SENTENCE_RE.search(s)]
    return " ".join(parts).strip()

def _redact_list(items):
    if not isinstance(items, list):
        return items
    return [x for x in items if not LEGAL_SENTENCE_RE.search(str(x or ""))]

def redact_ui_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return payload
    p = dict(payload)

    if "explanation" in p:
        p["explanation"] = _redact_explanation(p["explanation"])

    for key in ("domain_risks", "content_risks", "link_risks", "behavior_risks"):
        if key in p:
            p[key] = _redact_list(p.get(key))

    pol = p.get("policy")
    if isinstance(pol, dict):
        pol = dict(pol)
        pol.pop("legal_probe_pages", None)
        p["policy"] = pol

    return p

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html") if os.path.exists(os.path.join(app.template_folder or "templates", "privacy.html")) else ("<h1>Privacy</h1>", 200)

@app.route("/legal")
def legal():
    return render_template("legal.html") if os.path.exists(os.path.join(app.template_folder or "templates", "legal.html")) else ("<h1>Legal</h1>", 200)

@app.route("/faq")
def faq():
    return render_template("faq.html") if os.path.exists(os.path.join(app.template_folder or "templates", "faq.html")) else ("<h1>FAQ</h1>", 200)

@app.get("/healthz")
def healthz():
    return "ok", 200

@app.get("/diag")
def diag():
    import platform, sys, pkgutil, json, os
    from playwright.sync_api import __version__ as pwv
    info = {
        "python": sys.version,
        "platform": platform.platform(),
        "playwright": pwv,
        "scan_mode": os.getenv("SCAN_MODE"),
        "headless": os.getenv("HEADLESS"),
        "timeout_secs": os.getenv("REQUEST_TIMEOUT_SECS"),
        "installed": sorted([m.name for m in pkgutil.iter_modules() if m.name in ("playwright","pandas","sklearn","xgboost","bs4","tldextract")])
    }
    return json.dumps(info), 200, {"Content-Type":"application/json"}

# ------------------------------------------------------------------------------
# API
# ------------------------------------------------------------------------------
@app.route("/check", methods=["POST"])
def check_url():
    start = time.monotonic()
    def time_left():
        return REQUEST_BUDGET - (time.monotonic() - start)

    def ensure_reason_groups(payload: dict) -> dict:
        """
        Guarantee at least one grouped reason for any non-legitimate verdict.
        (Used for partial timeouts and unreachable paths as well.)
        """
        p = dict(payload or {})
        verdict = p.get("verdict") or "Suspicious"
        if verdict == "Legitimate":
            return p
        # Normalize lists
        for k in ("domain_risks","content_risks","link_risks","behavior_risks"):
            if k not in p or not isinstance(p[k], list):
                p[k] = []
        # If all empty, add an operational/diagnostic reason
        if not (p["domain_risks"] or p["content_risks"] or p["link_risks"] or p["behavior_risks"]):
            status = (p.get("status") or "").lower()
            if status in ("partial","timeout"):
                p["behavior_risks"].append("⏱ Partial result: some checks timed out/cancelled, live analysis incomplete.")
            elif verdict == "Unreachable":
                p["domain_risks"].append("🔌 Site unreachable (DNS/host/timeout) — could not verify content.")
            else:
                p["content_risks"].append("⚠ Risk signalled by model; no single factor dominated.")
        return p

    def out_partial(payload, msg="Timed out - partial checks only"):
        payload = dict(payload)
        payload.setdefault("ok", True)
        payload["status"] = "partial"
        payload.setdefault("message", msg)
        # Ensure grouped reasons for non-legit partials
        payload.setdefault("verdict", "Suspicious")
        payload = ensure_reason_groups(payload)
        return payload

    try:
        data = request.json or {}
        raw = (data.get("url") or "").strip()
        if not raw: return jsonify({"ok": False, "message": "No URL provided"}), 400

        ui_flag = (request.args.get("ui") or data.get("ui") or "").strip().lower()
        url = resolve_url(raw)
        if not url: return jsonify({"ok": False, "message": "Invalid URL"}), 400

        pre = dns_preflight(url)
        if not pre.get("ok"):
            resp = {
                "ok": True, "status": "ok",
                "url": url, "verdict": "Unreachable", "risk": 0.0, "confidence": 0.0,
                "explanation": "We couldn’t reach this site (DNS/host/timeout).",
                "diagnostic": {"label": pre.get("label") or "DNS error"},
                "domain_risks": ["🔌 Site unreachable (DNS/host/timeout) — could not verify content."],
                "content_risks": [], "link_risks": [], "behavior_risks": []
            }
            if ui_flag == "redacted": resp = redact_ui_payload(resp)
            app.logger.info("SCAN status=unreachable reason=dns label=%s url=%s", pre.get("label"), url)
            return jsonify(resp), 200

        # ---------- Fetch page (fast-fail, http fallback) ----------
        html_content = ""
        fetch_error = None

        if _is_our_domain(url):
            try:
                with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": BROWSER_ACCEPT,
            "Accept-Language": BROWSER_LANG,
            "Connection": "keep-alive",
        }

        def _try_get(u, c_to, r_to, ua=None):
            try:
                h = dict(headers)
                if ua: h["User-Agent"] = ua
                return _safe_req("GET", u, timeout=(c_to, r_to), allow_redirects=True, headers=h)
            except Exception as e:
                return None

        if not html_content:
            # 1st attempt (current small timeouts)
            r = _try_get(url, CONNECT_TIMEOUT, READ_TIMEOUT)

            # Retry with longer timeouts if first attempt failed
            if not r and time_left() > 0.5:
                r = _try_get(url, max(6.0, CONNECT_TIMEOUT), max(8.0, READ_TIMEOUT),
                             ua=BROWSER_UA.replace("Chrome/124.0", "Chrome/122.0"))

            # Fallback to http:// if https failed to connect at all
            if not r and url.startswith("https://"):
                r = _try_get(to_http(url), max(6.0, CONNECT_TIMEOUT), max(8.0, READ_TIMEOUT))

            # If still nothing, try a lightweight Playwright rescue (short budget)
            if not r and time_left() > 3.0:
                try:
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as p:
                        browser = p.chromium.launch(headless=True, args=[
                            "--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"
                        ])
                        ctx = browser.new_context(user_agent=BROWSER_UA, ignore_https_errors=True)
                        page = ctx.new_page()
                        page.goto(url, timeout=int(min(15000, max(3000, time_left() * 1000))))
                        html_content = page.content()
                        url = page.url
                        ctx.close();
                        browser.close()
                except Exception as e:
                    fetch_error = f"playwright:{type(e).__name__}"

            if r:
                html_content = r.text or ""
                url = r.url

            # If we reached the server but got non-2xx or empty body, don’t call it unreachable—return partial with reasons
            if (r and (r.status_code >= 400 or not (html_content or "").strip())) and not html_content:
                resp = {
                    "ok": True, "status": "partial", "url": url, "verdict": "Suspicious",
                    "risk": 0.4, "confidence": 40.0,
                    "explanation": "Fetched the site but response was not OK (non-2xx or empty).",
                    "domain_risks": [f"HTTP {r.status_code} while fetching."],
                    "content_risks": [], "link_risks": [],
                    "behavior_risks": ["⏱ Live checks limited due to response quality."]
                }
                if ui_flag == "redacted": resp = redact_ui_payload(resp)
                app.logger.info("SCAN status=partial reason=http_%s url=%s", r.status_code, url)
                return jsonify(resp), 200

            # Total failure → label as partial instead of unreachable, with a clear diagnostic
            if not (html_content or "").strip():
                diag_label = "connect_error"
                if fetch_error: diag_label = fetch_error
                resp = {
                    "ok": True, "status": "partial", "url": url, "verdict": "Suspicious",
                    "risk": 0.35, "confidence": 35.0,
                    "explanation": "Network fetch was unreliable; returning partial checks instead of Unreachable.",
                    "diagnostic": {"label": diag_label},
                    "domain_risks": ["🔌 Fetch instability — could not reliably retrieve content within budget."],
                    "content_risks": [], "link_risks": [], "behavior_risks": []
                }
                if ui_flag == "redacted": resp = redact_ui_payload(resp)
                app.logger.info("SCAN status=partial reason=%s url=%s", diag_label, url)
                return jsonify(resp), 200

        # ---------- Feature extraction ----------
        features = extract_features(url, html_content)
        features.pop("registrar_name", None)

        if _is_our_domain(url) and CTU_SOFT_WHITELIST_SELF:
            for k in ("is_new_domain","suspicious_tld"): features[k] = 0

        # Timer fallback (markup/NLP hints even when behavior is off)
        timer_fallback = detect_urgency_timer(html_content)
        if not int(features.get("has_js_timer", 0)) and timer_fallback["has_js_timer"]: features["has_js_timer"] = 1
        if not int(features.get("has_html_timer", 0)) and timer_fallback["has_html_timer"]: features["has_html_timer"] = 1
        features["timer_urgency_score"] = max(float(features.get("timer_urgency_score", 0.0)),
                                              float(timer_fallback["timer_urgency_score"]))

        # ---------- Legal probe (budgeted) ----------
        legal_probe = {"ok": 0, "pages": []}
        if time_left() > 0.2:
            legal_probe = probe_legal_pages(html_content, url, time_left=time_left)
        legal_ok = bool(legal_probe.get("ok"))
        features["legal_pages_ok"] = 1 if legal_ok else 0

        # ---------- Model ----------
        df = align_to_model(pd.DataFrame([features]), model)
        proba = model.predict_proba(df)[0]
        p_phish = float(dict(zip(model.classes_, proba)).get(1, 0.0))
        phishing_score = round(p_phish * 100.0, 2)
        legit_score    = round((1.0 - p_phish) * 100.0, 2)
        confidence     = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)

        # ---------- Behavior (optional, budgeted) ----------
        behavior = {"mode": "disabled", "score": 0.0, "events": []}
        if _behavior_enabled() and time_left() > 0.5:
            try:
                t0 = time.monotonic()
                behavior = simulate_behavior(url)
                behavior["elapsed_sec"] = round(time.monotonic() - t0, 3)
            except Exception as e:
                behavior = {"mode": "error", "score": 0.0, "events": [f"behavior engine unavailable: {type(e).__name__}"]}

        behv_full = _behavior_feature_block(behavior)

        # Neutralize PSP redirects
        chain = behavior.get("redirect_chain") or []
        cross_targets = []
        for i in range(len(chain) - 1):
            a, b = chain[i], chain[i+1]
            if _registrable_domain(a) != _registrable_domain(b):
                cross_targets.append(_registrable_domain(b))
        psp_neutral = bool(cross_targets) and all(d in CTU_TRUSTED_PSP for d in cross_targets)

        behv_for_blend = dict(behv_full)
        if psp_neutral:
            behv_for_blend["js_redirects"] = 0
            behv_for_blend["client_redirects"] = 0

        if _is_our_domain(url):
            behv_for_blend.update({
                "score": 0.0, "dom_mutation": 0.0, "js_redirects": 0,
                "client_redirects": 0, "post_redirects": 0, "timer_decreasing": 0, "timer_hint": 0
            })

        behavior_score = float(behv_for_blend.get("score", 0.0))

        # ---------- Structure & Visual ----------
        structure_guard = "none"
        try:
            structure = structure_similarity(html_content or "")
            s = float(structure.get("score", 0.0))
            tmpl = (structure.get("template") or "").strip()
            is_benign = bool(tmpl.startswith(STRUCTURE_BENIGN_PREFIXES) or tmpl in STRUCTURE_IGNORE_TEMPLATES)
            if s >= 0.55 and tmpl and not (_is_our_domain(url) or is_benign):
                structure_guard = "high" if s >= 0.75 else "medium"
                features["non_surface_red_flags"] = int(features.get("non_surface_red_flags", 0)) + 1
        except Exception:
            structure = {"score": 0.0, "template": None}

        try:
            visual = visual_similarity(url)
        except Exception:
            visual = {"score": 0.0, "closest": None}

        # ---------- Risk / Verdict ----------
        blended_risk = _blend_risk(p_phish, behv_for_blend)
        verdict = choose_verdict(blended_risk)
        category_scores = compute_category_scores(features, behavior_score)

        if not DOMAIN_ONLY_CAN_PHISH:
            non_surface = int(features.get("non_surface_red_flags", 0))
            link_sig = (
                int(features.get("link_red_flags", 0)) or
                float(features.get("mismatched_anchor_ratio", 0)) > 0.30 or
                float(features.get("external_link_ratio", 0)) > 0.65
            )
            content_sig = int(features.get("content_red_flags", 0)) or float(features.get("phish_context_score", 0)) >= 0.35
            behavior_sig = float(behavior_score) >= 0.25
            if verdict == "Phishing" and not (content_sig or link_sig or behavior_sig or non_surface):
                verdict = "Suspicious"

        if STRICT_SURFACE_GUARD and verdict == "Phishing" and int(features.get("non_surface_red_flags", 0)) == 0:
            verdict = "Suspicious" if blended_risk >= 0.45 else "Legitimate"

        if STARTUP_EXCEPTION_GUARD and verdict == "Phishing" \
           and features.get("startup_like", 0) == 1 and features.get("is_new_domain", 0) == 1 \
           and int(features.get("non_surface_red_flags", 0)) <= 1 and blended_risk < 0.85:
            verdict = "Suspicious"

        hard_content = (
            int(features.get("has_password_field", 0)) == 1 or
            float(features.get("phish_context_score", 0.0)) >= 0.45 or
            float(features.get("timer_urgency_score", 0.0)) >= 0.45 or
            behv_for_blend.get("timer_decreasing", 0) == 1 or
            int(behavior.get("post_action_redirects_form", 0)) >= 1
        )

        if legal_ok and not hard_content and (len((behavior.get("redirect_chain") or [])) <= 1) and int(features.get("suspicious_tld", 0)) == 0:
            verdict = "Legitimate"
            blended_risk = min(blended_risk, 0.25)

        if verdict == "Legitimate" and (structure_guard in ("medium","high")) and not legal_ok:
            verdict = "Suspicious"
        if verdict == "Suspicious" and structure_guard == "high" and hard_content:
            verdict = "Phishing"

        reg = _registrable_domain(url)
        if reg in CTU_TRUSTED_DOMAINS and verdict == "Phishing" and not hard_content:
            verdict = "Suspicious"

        if _is_our_domain(url) and not hard_content:
            verdict = "Legitimate"
            blended_risk = min(blended_risk, 0.30)

        # ---------- Reasons (restored timers/http) ----------
        human_reasons = []

        if verdict in ("Phishing","Suspicious"):
            # HTTP (no TLS)
            if int(features.get("has_https", 1)) == 0:
                human_reasons.append("🔓 Connection not secure (HTTP).")

            if features.get("suspicious_keyword_found"): human_reasons.append("🔑 Suspicious keywords present.")
            if features.get("suspicious_tld"):           human_reasons.append("🌐 Suspicious TLD.")
            if features.get("domain_entropy", 0) > 4.0:  human_reasons.append("🎲 Domain name has high entropy.")
            if features.get("has_password_field"):
                human_reasons.append("🔒 Password field present (possible credential capture).")
            elif features.get("num_forms", 0) > 0 and verdict != "Legitimate":
                human_reasons.append("📝 Form(s) present (likely contact/newsletter).")
            if features.get("keyword_density", 0) > 0.02: human_reasons.append("📌 Elevated phishing keyword density.")
            if features.get("duplicate_phrases", 0) > 1:  human_reasons.append("📋 Repeating suspicious phrases.")
            if float(features.get("mismatched_anchor_ratio", 0)) > 0.3: human_reasons.append("🔗 Anchor text vs link mismatch.")
            if float(features.get("external_link_ratio", 0)) > 0.65 and not _is_our_domain(url):
                human_reasons.append("🌍 Many external links.")

            # Markup/NLP timer hints (no behavior engine required)
            if int(features.get("has_html_timer", 0)) == 1 or int(features.get("has_js_timer", 0)) == 1:
                human_reasons.append("⏱ Timer/countdown present in page markup.")
            if float(features.get("timer_urgency_score", 0.0)) >= 0.25:
                human_reasons.append("⚠ Urgency language / timer hints detected in content.")

            # Behavior-based signals (live)
            chain = behavior.get("redirect_chain") or []
            cross_soft_count = max(0, len(chain) - 1)
            cross_targets = []
            for i in range(len(chain) - 1):
                a, b = chain[i], chain[i+1]
                if _registrable_domain(a) != _registrable_domain(b):
                    cross_targets.append(_registrable_domain(b))
            psp_neutral = bool(cross_targets) and all(d in CTU_TRUSTED_PSP for d in cross_targets)

            if cross_soft_count > 0 and not psp_neutral:
                human_reasons.append("↪ Client/JS-driven redirect to a different site (behavior).")
            if int(behavior.get("post_action_redirects_form", 0)) > 0:
                human_reasons.append("➡️ Redirect occurred after form submission (behavior).")
            if behv_for_blend.get("timer_decreasing"):
                human_reasons.append("⏳ Decreasing countdown timer detected (behavior).")
            if float(behavior.get("dom_mutation_score", 0)) >= 0.10:
                human_reasons.append("🧪 Significant DOM mutation after load (behavior).")

            # Structure similarity
            tmpl = (structure.get("template") or "").strip()
            is_benign = bool(tmpl.startswith(STRUCTURE_BENIGN_PREFIXES) or tmpl in STRUCTURE_IGNORE_TEMPLATES)
            if tmpl and float(structure.get("score", 0.0)) >= 0.55 and not is_benign and not legal_ok:
                pct = round(float(structure.get("score", 0.0)) * 100.0, 1)
                human_reasons.append(f"🧩 DOM structure similarity {pct}% to '{tmpl}'.")

        if legal_ok:
            human_reasons.append("✅ Verified legal pages (privacy/terms) present on this site.")

        # Consider *any* timer hint (markup, NLP, or behavior) as grounds to keep timer reasons
        timer_hint_present = (
            int(features.get("has_html_timer", 0)) == 1 or
            int(features.get("has_js_timer", 0)) == 1 or
            float(features.get("timer_urgency_score", 0.0)) >= 0.2 or
            behv_for_blend.get("timer_decreasing") == 1 or
            behv_for_blend.get("timer_hint") == 1
        )

        pruned = _prune_explanations(verdict, human_reasons, behv_for_blend, timer_hint_present=timer_hint_present)

        DOMAIN_HINTS  = ("domain","whois","tld","dns","registrar","mx","spf","dkim","age","subdomain","punycode","entropy")
        CONTENT_HINTS = ("content","text","keyword","phrase","login","form","credential","timer","urgency","brand","logo","tfidf","nlp","password","ocr","policy","terms")
        LINK_HINTS    = ("link","url","redirect","anchor","href","shortener","bit.ly","t.co","utm_","outbound","mismatch")
        BEHAV_HINTS   = ("redirect","cta","mutation","hidden","sandbox","behavior","post-action")

        def _group_reasons(reasons):
            dom, con, lin, beh, other = [], [], [], [], []
            for r in reasons or []:
                low = str(r).lower()
                if   any(h in low for h in DOMAIN_HINTS):  dom.append(r)
                elif any(h in low for h in CONTENT_HINTS): con.append(r)
                elif any(h in low for h in LINK_HINTS):    lin.append(r)
                elif any(h in low for h in BEHAV_HINTS):   beh.append(r)
                else:                                      other.append(r)
            if not (dom or con or lin or beh) and other: con, other = other, []
            return dom, con, lin, beh, other

        domain_risks, content_risks, link_risks, behavior_risks, _ = _group_reasons(pruned)

        if verdict in ("Phishing","Suspicious") and not (domain_risks or content_risks or link_risks or behavior_risks):
            if features.get("is_new_domain"):          domain_risks.append("🆕 Recently-registered domain.")
            if features.get("suspicious_tld"):         domain_risks.append("🌐 Suspicious/rare TLD.")
            if features.get("domain_entropy", 0) > 4:  domain_risks.append("🎲 Unnatural/complex domain pattern.")
            if float(features.get("phish_context_score", 0)) >= 0.35:
                content_risks.append("🧠 NLP flagged phishing-like phrasing.")
            if not (domain_risks or content_risks or link_risks or behavior_risks):
                domain_risks.append("⚠ Model confidence came primarily from domain-only signals; content/link/behavior had no red flags.")

        summary_bits = []
        if features.get("startup_like"):                 summary_bits.append("startup-like pattern detected")
        if features.get("is_new_domain"):                summary_bits.append("young domain")
        if features.get("non_surface_red_flags", 0) > 0: summary_bits.append(f"{int(features.get('non_surface_red_flags', 0))} non-surface signal(s)")
        if behavior_score >= 0.35:                       summary_bits.append("dynamic behavior observed")
        summary_tail = (" • " + ", ".join(summary_bits)) if summary_bits else ""
        explanation = (
            f"{confidence}% confidence • {verdict}{summary_tail}. See grouped risk signals below."
            if verdict != "Legitimate"
            else "Looks legitimate based on current checks. We verified legal pages and avoided penalizing internal navigation."
        )

        resp = {
            "ok": True,
            "status": "ok",
            "url": url,
            "verdict": verdict,
            "risk": round(blended_risk, 3),
            "confidence": confidence,
            "phishing_score": phishing_score,
            "legit_score": legit_score,
            "explanation": explanation,
            "domain_risks": domain_risks,
            "content_risks": content_risks,
            "link_risks": link_risks,
            "behavior_risks": behavior_risks,
            "category_scores": category_scores,
            "behavior": behavior,
            "structure": structure,
            "visual": visual,
            "policy": {
                "strict_surface_guard": STRICT_SURFACE_GUARD,
                "startup_exception_guard": STARTUP_EXCEPTION_GUARD,
                "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH,
                "self_domain_behavior_ignored": bool(_is_our_domain(url)),
                "structure_ignore_templates": sorted(STRUCTURE_IGNORE_TEMPLATES),
                "structure_benign_prefixes": STRUCTURE_BENIGN_PREFIXES,
                "trusted_domains": sorted(CTU_TRUSTED_DOMAINS),
                "trusted_psp": sorted(CTU_TRUSTED_PSP),
                "psp_redirects_neutralized": bool(psp_neutral),
                "legal_probe_pages": legal_probe.get("pages", []),
            },
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }

        if time_left() <= 0:
            resp = out_partial(resp)

        # Last-line guard: ALWAYS provide grouped reasons for non-legit
        resp = ensure_reason_groups(resp)

        if ui_flag == "redacted":
            resp = redact_ui_payload(resp)

        # ---------- Observability: single structured log line ----------
        app.logger.info(
            "SCAN verdict=%s risk=%.3f conf=%.1f http=%s struct=%s beh=%.2f psp_neutral=%s legal=%s url=%s",
            resp.get("verdict"), resp.get("risk"), resp.get("confidence"),
            resp.get("behavior", {}).get("http_status", None),
            resp.get("structure", {}).get("template", None),
            float(behavior_score),
            bool(psp_neutral), bool(legal_ok),
            resp.get("url"),
        )

        return jsonify(resp), 200

    except Exception as e:
        # Keep message for UI and leave room for frontend fallback group reasons
        app.logger.exception("SCAN fatal error: %s", e)
        return jsonify({"ok": False, "status": "error", "message": f"{type(e).__name__}: {e}"}), 200

# --- Hard self-tests to verify Playwright/behavior in PROD ---

@app.get("/selftest/playwright")
def selftest_playwright():
    """
    Launch Chromium with safe flags and load a simple page.
    If this fails in Render, your behavior engine can't run.
    """
    try:
        from playwright.sync_api import sync_playwright
        t0 = time.monotonic()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                    "--disable-web-security",
                    "--no-first-run",
                    "--no-zygote",
                    "--single-process",
                ],
            )
            ctx = browser.new_context(ignore_https_errors=True, user_agent=BROWSER_UA, locale="en-GB")
            page = ctx.new_page()
            page.set_default_timeout(30000)
            page.goto("https://example.com", wait_until="load")
            title = page.title()
            final_url = page.url
            browser.close()
        return jsonify({
            "ok": True,
            "elapsed_ms": int((time.monotonic()-t0)*1000),
            "title": title,
            "final_url": final_url,
            "note": "If ok==True here, Chromium can launch in prod."
        }), 200
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 200


@app.get("/selftest/behavior")
def selftest_behavior():
    """
    Run your simulate_behavior() on a known redirect; report what it saw.
    """
    try:
        t0 = time.monotonic()
        test_url = "https://httpbin.org/redirect-to?url=https://example.com"
        b = simulate_behavior(test_url)  # uses your replay_engine
        b["elapsed_ms"] = int((time.monotonic()-t0)*1000)
        return jsonify({"ok": True, "behavior": b}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
