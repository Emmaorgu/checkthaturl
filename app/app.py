# app/app.py
import os
import sys
import glob
import math
import re
import base64
import socket
import requests
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse, urlunparse, urljoin, quote_plus

# ------------------------------------------------------------------------------
# Import project modules (works as script or package)
# ------------------------------------------------------------------------------
if __package__ in (None, "",):
    sys.path.insert(0, os.path.dirname(__file__))
    from extract_features import extract_features
    from replay_engine import simulate as simulate_behavior
    from dom_diff import structure_similarity
    try:
        from visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str):
            return {"score": 0.0, "closest": None, "distance": None}
    try:
        from feedback import feedback_bp
    except Exception:
        feedback_bp = None
else:
    from .extract_features import extract_features
    from .replay_engine import simulate as simulate_behavior
    from .dom_diff import structure_similarity
    try:
        from .visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str):
            return {"score": 0.0, "closest": None, "distance": None}
    try:
        from .feedback import feedback_bp
    except Exception:
        feedback_bp = None

# ------------------------------------------------------------------------------
# Flask app
# ------------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)
if feedback_bp:
    app.register_blueprint(feedback_bp)

# ------------------------------------------------------------------------------
# Tunables / policy
# ------------------------------------------------------------------------------
PHISHING_THRESHOLD = 0.70
LEGIT_THRESHOLD    = 0.30
STRICT_SURFACE_GUARD = True
STARTUP_EXCEPTION_GUARD = True
DOMAIN_ONLY_CAN_PHISH = False

CTU_SOFT_WHITELIST_SELF = os.getenv("CTU_SOFT_WHITELIST_SELF", "1") == "1"
OUR_HOSTS = {"checkthaturl.com", "www.checkthaturl.com"}
LOCAL_TEMPLATE_INDEX = os.path.join(os.path.dirname(__file__), "templates", "index.html")

CTU_BEHAVIOR_MODE = os.getenv("CTU_BEHAVIOR_MODE", "auto")

DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

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
# Template/global flags
# ------------------------------------------------------------------------------
@app.context_processor
def inject_flags():
    return {
        "SELF_HOSTED": os.getenv("CTU_SELF_HOSTED", "0") == "1",
        "now": datetime.utcnow().strftime("%Y-%m-%d"),
    }

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _is_our_domain(u: str) -> bool:
    try:
        host = urlparse(u).netloc.split(":")[0].lower()
        return host in OUR_HOSTS
    except Exception:
        return False

def to_http(u: str) -> str:
    p = urlparse(u)
    if p.scheme == "https":
        return urlunparse(("http", p.netloc, p.path, p.params, p.query, p.fragment))
    return u

def resolve_url(raw_url: str | None) -> str | None:
    """Normalize user text to a URL. Prefer https:// and support bare domains/ //host."""
    if not raw_url:
        return None
    u = raw_url.strip()
    if u.startswith(("http://", "https://")):
        return u
    if u.startswith("//"):
        return "https:" + u
    return "https://" + u

def choose_verdict(p_phish: float) -> str:
    if p_phish >= PHISHING_THRESHOLD: return "Phishing"
    if p_phish <= LEGIT_THRESHOLD:    return "Legitimate"
    return "Suspicious"

def align_to_model(df: pd.DataFrame, mdl) -> pd.DataFrame:
    if hasattr(mdl, "feature_names_in_"):
        need = list(mdl.feature_names_in_)
        for c in need:
            if c not in df.columns:
                df[c] = 0.0
        df = df[need]
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df

def clip01(x):
    try:
        return max(0.0, min(1.0, float(x)))
    except Exception:
        return 0.0

DOMAIN_HINTS  = ("domain","whois","tld","dns","registrar","mx","spf","dkim","age","subdomain","punycode","entropy")
CONTENT_HINTS = ("content","text","keyword","phrase","login","form","credential","timer","urgency","brand","logo","tfidf","nlp","password","ocr")
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
    if not (dom or con or lin or beh) and other:
        con, other = other, []
    return dom, con, lin, beh, other

def guarded_verdict(p_phish: float, feats: dict, behavior_score: float = 0.0) -> str:
    base = choose_verdict(p_phish)

    surface = (
        int(feats.get("is_new_domain", 0) == 1) +
        int(feats.get("has_https", 1) == 0) +
        int(feats.get("suspicious_tld", 0) == 1)
    )
    non_surface = int(feats.get("non_surface_red_flags", 0))

    content_sig  = int(feats.get("content_red_flags", 0)) or float(feats.get("phish_context_score", 0)) >= 0.35
    link_sig     = int(feats.get("link_red_flags", 0)) or float(feats.get("mismatched_anchor_ratio", 0)) > 0.30 \
                   or float(feats.get("external_link_ratio", 0)) > 0.50
    behavior_sig = float(behavior_score) >= 0.25

    if not DOMAIN_ONLY_CAN_PHISH and base == "Phishing" and not (content_sig or link_sig or behavior_sig or non_surface):
        return "Suspicious"

    if STRICT_SURFACE_GUARD and base == "Phishing" and non_surface == 0 and surface > 0:
        return "Suspicious" if p_phish >= 0.45 else "Legitimate"

    if STARTUP_EXCEPTION_GUARD and base == "Phishing" and feats.get("startup_like", 0) == 1 \
       and feats.get("is_new_domain", 0) == 1 and non_surface <= 1 and p_phish < 0.85:
        return "Suspicious"

    return base

def compute_category_scores(feats: dict, behavior_score: float) -> dict:
    domain = 0.0
    domain += 0.35 * int(feats.get("suspicious_tld", 0) == 1)
    domain += 0.35 * int(feats.get("is_new_domain", 0) == 1)
    domain += 0.30 * min(1.0, float(feats.get("domain_entropy", 0)) / 4.5)

    link = clip01(int(feats.get("link_red_flags", 0)) / 3.0)

    nlp = float(feats.get("phish_context_score", 0.0))
    content_flags = int(feats.get("content_red_flags", 0))
    content = clip01(0.6 * nlp + 0.4 * (content_flags / 7.0))

    behavior = clip01(behavior_score)

    return {"domain": round(domain, 3), "link": round(link, 3), "content": round(content, 3), "behavior": round(behavior, 3)}

# --------------------------- Diagnostics & utilities --------------------------
KNOWN_SHORTENERS = {"is.gd", "v.gd", "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly"}

def dns_preflight(u: str) -> dict:
    """Resolve host before fetching; tell user if DNS is the problem."""
    try:
        host = urlparse(u).netloc.split(":")[0]
        socket.getaddrinfo(host, 443)
        socket.getaddrinfo(host, 80)
        return {"ok": True, "label": ""}
    except socket.gaierror:
        return {"ok": False, "label": "DNS didn’t resolve (NXDOMAIN)"}
    except Exception:
        return {"ok": False, "label": "DNS error"}

def diag_label_from_exception(e: Exception) -> str:
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection timed out"
    if isinstance(e, requests.exceptions.SSLError):
        return "TLS handshake failed"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "Connection error"
    return "Network error"

def waf_hint(headers: dict, status: int) -> str | None:
    """Best-effort hint about who blocked us (403/401)."""
    if not headers:
        return None
    h = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    if status in (401, 403):
        if "cf-ray" in h or ("server" in h and "cloudflare" in h["server"]):
            return "Blocked by site firewall (Cloudflare)"
        if any("akamai" in v for v in h.values()):
            return "Blocked by site firewall (Akamai)"
        if "x-sucuri-id" in h or "x-sucuri-cache" in h:
            return "Blocked by site firewall (Sucuri)"
    return None

def expand_short_url(u: str) -> str | None:
    """Resolve popular shorteners first (is.gd/v.gd API or single-hop HEAD)."""
    host = urlparse(u).netloc.lower().split(":")[0]
    try:
        if host in {"is.gd", "v.gd"}:
            api = f"https://is.gd/forward.php?format=simple&shorturl={quote_plus(u)}"
            r = requests.get(api, timeout=6)
            if r.ok:
                dst = r.text.strip()
                if dst.startswith(("http://", "https://")):
                    return dst
        r = requests.head(u, allow_redirects=False, timeout=6)
        if 300 <= r.status_code < 400 and "Location" in r.headers:
            dst = r.headers["Location"].strip()
            if dst.startswith(("http://", "https://")):
                return dst
    except requests.RequestException:
        pass
    return None

# ------------------------- Neutral/Unreachable responses ----------------------
def neutral_response(url: str, verdict: str, msg: str, diag: dict | None = None):
    return jsonify({
        "url": url,
        "verdict": verdict,
        "confidence": 0.0,
        "phishing_score": 0.0,
        "legit_score": 0.0,
        "explanation": msg,
        "diagnostic": diag or {},
        "domain_risks": [],
        "content_risks": [],
        "link_risks": [],
        "behavior_risks": [],
        "features_triggered": [],
        "category_scores": {"domain":0,"content":0,"link":0,"behavior":0},
        "explanations": {"domain": [], "link": [], "content": [], "behavior": [], "summary": msg},
        "behavior": {"mode":"disabled","score":0.0,"events":[]},
        "structure": {"score":0.0, "template":None},
        "visual": {"score":0.0, "closest":None},
        "policy": {
            "strict_surface_guard": STRICT_SURFACE_GUARD,
            "startup_exception_guard": STARTUP_EXCEPTION_GUARD,
            "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH
        },
        "startup_like": 0
    }), 200

def unreachable_response(url: str, diag_label: str | None = None):
    return neutral_response(
        url,
        "Unreachable",
        "We couldn’t reach this site (DNS/host/timeout). No phishing verdict given because content wasn’t available.",
        {"label": diag_label} if diag_label else None
    )

# ----------------------------- JS redirect scanners ---------------------------
# Broad patterns (inline & external)
JS_LOCATION_RE = re.compile(
    r"(?:window|document|self|top)?\s*\.?\s*location\.(?:href|assign|replace)\s*=",
    re.I,
)
JS_TIMEOUT_REDIRECT_RE = re.compile(
    r"setTimeout\s*\(\s*function\s*\([^)]*\)\s*{[^}]*location\.(?:href|assign|replace)\s*=",
    re.I | re.S,
)
ATOB_RE = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{12,})['\"]\)", re.I)

def scan_external_scripts_for_redirects(base_url: str, html: str, headers: dict) -> int:
    """
    Fetch up to 3 external scripts (size <= 150 KB each) and scan for redirect patterns.
    Return number of client-side redirect hints found.
    """
    found = 0
    if not html:
        return 0
    try:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        checked = 0
        for src in srcs:
            if checked >= 3:
                break
            js_url = urljoin(base_url, src)
            try:
                jr = requests.get(js_url, timeout=6, headers=headers)
                if not jr.ok:
                    continue
                if int(jr.headers.get("Content-Length", "0") or 0) > 150_000:
                    continue
                js = jr.text or ""
                if JS_LOCATION_RE.search(js) or JS_TIMEOUT_REDIRECT_RE.search(js):
                    found += 1
                else:
                    for m in ATOB_RE.findall(js):
                        try:
                            decoded = base64.b64decode(m + "==").decode("utf-8", "ignore")
                            if decoded.strip().startswith(("http://", "https://")):
                                found += 1
                                break
                        except Exception:
                            pass
                checked += 1
            except requests.RequestException:
                continue
    except Exception:
        pass
    return found

# ------------------------------------------------------------------------------
# API
# ------------------------------------------------------------------------------
@app.route("/check", methods=["POST"])
def check_url():
    try:
        data = request.json or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Normalize & expand shorteners
        url = resolve_url(url)
        if not url:
            return unreachable_response("", "Invalid URL")

        host0 = urlparse(url).netloc.lower().split(":")[0]
        if host0 in KNOWN_SHORTENERS:
            expanded = expand_short_url(url)
            if expanded:
                url = expanded

        # DNS preflight
        pre = dns_preflight(url)
        if not pre.get("ok"):
            return unreachable_response(url, pre.get("label") or "DNS error")

        html_content = ""
        reasons: list[str] = []
        OUR_SCAN = _is_our_domain(url)

        # Self-scan shortcut
        if OUR_SCAN:
            try:
                with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        # Fetch
        r = None
        if not html_content:
            try:
                r = requests.get(url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
                status = r.status_code
            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                if url.startswith("https://"):
                    try:
                        r = requests.get(to_http(url), headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
                        status = r.status_code
                        url = r.url
                    except requests.RequestException:
                        return unreachable_response(url, diag_label_from_exception(e) + " (https and http)")
                else:
                    return unreachable_response(url, diag_label_from_exception(e))
            except requests.RequestException as e:
                return unreachable_response(url, diag_label_from_exception(e))

            if 200 <= status < 300:
                html_content = r.text
                url = r.url
            else:
                label = f"HTTP {status} {r.reason or ''}".strip()
                hint = waf_hint(getattr(r, "headers", {}), status)
                if status in (401, 403):
                    return neutral_response(url, "Blocked",
                        "The site is online but refused automated requests.",
                        {"label": hint or label})
                if status == 404:
                    return neutral_response(url, "Not Found",
                        "The site is online but the page path was not found (HTTP 404).",
                        {"label": "HTTP 404 Not Found"})
                if status == 429:
                    return neutral_response(url, "Rate Limited",
                        "The site is online but rate-limited our request (HTTP 429). Try again later.",
                        {"label": "HTTP 429 Too Many Requests"})
                if 400 <= status < 500:
                    return neutral_response(url, "Blocked",
                        f"The site refused analysis (HTTP {status}).",
                        {"label": label})
                if 500 <= status < 600:
                    return neutral_response(url, "Server Error",
                        f"The site responded with a server error (HTTP {status}).",
                        {"label": label})

        # ---------- Feature extraction ----------
        features = extract_features(url, html_content)
        features.pop("registrar_name", None)

        if OUR_SCAN and CTU_SOFT_WHITELIST_SELF:
            for k in ("is_new_domain", "suspicious_tld"):
                features[k] = 0

        df = align_to_model(pd.DataFrame([features]), model)

        # ---------- Model inference ----------
        proba = model.predict_proba(df)[0]
        p_phish = float(dict(zip(model.classes_, proba)).get(1, 0.0))
        phishing_score = round(p_phish * 100.0, 2)
        legit_score    = round((1.0 - p_phish) * 100.0, 2)
        confidence     = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)

        # ---------- Behavior ----------
        behavior = {"mode": "disabled", "score": 0.0, "events": []}
        try:
            if CTU_BEHAVIOR_MODE != "off":
                behavior = simulate_behavior(url)
        except Exception as e:
            behavior = {"mode": "error", "score": 0.0, "events": [f"behavior engine unavailable: {type(e).__name__}"]}

        # Merge HTTP redirects from requests history
        try:
            if r is not None:
                http_history   = list(getattr(r, "history", []) or [])
                http_redirects = len(http_history)
                http_chain     = [resp.headers.get("Location") or resp.url for resp in http_history] + [r.url]
                if http_redirects > 0:
                    behavior.setdefault("events", [])
                    behavior["http_redirects"] = http_redirects
                    if not behavior.get("redirect_chain"):
                        behavior["redirect_chain"] = http_chain
                    behavior["events"].append(f"↪ HTTP redirect chain length {http_redirects}.")
                # Header-based refresh (rare)
                refresh = (r.headers or {}).get("Refresh") or (r.headers or {}).get("refresh")
                if refresh and re.search(r'url\s*=\s*', refresh, re.I):
                    behavior["client_redirects"] = behavior.get("client_redirects", 0) + 1
                    behavior.setdefault("events", []).append("↪ HTTP Refresh header redirect.")
        except Exception:
            pass

        # Detect client-side redirects in HTML (meta refresh / JS patterns)
        try:
            if html_content:
                # meta refresh (URL or url forms)
                if re.search(r'<meta[^>]+http-equiv=["\']?\s*refresh\s*["\']?[^>]*content=["\']?\s*\d+\s*;\s*url\s*=', html_content, re.I):
                    behavior["client_redirects"] = behavior.get("client_redirects", 0) + 1
                    behavior.setdefault("events", []).append("↪ Meta refresh redirect in HTML.")
                # JS location patterns
                if JS_LOCATION_RE.search(html_content) or JS_TIMEOUT_REDIRECT_RE.search(html_content):
                    behavior["client_redirects"] = behavior.get("client_redirects", 0) + 1
                    behavior.setdefault("events", []).append("↪ JavaScript redirect pattern in HTML.")
                # atob(...) inline
                for m in ATOB_RE.findall(html_content):
                    try:
                        decoded = base64.b64decode(m + "==").decode("utf-8", "ignore")
                        if decoded.strip().startswith(("http://","https://")):
                            behavior["client_redirects"] = behavior.get("client_redirects", 0) + 1
                            behavior.setdefault("events", []).append("↪ Redirect target (decoded from atob) in HTML.")
                            break
                    except Exception:
                        pass
                # external scripts (limited)
                ext_hits = scan_external_scripts_for_redirects(url, html_content, DEFAULT_HEADERS)
                if ext_hits > 0:
                    behavior["client_redirects"] = behavior.get("client_redirects", 0) + ext_hits
                    behavior.setdefault("events", []).append("↪ Redirect pattern found in external script(s).")
        except Exception:
            pass

        behavior_score = float(behavior.get("score", 0.0))

        # ---------- DOM/Visual ----------
        structure = {"score": 0.0, "template": None}
        try:
            structure = structure_similarity(html_content or "")
            if float(structure.get("score", 0.0)) >= 0.85 and structure.get("template"):
                reasons.append(f"🧩 DOM layout highly similar to template '{structure.get('template')}'.")
        except Exception:
            structure = {"score": 0.0, "template": None}

        visual = {"score": 0.0, "closest": None}
        try:
            visual = visual_similarity(url)
            if float(visual.get("score", 0.0)) >= 0.90 and visual.get("closest"):
                reasons.append(f"🖼️ Visual appearance matches known template '{visual.get('closest')}'.")
        except Exception:
            visual = {"score": 0.0, "closest": None}

        # ---------- Score + verdict ----------
        category_scores = compute_category_scores(features, behavior_score)
        verdict = guarded_verdict(p_phish, features, behavior_score)

        human_reasons = []
        if verdict in ("Phishing", "Suspicious"):
            if features.get("suspicious_keyword_found"): human_reasons.append("🔑 Suspicious keywords present.")
            if features.get("suspicious_tld"):           human_reasons.append("🌐 Suspicious TLD.")
            if features.get("domain_entropy", 0) > 4.0:  human_reasons.append("🎲 Domain name has high entropy.")
            if features.get("num_forms", 0) > 0:         human_reasons.append("📝 Form(s) found; potential credential capture.")
            if features.get("has_password_field"):       human_reasons.append("🔒 Password field present.")
            if features.get("keyword_density", 0) > 0.02: human_reasons.append("📌 Elevated phishing keyword density.")
            if features.get("duplicate_phrases", 0) > 1: human_reasons.append("📋 Repeating suspicious phrases.")
            if features.get("mismatched_anchor_ratio", 0) > 0.3: human_reasons.append("🔗 Anchor text vs link mismatch.")
            if features.get("link_density", 0) > 0.4:    human_reasons.append("🌐 Link density is unusually high.")
            if features.get("external_link_ratio", 0) > 0.5: human_reasons.append("🌍 Too many external links.")
            if sum([features.get(f"tfidf_{i}", 0) for i in range(20)]) < 0.1 and not _is_our_domain(url):
                human_reasons.append("📉 Low informational content.")
            if features.get("has_js_timer") or features.get("has_html_timer"):
                human_reasons.append("⏳ Urgency timer detected.")
            if int(behavior.get("post_action_redirects", 0)) > 0:
                human_reasons.append("➡️ Redirect occurred after CTA/form action (behavior).")
            if int(behavior.get("js_redirects_detected", 0)) > 0:
                human_reasons.append("↪ JS-driven redirect detected (behavior).")
            if float(behavior.get("dom_mutation_score", 0)) >= 0.05:
                human_reasons.append("🧪 Significant DOM mutation after load (behavior).")

        domain_risks, content_risks, link_risks, behavior_risks, _ = _group_reasons(human_reasons)

        if verdict in ("Phishing", "Suspicious") and not (domain_risks or content_risks or link_risks or behavior_risks):
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
            else "Looks legitimate based on current checks. We avoid penalizing new/startup sites without other red flags."
        )

        v2_summary = (
            "This site appears mostly safe but shows content/behavior cues associated with phishing. Proceed with caution."
            if ((float(features.get("phish_context_score", 0)) >= 0.35 or behavior_score >= 0.35) and verdict == "Suspicious")
            else ("Low phishing indicators detected." if verdict == "Legitimate" else
                  "Multiple static and behavioral signals consistent with phishing were detected.")
        )

        return jsonify({
            "url": url,
            "verdict": verdict,
            "confidence": confidence,
            "phishing_score": phishing_score,
            "legit_score": legit_score,
            "explanation": explanation,
            "domain_risks": domain_risks,
            "content_risks": content_risks,
            "link_risks": link_risks,
            "behavior_risks": behavior_risks,
            "features_triggered": domain_risks + content_risks + link_risks + behavior_risks,
            "category_scores": category_scores,
            "explanations": {
                "domain": domain_risks,
                "link": link_risks,
                "content": content_risks,
                "behavior": behavior_risks,
                "summary": v2_summary
            },
            "behavior": behavior,
            "structure": structure,
            "visual": visual,
            "policy": {
                "strict_surface_guard": STRICT_SURFACE_GUARD,
                "startup_exception_guard": STARTUP_EXCEPTION_GUARD,
                "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH
            },
            "counters": {
                "surface_flags": int(features.get("is_new_domain", 0) == 1) +
                                 int(features.get("has_https", 1) == 0) +
                                 int(features.get("suspicious_tld", 0) == 1),
                "non_surface_red_flags": int(features.get("non_surface_red_flags", 0))
            },
            "startup_like": int(features.get("startup_like", 0))
        })

    except Exception as e:
        return unreachable_response(
            request.json.get("url") if request.is_json else "",
            f"Scanner error: {type(e).__name__}"
        )

# ------------------------------------------------------------------------------
# Pages
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html")

@app.route("/legal", methods=["GET"])
def legal():
    return render_template("legal.html")

@app.route("/faq", methods=["GET"])
def faq():
    return render_template("faq.html")

# Health/version
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/version", methods=["GET"])
def version():
    return jsonify({
        "model_path": os.path.abspath(MODEL_PATH),
        "server_time_utc": datetime.utcnow().isoformat() + "Z"
    })

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    if not sys.argv or "gunicorn" not in sys.argv[0]:
        app.run(debug=True)
