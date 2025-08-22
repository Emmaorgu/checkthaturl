# app/app.py
import os
import sys
import glob
import math
import socket
import re
import threading
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

# ------------------------------------------------------------------------------
# Flask
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

STRICT_SURFACE_GUARD      = True
STARTUP_EXCEPTION_GUARD   = True
DOMAIN_ONLY_CAN_PHISH     = False

# IMPORTANT: default behavior engine OFF in prod unless explicitly "on"
#   auto  -> try, but we also enforce a hard timeout
#   on    -> try (still with timeout)
#   off   -> skip behavior entirely
CTU_BEHAVIOR_MODE         = os.getenv("CTU_BEHAVIOR_MODE", "off").lower()
CTU_BEHAVIOR_TIMEOUT_SEC  = int(os.getenv("CTU_BEHAVIOR_TIMEOUT_SEC", "8"))

CTU_SOFT_WHITELIST_SELF   = os.getenv("CTU_SOFT_WHITELIST_SELF", "1") == "1"
OUR_HOSTS                 = {"checkthaturl.com", "www.checkthaturl.com"}
LOCAL_TEMPLATE_INDEX      = os.path.join(os.path.dirname(__file__), "templates", "index.html")

STRUCTURE_BENIGN_PREFIXES   = ("ctu_", "benign_", "safe_", "homepage_")
STRUCTURE_IGNORE_TEMPLATES  = {"ctu_home"}

DEFAULT_PSP = (
    "paypal.com,stripe.com,paystack.com,flutterwave.com,interswitchgroup.com,monnify.com,"
    "accounts.google.com,google.com,live.com,microsoftonline.com,apple.com,amazon.com"
)
CTU_TRUSTED_PSP = {d.strip().lower() for d in os.getenv("CTU_TRUSTED_PSP", DEFAULT_PSP).split(",") if d.strip()}

CTU_TRUSTED_DOMAINS = {d.strip().lower() for d in os.getenv("CTU_TRUSTED_DOMAINS", "").split(",") if d.strip()}

CTU_FETCH_LEGAL = os.getenv("CTU_FETCH_LEGAL", "1") == "1"

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
BROWSER_ACCEPT = "text/html,application/xhtml+xml"
BROWSER_LANG = "en,en-NG;q=0.9,en-GB;q=0.8"

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

# --------------------------- Legal probe (robust) --------------
ANCHOR_RE = re.compile(r"<a\b[^>]*href=['\"]([^'\"#]+)['\"][^>]*>(.*?)</a>", re.I | re.S)

LEGAL_GUESS_BASENAMES = [
    "privacy", "privacy-policy", "policy/privacy", "policies/privacy", "legal/privacy",
    "terms", "terms-and-conditions", "terms-of-service", "terms-conditions", "terms_of_use",
    "legal", "legal/terms", "legal/privacy-policy",
    "cookies", "cookie-policy", "policies/cookies", "policy/cookies",
    "policies", "disclosure", "imprint"
]

LEGAL_MAX_TOTAL_CHECKS = 24
LEGAL_PROBE_TIMEOUT = 6

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
    alts = set()
    alts.add(f"{p.scheme}://{host}")
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

def probe_legal_pages(html: str, base_url: str):
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
    for u in norm:
        entry = {"url": u}
        try:
            r = requests.get(u, headers=headers, timeout=LEGAL_PROBE_TIMEOUT, allow_redirects=True)
            entry["status"] = getattr(r, "status_code", None)
            accept = False
            if 200 <= r.status_code < 400:
                accept = _looks_like_policy(r.text, r.url) or _looks_like_policy_url(r.url)
            elif r.status_code in (401, 403) and _looks_like_policy_url(r.url):
                accept = True
            if not accept:
                h = requests.head(u, headers=headers, timeout=LEGAL_PROBE_TIMEOUT, allow_redirects=True)
                entry["head_status"] = getattr(h, "status_code", None)
                if (200 <= h.status_code < 400 or h.status_code in (401,403)) and _looks_like_policy_url(h.url):
                    r2 = requests.get(h.url, headers=headers, timeout=LEGAL_PROBE_TIMEOUT, allow_redirects=True)
                    entry["status2"] = getattr(r2, "status_code", None)
                    if (200 <= r2.status_code < 400 or r2.status_code in (401,403)):
                        accept = True

            if accept:
                good.append(r.url)
                entry["accepted"] = True
                debug["hits"].append(r.url)
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

def _prune_explanations(verdict: str, reasons: list[str], behv: dict) -> list[str]:
    out = []
    has_timer_down = bool(behv.get("timer_decreasing"))
    for r in reasons or []:
        txt = (r or "").lower()
        if ("timer" in txt or "countdown" in txt or "urgency" in txt) and not has_timer_down:
            continue
        if verdict == "Legitimate":
            if any(k in txt for k in ["credential","countdown","urgency","verify now","password","2fa","otp","seed phrase","transfer"]):
                continue
        out.append(r)
    if not out:
        if verdict == "Phishing":     out = ["Multiple high-risk behavioral or content signals observed."]
        elif verdict == "Suspicious": out = ["Some risk signals observed; further checks recommended."]
        else:                          out = ["Low phishing indicators detected."]
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
# Small utility: run a callable with a hard timeout (thread join)
# ------------------------------------------------------------------------------
class _ResultBox:
    __slots__ = ("value","err")
    def __init__(self): self.value=None; self.err=None

def run_with_timeout(fn, timeout_sec: int, *args, **kwargs):
    box = _ResultBox()
    def _target():
        try:
            box.value = fn(*args, **kwargs)
        except Exception as e:
            box.err = e
    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=timeout_sec)
    if t.is_alive():
        return None, TimeoutError(f"operation exceeded {timeout_sec}s")
    if box.err:
        return None, box.err
    return box.value, None

# ------------------------------------------------------------------------------
# API
# ------------------------------------------------------------------------------
@app.route("/check", methods=["POST"])
def check_url():
    try:
        # SAFE JSON PARSE: never let bad JSON bubble into a 500/HTML error
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url: return jsonify({"error": "No URL provided"}), 400

        ui_flag = (request.args.get("ui") or data.get("ui") or "").strip().lower()

        url = resolve_url(url)
        if not url: return jsonify({"error": "Invalid URL"}), 400

        pre = dns_preflight(url)
        if not pre.get("ok"):
            resp = {
                "url": url, "verdict": "Unreachable", "confidence": 0.0,
                "explanation": "We couldn’t reach this site (DNS/host/timeout).",
                "diagnostic": {"label": pre.get("label") or "DNS error"}
            }
            if ui_flag == "redacted":
                resp = redact_ui_payload(resp)
            return jsonify(resp), 200

        html_content = ""
        OUR_SCAN = _is_our_domain(url)
        diag = {}

        if OUR_SCAN:
            try:
                with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        if not html_content:
            headers = {
                "User-Agent": BROWSER_UA,
                "Accept": BROWSER_ACCEPT,
                "Accept-Language": BROWSER_LANG,
                "Connection": "keep-alive",
            }
            try:
                r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                status = r.status_code
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if url.startswith("https://"):
                    try:
                        r = requests.get(to_http(url), headers=headers, timeout=10, allow_redirects=True)
                        status = r.status_code
                        url = r.url
                    except requests.RequestException:
                        resp = {
                            "url": url, "verdict": "Unreachable", "confidence": 0.0,
                            "explanation": "We couldn’t reach this site (TLS/connect error).",
                            "diagnostic": {"label": f"{type(e).__name__} (https and http)"}
                        }
                        if ui_flag == "redacted":
                            resp = redact_ui_payload(resp)
                        return jsonify(resp), 200
                else:
                    resp = {
                        "url": url, "verdict": "Unreachable", "confidence": 0.0,
                        "explanation": "We couldn’t reach this site.",
                        "diagnostic": {"label": f"{type(e).__name__}"}
                    }
                    if ui_flag == "redacted":
                        resp = redact_ui_payload(resp)
                    return jsonify(resp), 200
            except requests.RequestException as e:
                resp = {
                    "url": url, "verdict": "Unreachable", "confidence": 0.0,
                    "explanation": "We couldn’t reach this site.",
                    "diagnostic": {"label": f"{type(e).__name__}"}
                }
                if ui_flag == "redacted":
                    resp = redact_ui_payload(resp)
                return jsonify(resp), 200

            if not (200 <= status < 300):
                diag = {"label": f"HTTP {status} {r.reason or ''}".strip()}
            html_content = r.text or ""
            url = r.url

        # ---------- Feature extraction ----------
        features = extract_features(url, html_content)
        features.pop("registrar_name", None)

        if OUR_SCAN and CTU_SOFT_WHITELIST_SELF:
            for k in ("is_new_domain","suspicious_tld"): features[k] = 0

        timer_fallback = detect_urgency_timer(html_content)
        if not int(features.get("has_js_timer", 0)) and timer_fallback["has_js_timer"]: features["has_js_timer"] = 1
        if not int(features.get("has_html_timer", 0)) and timer_fallback["has_html_timer"]: features["has_html_timer"] = 1
        features["timer_urgency_score"] = max(float(features.get("timer_urgency_score", 0.0)), float(timer_fallback["timer_urgency_score"]))

        legal_probe = probe_legal_pages(html_content, url)
        legal_ok = bool(legal_probe.get("ok"))
        features["legal_pages_ok"] = 1 if legal_ok else 0

        df = align_to_model(pd.DataFrame([features]), model)

        # ---------- Model ----------
        proba = model.predict_proba(df)[0]
        p_phish = float(dict(zip(model.classes_, proba)).get(1, 0.0))
        phishing_score = round(p_phish * 100.0, 2)
        legit_score    = round((1.0 - p_phish) * 100.0, 2)
        confidence     = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)

        # ---------- Behavior (with HARD TIMEOUT) ----------
        behavior = {"mode": "disabled", "score": 0.0, "events": []}
        try:
            if _behavior_enabled():
                # hard timeout wrapper so Render/gunicorn never hangs the request
                result, err = run_with_timeout(simulate_behavior, CTU_BEHAVIOR_TIMEOUT_SEC, url)
                if err or result is None:
                    behavior = {"mode": "timeout", "score": 0.0, "events": [f"behavior_engine_timeout:{CTU_BEHAVIOR_TIMEOUT_SEC}s"]}
                else:
                    behavior = result
        except Exception as e:
            behavior = {"mode": "error", "score": 0.0, "events": [f"behavior engine unavailable: {type(e).__name__}"]}

        behv_full = _behavior_feature_block(behavior)

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
        structure = {"score": 0.0, "template": None}
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

        visual = {"score": 0.0, "closest": None}
        try: visual = visual_similarity(url)
        except Exception: visual = {"score": 0.0, "closest": None}

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

        legal_ok = bool(legal_probe.get("ok"))
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

        # ---------- Reasons ----------
        human_reasons = []
        if verdict in ("Phishing","Suspicious"):
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

            tmpl = (structure.get("template") or "").strip()
            is_benign = bool(tmpl.startswith(STRUCTURE_BENIGN_PREFIXES) or tmpl in STRUCTURE_IGNORE_TEMPLATES)
            if tmpl and float(structure.get("score", 0.0)) >= 0.55 and not is_benign and not legal_ok:
                pct = round(float(structure.get("score", 0.0)) * 100.0, 1)
                human_reasons.append(f"🧩 DOM structure similarity {pct}% to '{tmpl}'.")

        if legal_ok:
            human_reasons.append("✅ Verified legal pages (privacy/terms) present on this site.")

        pruned = _prune_explanations(verdict, human_reasons, behv_for_blend)
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

        v2_summary = (
            "This site appears mostly safe but shows content/behavior cues associated with phishing. Proceed with caution."
            if ((float(features.get("phish_context_score", 0)) >= 0.35 or behavior_score >= 0.35) and verdict == "Suspicious")
            else ("Low phishing indicators detected." if verdict == "Legitimate" else
                  "Multiple static and behavioral signals consistent with phishing were detected.")
        )

        resp = {
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
                "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH,
                "self_domain_behavior_ignored": bool(_is_our_domain(url)),
                "structure_ignore_templates": sorted(STRUCTURE_IGNORE_TEMPLATES),
                "structure_benign_prefixes": STRUCTURE_BENIGN_PREFIXES,
                "trusted_domains": sorted(CTU_TRUSTED_DOMAINS),
                "trusted_psp": sorted(CTU_TRUSTED_PSP),
                "psp_redirects_neutralized": bool(psp_neutral),
                "legal_probe_pages": legal_probe.get("pages", []),
                "legal_probe_debug": legal_probe.get("debug", {})
            },
            "counters": {
                "surface_flags": int(features.get("is_new_domain", 0) == 1) +
                                 int(features.get("has_https", 1) == 0) +
                                 int(features.get("suspicious_tld", 0) == 1),
                "non_surface_red_flags": int(features.get("non_surface_red_flags", 0))
            },
            "startup_like": int(features.get("startup_like", 0))
        }

        if diag: resp["diagnostic"] = diag

        # UI redaction
        if ui_flag == "redacted":
            resp = redact_ui_payload(resp)

        return jsonify(resp)

    except Exception as e:
        # Never leak a 500; always return JSON
        resp = {
            "url": ((request.get_json(silent=True) or {}).get("url") if request.is_json else ""),
            "verdict": "Suspicious",
            "risk": 0.5,
            "confidence": 0.0,
            "explanation": f"Our scanner hit an unexpected error ({type(e).__name__}). Returning a cautious verdict.",
            "error": f"{type(e).__name__}: {e}",
            "domain_risks": [], "content_risks": [], "link_risks": [], "behavior_risks": [],
            "category_scores": {"domain":0,"content":0,"link":0,"behavior":0},
            "behavior": {"mode":"error","score":0.0,"events":[]},
            "structure": {"score":0.0,"template":None},
            "visual": {"score":0.0,"closest":None}
        }
        ui_flag = (request.args.get("ui") or ((request.get_json(silent=True) or {}).get("ui") if request.is_json else "") or "").strip().lower()
        if ui_flag == "redacted":
            resp = redact_ui_payload(resp)
        return jsonify(resp), 200

# ------------------------------------------------------------------------------
# Pages & health
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index(): return render_template("index.html")

@app.route("/privacy", methods=["GET"])
def privacy(): return render_template("privacy.html")

@app.route("/legal", methods=["GET"])
def legal(): return render_template("legal.html")

@app.route("/faq", methods=["GET"])
def faq(): return render_template("faq.html")

@app.route("/health", methods=["GET"])
def health(): return jsonify({"ok": True})

@app.route("/version", methods=["GET"])
def version():
    return jsonify({"model_path": os.path.abspath(MODEL_PATH), "server_time_utc": datetime.utcnow().isoformat() + "Z"})

# ---- API route aliases (for proxying /api/* in production) ----
@app.route("/api/check", methods=["POST"])
def api_check(): return check_url()

@app.route("/api/health", methods=["GET"])
def api_health(): return health()

@app.route("/api/version", methods=["GET"])
def api_version(): return version()

if __name__ == "__main__":
    # In dev you’ll see tracebacks; prod (gunicorn) will ignore this.
    app.run(debug=True)
