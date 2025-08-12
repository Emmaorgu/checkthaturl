# app/app.py
import os
import sys
import glob
import math
import re
import socket
from datetime import datetime
from urllib.parse import urlparse, urlunparse, quote_plus

import joblib
import pandas as pd
import requests
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

# ------------------------------------------------------------------------------
# Local imports (work both as script and package)
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
PHISHING_THRESHOLD = 0.70   # >= -> Phishing
LEGIT_THRESHOLD    = 0.30   # <= -> Legitimate
STRICT_SURFACE_GUARD = True
STARTUP_EXCEPTION_GUARD = True
DOMAIN_ONLY_CAN_PHISH = False  # domain-only signals won't produce "Phishing"

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

# Short URL services we can expand
KNOWN_SHORTENERS = {"is.gd", "v.gd", "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly"}

# ------------------------------------------------------------------------------
# Model loading
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
# Template flags
# ------------------------------------------------------------------------------
@app.context_processor
def inject_flags():
    return {"SELF_HOSTED": os.getenv("CTU_SELF_HOSTED", "0") == "1",
            "now": datetime.utcnow().strftime("%Y-%m-%d")}

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _is_our_domain(u: str) -> bool:
    try:
        host = urlparse(u).netloc.split(":")[0].lower()
        return host in OUR_HOSTS
    except Exception:
        return False

def resolve_url(raw_url: str | None) -> str | None:
    if not raw_url:
        return None
    u = raw_url.strip()
    if u.startswith(("http://","https://")):
        return u
    if u.startswith("//"):
        return "https:" + u
    return "https://" + u

def to_http(u: str) -> str:
    p = urlparse(u)
    return urlunparse(("http", p.netloc, p.path, p.params, p.query, p.fragment)) if p.scheme=="https" else u

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
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df

def clip01(x):
    try: return max(0.0, min(1.0, float(x)))
    except Exception: return 0.0

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
    if not (dom or con or lin or beh) and other: con, other = other, []
    return dom, con, lin, beh, other

def guarded_verdict(p_phish: float, feats: dict, behavior_score: float = 0.0) -> str:
    base = choose_verdict(p_phish)
    surface = (int(feats.get("is_new_domain",0)==1) +
               int(feats.get("has_https",1)==0) +
               int(feats.get("suspicious_tld",0)==1))
    non_surface = int(feats.get("non_surface_red_flags",0))
    content_sig  = int(feats.get("content_red_flags",0)) or float(feats.get("phish_context_score",0))>=0.35
    link_sig     = int(feats.get("link_red_flags",0)) or float(feats.get("mismatched_anchor_ratio",0))>0.30 \
                   or float(feats.get("external_link_ratio",0))>0.50
    behavior_sig = float(behavior_score)>=0.25

    if not DOMAIN_ONLY_CAN_PHISH and base=="Phishing" and not (content_sig or link_sig or behavior_sig or non_surface):
        return "Suspicious"
    if STRICT_SURFACE_GUARD and base=="Phishing" and non_surface==0 and surface>0:
        return "Suspicious" if p_phish>=0.45 else "Legitimate"
    if STARTUP_EXCEPTION_GUARD and base=="Phishing" and feats.get("startup_like",0)==1 \
       and feats.get("is_new_domain",0)==1 and non_surface<=1 and p_phish<0.85:
        return "Suspicious"
    return base

def compute_category_scores(feats: dict, behavior_score: float) -> dict:
    domain = 0.0
    domain += 0.35 * int(feats.get("suspicious_tld",0)==1)
    domain += 0.35 * int(feats.get("is_new_domain",0)==1)
    domain += 0.30 * min(1.0, float(feats.get("domain_entropy",0))/4.5)

    link = clip01(int(feats.get("link_red_flags",0))/3.0)

    nlp = float(feats.get("phish_context_score",0.0))
    content_flags = int(feats.get("content_red_flags",0))
    content = clip01(0.6*nlp + 0.4*(content_flags/7.0))

    behavior = clip01(behavior_score)

    return {"domain": round(domain,3), "link": round(link,3),
            "content": round(content,3), "behavior": round(behavior,3)}

# ---------- Shorteners ----------
def expand_short_url(u: str) -> str | None:
    host = urlparse(u).netloc.lower().split(":")[0]
    try:
        if host in {"is.gd","v.gd"}:
            api = f"https://is.gd/forward.php?format=simple&shorturl={quote_plus(u)}"
            r = requests.get(api, timeout=6)
            if r.ok:
                dst = (r.text or "").strip()
                if dst.startswith(("http://","https://")):
                    return dst
        r = requests.head(u, allow_redirects=False, timeout=6)
        if 300 <= r.status_code < 400 and "Location" in r.headers:
            dst = r.headers["Location"].strip()
            if dst.startswith(("http://","https://")):
                return dst
    except requests.RequestException:
        pass
    return None

# ---------- Diagnostics ----------
def dns_preflight(u: str) -> dict:
    try:
        host = urlparse(u).netloc.split(":")[0]
        socket.getaddrinfo(host, 443); socket.getaddrinfo(host, 80)
        return {"ok": True, "label": ""}
    except socket.gaierror:
        return {"ok": False, "label": "DNS didn’t resolve (NXDOMAIN)"}
    except Exception:
        return {"ok": False, "label": "DNS error"}

def diag_label_from_exception(e: Exception) -> str:
    if isinstance(e, requests.exceptions.Timeout):       return "Connection timed out"
    if isinstance(e, requests.exceptions.SSLError):      return "TLS handshake failed"
    if isinstance(e, requests.exceptions.ConnectionError): return "Connection error"
    return "Network error"

def waf_hint(headers: dict, status: int) -> str | None:
    if not headers: return None
    h = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    if status in (401,403):
        if "cf-ray" in h or ("server" in h and "cloudflare" in h["server"]): return "Blocked by site firewall (Cloudflare)"
        if any("akamai" in v for v in h.values()): return "Blocked by site firewall (Akamai)"
        if "x-sucuri-id" in h or "x-sucuri-cache" in h: return "Blocked by site firewall (Sucuri)"
    return None

# ---------- Neutral responses ----------
def neutral_response(url: str, verdict: str, msg: str, diag: dict | None = None):
    return jsonify({
        "url": url, "verdict": verdict, "confidence": 0.0,
        "phishing_score": 0.0, "legit_score": 0.0,
        "explanation": msg, "diagnostic": diag or {},
        "domain_risks": [], "content_risks": [], "link_risks": [], "behavior_risks": [],
        "features_triggered": [],
        "category_scores": {"domain":0,"content":0,"link":0,"behavior":0},
        "explanations": {"domain":[], "link":[], "content":[], "behavior":[], "summary": msg},
        "behavior": {"mode":"disabled","score":0.0,"events":[]},
        "structure": {"score":0.0,"template":None},
        "visual": {"score":0.0,"closest":None},
        "policy": {"strict_surface_guard": STRICT_SURFACE_GUARD,
                   "startup_exception_guard": STARTUP_EXCEPTION_GUARD,
                   "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH},
        "startup_like": 0
    }), 200

def unreachable_response(url: str, diag_label: str | None = None):
    return neutral_response(
        url, "Unreachable",
        "We couldn’t reach this site (DNS/host/timeout). No phishing verdict given because content wasn’t available.",
        {"label": diag_label} if diag_label else None
    )

# ---------- Content quality gate (used for 'lite mode', not to abort) ----------
def meaningful_html_metrics(html: str) -> dict:
    if not html:
        return {"ok": False, "bytes": 0, "words": 0}
    stripped = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    stripped = re.sub(r"(?s)<[^>]+>", " ", stripped)
    words = re.findall(r"[A-Za-z]{3,}", stripped)
    b = len(html or ""); w = len(words)
    ok = (b >= 600 and w >= 80)
    return {"ok": ok, "bytes": b, "words": w}

# ------------------------------------------------------------------------------
# API
# ------------------------------------------------------------------------------
@app.route("/check", methods=["POST"])
def check_url():
    try:
        data = request.json or {}
        raw = (data.get("url") or "").strip()
        if not raw:
            return jsonify({"error": "No URL provided"}), 400

        url = resolve_url(raw)
        if not url:
            return unreachable_response("", "Invalid URL")

        # Expand shorteners
        host0 = urlparse(url).netloc.lower().split(":")[0]
        if host0 in KNOWN_SHORTENERS:
            expanded = expand_short_url(url)
            if expanded: url = expanded

        # DNS preflight
        pre = dns_preflight(url)
        if not pre.get("ok"):
            return unreachable_response(url, pre.get("label") or "DNS error")

        html_content = ""
        lite_mode = False
        lite_reason = ""
        OUR_SCAN = _is_our_domain(url)

        if OUR_SCAN:
            try:
                with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        r = None
        if not html_content:
            try:
                r = requests.get(url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                if url.startswith("https://"):
                    try:
                        r = requests.get(to_http(url), headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
                        url = r.url
                    except requests.RequestException:
                        return unreachable_response(url, diag_label_from_exception(e) + " (https and http)")
                else:
                    return unreachable_response(url, diag_label_from_exception(e))
            except requests.RequestException as e:
                return unreachable_response(url, diag_label_from_exception(e))

            status = r.status_code
            if 200 <= status < 300:
                ctype = (r.headers or {}).get("Content-Type","").lower()
                html_content = r.text or ""
                metrics = meaningful_html_metrics(html_content)
                # We DO NOT abort on non-HTML or thin HTML; we classify in lite mode.
                if ctype and "text/html" not in ctype:
                    lite_mode, lite_reason = True, f"Non-HTML ({ctype})"
                elif not metrics["ok"]:
                    lite_mode, lite_reason = True, f"Thin page ({metrics['bytes']} bytes / {metrics['words']} words)"
                url = r.url
            else:
                label = f"HTTP {status} {(r.reason or '').strip()}"
                hint = waf_hint(getattr(r,"headers",{}), status)
                if status in (401,403):
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
                        f"The site refused analysis (HTTP {status}).", {"label": label})
                if 500 <= status < 600:
                    return neutral_response(url, "Server Error",
                        f"The site responded with a server error (HTTP {status}).", {"label": label})

        # Feature extraction (works even if lite_mode / empty html)
        features = extract_features(url, html_content)
        features.pop("registrar_name", None)

        if OUR_SCAN and CTU_SOFT_WHITELIST_SELF:
            for k in ("is_new_domain","suspicious_tld"): features[k] = 0

        df = align_to_model(pd.DataFrame([features]), model)

        # Model inference
        proba = model.predict_proba(df)[0]
        p_phish = float(dict(zip(model.classes_, proba)).get(1, 0.0))
        phishing_score = round(p_phish * 100.0, 2)
        legit_score    = round((1.0 - p_phish) * 100.0, 2)
        confidence     = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)

        # Behavior
        behavior = {"mode":"disabled","score":0.0,"events":[]}
        try:
            if CTU_BEHAVIOR_MODE != "off":
                behavior = simulate_behavior(url)
        except Exception as e:
            behavior = {"mode":"error","score":0.0,"events":[f"behavior engine unavailable: {type(e).__name__}"]}

        # Merge HTTP redirects
        try:
            if r is not None:
                hist = list(getattr(r, "history", []) or [])
                http_redirects = len(hist)
                chain = [resp.headers.get("Location") or resp.url for resp in hist] + [r.url]
                if http_redirects > 0:
                    behavior.setdefault("events", []).append(f"↪ HTTP redirect chain length {http_redirects}.")
                    behavior["http_redirects"] = http_redirects
                    behavior.setdefault("redirect_chain", chain)
                refresh = (r.headers or {}).get("Refresh") or (r.headers or {}).get("refresh")
                if refresh and re.search(r'url\s*=\s*', refresh, re.I):
                    behavior["client_redirects"] = behavior.get("client_redirects", 0) + 1
                    behavior.setdefault("events", []).append("↪ HTTP Refresh header redirect.")
        except Exception:
            pass

        # DOM / Visual (best-effort)
        structure = {"score": 0.0, "template": None}
        try: structure = structure_similarity(html_content or "")
        except Exception: pass

        visual = {"score": 0.0, "closest": None}
        try: visual = visual_similarity(url)
        except Exception: pass

        # Scores + verdict
        behavior_score = float(behavior.get("score", 0.0))
        category_scores = compute_category_scores(features, behavior_score)
        if lite_mode:
            # make it explicit that content/link are not used
            category_scores["content"] = 0.0
            category_scores["link"] = 0.0
        verdict = guarded_verdict(p_phish, features, behavior_score)

        # ---------------- Reasons (timer gated; suppress content/link in lite mode) ----------------
        reasons = []
        metrics = meaningful_html_metrics(html_content)

        if verdict in ("Phishing", "Suspicious"):
            # Domain cues always okay
            if features.get("suspicious_keyword_found"): reasons.append("🔑 Suspicious keywords present.")
            if features.get("suspicious_tld"):           reasons.append("🌐 Suspicious TLD.")
            if features.get("domain_entropy", 0) > 4.0:  reasons.append("🎲 Domain name has high entropy.")

            if not lite_mode and metrics["ok"]:
                # Only when we had meaningful HTML
                if features.get("num_forms", 0) > 0:         reasons.append("📝 Form(s) found; potential credential capture.")
                if features.get("has_password_field"):       reasons.append("🔒 Password field present.")
                if features.get("keyword_density", 0) > 0.02: reasons.append("📌 Elevated phishing keyword density.")
                if features.get("duplicate_phrases", 0) > 1: reasons.append("📋 Repeating suspicious phrases.")
                if features.get("mismatched_anchor_ratio", 0) > 0.3: reasons.append("🔗 Anchor text vs link mismatch.")
                if features.get("link_density", 0) > 0.4:    reasons.append("🌐 Link density is unusually high.")
                if features.get("external_link_ratio", 0) > 0.5: reasons.append("🌍 Too many external links.")
                if sum([features.get(f"tfidf_{i}", 0) for i in range(20)]) < 0.1 and not OUR_SCAN:
                    reasons.append("📉 Low informational content.")

                # STRICT TIMER GATING — only if timer markup AND behavior evidence
                has_meta_refresh = bool(re.search(r'<meta[^>]+http-equiv=["\']?\s*refresh', html_content or "", re.I))
                timer_flag = bool(features.get("has_js_timer") or features.get("has_html_timer") or has_meta_refresh)
                behavior_evidence = (
                    int(behavior.get("js_redirects_detected", 0)) > 0 or
                    int(behavior.get("post_action_redirects", 0)) > 0 or
                    int(behavior.get("client_redirects", 0) or 0) > 0
                )
                if timer_flag and behavior_evidence:
                    reasons.append("⏳ Urgency timer detected (confirmed by behavior).")

            # Behavior-driven (independent of content)
            if int(behavior.get("post_action_redirects", 0)) > 0: reasons.append("➡️ Redirect occurred after CTA/form action (behavior).")
            if int(behavior.get("js_redirects_detected", 0)) > 0: reasons.append("↪ JS-driven redirect detected (behavior).")
            if float(behavior.get("dom_mutation_score", 0)) >= 0.05: reasons.append("🧪 Significant DOM mutation after load (behavior).")

        # Group reasons
        domain_risks, content_risks, link_risks, behavior_risks, _ = _group_reasons(reasons)

        # Explanation
        summary_bits = []
        if lite_mode: summary_bits.append("content-lite mode")
        if features.get("startup_like"): summary_bits.append("startup-like pattern detected")
        if features.get("is_new_domain"): summary_bits.append("young domain")
        if int(features.get("non_surface_red_flags",0))>0: summary_bits.append(f"{int(features.get('non_surface_red_flags',0))} non-surface signal(s)")
        if behavior_score >= 0.35: summary_bits.append("dynamic behavior observed")
        summary_tail = (" • " + ", ".join(summary_bits)) if summary_bits else ""

        base_msg = "See grouped risk signals below."
        if lite_mode and lite_reason:
            base_msg = f"Limited page content ({lite_reason}); verdict relies on domain/network cues."

        explanation = (
            f"{confidence}% confidence • {verdict}{summary_tail}. {base_msg}"
            if verdict != "Legitimate"
            else ("Looks legitimate based on current checks."
                  + (" Content-lite mode; we avoid penalizing pages with little content." if lite_mode else "")
            )
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
            "diagnostic": ({"label": lite_reason} if lite_mode and lite_reason else {}),
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
                "surface_flags": int(features.get("is_new_domain",0)==1) +
                                 int(features.get("has_https",1)==0) +
                                 int(features.get("suspicious_tld",0)==1),
                "non_surface_red_flags": int(features.get("non_surface_red_flags",0))
            },
            "startup_like": int(features.get("startup_like",0))
        })

    except Exception as e:
        return unreachable_response(request.json.get("url") if request.is_json else "", f"Scanner error: {type(e).__name__}")

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
def version(): return jsonify({"model_path": os.path.abspath(MODEL_PATH),
                              "server_time_utc": datetime.utcnow().isoformat() + "Z"})

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    if not sys.argv or "gunicorn" not in sys.argv[0]:
        app.run(debug=True)
