# app/app.py
import os
import sys
import glob
import math
import requests
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse

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
PHISHING_THRESHOLD = 0.70   # >= -> Phishing
LEGIT_THRESHOLD    = 0.30   # <= -> Legitimate
STRICT_SURFACE_GUARD = True
STARTUP_EXCEPTION_GUARD = True

# Domain-only predictions cannot produce "Phishing"
DOMAIN_ONLY_CAN_PHISH = False

# Our own domain bias guards
CTU_SOFT_WHITELIST_SELF = os.getenv("CTU_SOFT_WHITELIST_SELF", "1") == "1"
OUR_HOSTS = {"checkthaturl.com", "www.checkthaturl.com"}
LOCAL_TEMPLATE_INDEX = os.path.join(os.path.dirname(__file__), "templates", "index.html")

# Behavior mode (auto/requests/off) used by replay_engine
CTU_BEHAVIOR_MODE = os.getenv("CTU_BEHAVIOR_MODE", "auto")

# ------------------------------------------------------------------------------
# Model loading (pick latest timestamped)
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

def resolve_url(raw_url: str | None) -> str | None:
    if not raw_url:
        return None
    raw_url = raw_url.strip()
    if raw_url.startswith(("http://", "https://")):
        return raw_url
    for scheme in ("https://", "http://"):
        try:
            t = scheme + raw_url
            r = requests.head(t, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                return t
        except Exception:
            pass
    return None

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

    return {
        "domain": round(domain, 3),
        "link": round(link, 3),
        "content": round(content, 3),
        "behavior": round(behavior, 3),
    }

# ------------------------------------------------------------------------------
# Unified "Unreachable" response (no phishing judgement when content not fetched)
# ------------------------------------------------------------------------------
def unreachable_response(url: str, err_msg: str, status: int = 200):
    msg = "We couldn’t reach this site (DNS/host/timeout). No phishing verdict given because content wasn’t available."
    return jsonify({
        "url": url,
        "verdict": "Unreachable",
        "confidence": 0.0,
        "phishing_score": 0.0,
        "legit_score": 0.0,
        "explanation": msg,
        "domain_risks": [],
        "content_risks": [f"Site unreachable. {err_msg}".strip()],
        "link_risks": [],
        "behavior_risks": [],
        "features_triggered": [],
        "category_scores": {"domain":0,"content":0,"link":0,"behavior":0},
        "explanations": {
            "domain": [],
            "link": [],
            "content": [],
            "behavior": [],
            "summary": "Site unreachable."
        },
        "behavior": {"mode":"disabled","score":0.0,"events":[]},
        "structure": {"score":0.0,"template":None},
        "visual": {"score":0.0,"closest":None},
        "policy": {
            "strict_surface_guard": STRICT_SURFACE_GUARD,
            "startup_exception_guard": STARTUP_EXCEPTION_GUARD,
            "domain_only_can_phish": DOMAIN_ONLY_CAN_PHISH
        },
        "startup_like": 0
    }), status

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

        # Resolve URL; if no scheme works, treat as Unreachable (not an error to the UI)
        resolved = resolve_url(url)
        if not resolved:
            return unreachable_response(url, "Could not resolve host via HTTP/HTTPS.", status=200)
        url = resolved

        html_content = ""
        reasons: list[str] = []
        OUR_SCAN = _is_our_domain(url)

        # Use local template for our own domain (no penalty if missing)
        if OUR_SCAN:
            try:
                with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                    html_content = f.read()
            except Exception:
                html_content = ""

        # Network fetch if still empty
        if not html_content:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                }
                r = requests.get(url, headers=headers, timeout=10)
                r.raise_for_status()
                html_content = r.text
            except Exception as e:
                # If we cannot fetch content, return Unreachable instead of partial analysis
                return unreachable_response(url, f"Failed to fetch HTML content: {e}")

        # ---------- Feature extraction ----------
        features = extract_features(url, html_content)
        features.pop("registrar_name", None)

        # Neutralize surface-only bias on our own domain
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

        # ---------- Behavior (guarded) ----------
        behavior = {"mode": "disabled", "score": 0.0, "events": []}
        try:
            if CTU_BEHAVIOR_MODE != "off":
                behavior = simulate_behavior(url)
        except Exception as e:
            behavior = {"mode": "error", "score": 0.0, "events": [f"behavior engine unavailable: {type(e).__name__}"]}
        behavior_score = float(behavior.get("score", 0.0))

        # ---------- DOM similarity (guarded) ----------
        structure = {"score": 0.0, "template": None}
        try:
            structure = structure_similarity(html_content or "")
            if float(structure.get("score", 0.0)) >= 0.85 and structure.get("template"):
                reasons.append(f"🧩 DOM layout highly similar to template '{structure.get('template')}'.")
        except Exception:
            structure = {"score": 0.0, "template": None}

        # ---------- Visual similarity (guarded) ----------
        visual = {"score": 0.0, "closest": None}
        try:
            visual = visual_similarity(url)
            if float(visual.get("score", 0.0)) >= 0.90 and visual.get("closest"):
                reasons.append(f"🖼️ Visual appearance matches known template '{visual.get('closest')}'.")
        except Exception:
            visual = {"score": 0.0, "closest": None}

        # ---------- Category + verdict with guard rails ----------
        category_scores = compute_category_scores(features, behavior_score)
        verdict = guarded_verdict(p_phish, features, behavior_score)

        # Human-readable reasons
        if verdict in ("Phishing", "Suspicious"):
            if features.get("suspicious_keyword_found"): reasons.append("🔑 Suspicious keywords present.")
            if features.get("suspicious_tld"):           reasons.append("🌐 Suspicious TLD.")
            if features.get("domain_entropy", 0) > 4.0:  reasons.append("🎲 Domain name has high entropy.")
            if features.get("num_forms", 0) > 0:         reasons.append("📝 Form(s) found; potential credential capture.")
            if features.get("has_password_field"):       reasons.append("🔒 Password field present.")
            if features.get("keyword_density", 0) > 0.02: reasons.append("📌 Elevated phishing keyword density.")
            if features.get("duplicate_phrases", 0) > 1: reasons.append("📋 Repeating suspicious phrases.")
            if features.get("mismatched_anchor_ratio", 0) > 0.3: reasons.append("🔗 Anchor text vs link mismatch.")
            if features.get("link_density", 0) > 0.4:    reasons.append("🌐 Link density is unusually high.")
            if features.get("external_link_ratio", 0) > 0.5: reasons.append("🌍 Too many external links.")
            if sum([features.get(f"tfidf_{i}", 0) for i in range(20)]) < 0.1 and not _is_our_domain(url):
                reasons.append("📉 Low informational content.")
            if features.get("has_js_timer") or features.get("has_html_timer"): reasons.append("⏳ Urgency timer detected.")
            if int(behavior.get("post_action_redirects", 0)) > 0: reasons.append("➡️ Redirect occurred after CTA/form action (behavior).")
            if int(behavior.get("js_redirects_detected", 0)) > 0: reasons.append("↪ JS-driven redirect detected (behavior).")
            if float(behavior.get("dom_mutation_score", 0)) >= 0.05: reasons.append("🧪 Significant DOM mutation after load (behavior).")
        else:
            reasons = []

        # Group reasons
        domain_risks, content_risks, link_risks, behavior_risks, _ = _group_reasons(reasons)

        # Fallback reasons: never empty on non-Legit
        if verdict in ("Phishing", "Suspicious") and not (domain_risks or content_risks or link_risks or behavior_risks):
            if features.get("is_new_domain"):          domain_risks.append("🆕 Recently-registered domain.")
            if features.get("suspicious_tld"):         domain_risks.append("🌐 Suspicious/rare TLD.")
            if features.get("domain_entropy", 0) > 4:  domain_risks.append("🎲 Unnatural/complex domain pattern.")
            if float(features.get("phish_context_score", 0)) >= 0.35:
                content_risks.append("🧠 NLP flagged phishing-like phrasing.")
            if not (domain_risks or content_risks or link_risks or behavior_risks):
                domain_risks.append("⚠ Model confidence came primarily from domain-only signals; content/link/behavior had no red flags.")

        # Explanations
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
        # Last-resort: return Unreachable instead of 500 to keep UI honest
        return unreachable_response(request.json.get("url") if request.is_json else "", f"Scanner error: {type(e).__name__}")

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
