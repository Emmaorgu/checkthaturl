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

# Allow running both as a package (gunicorn app.app:app) and directly (python app/app.py)
try:
    from app.extract_features import extract_features
except Exception:
    sys.path = ['.','..'] + sys.path
    from extract_features import extract_features  # type: ignore

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------------------
# Verdict thresholds (Day 1)
# ------------------------------------------------------------------------------
PHISHING_THRESHOLD = 0.70   # >= 0.70 -> "Phishing"
LEGIT_THRESHOLD    = 0.30   # <= 0.30 -> "Legitimate"
# 0.30 < p < 0.70           -> "Suspicious" (Grey zone)

# ------------------------------------------------------------------------------
# Model loader (latest timestamped .pkl in /model) (Day 1)
# ------------------------------------------------------------------------------
def get_latest_model_path():
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'model')
    versioned = glob.glob(os.path.join(model_dir, "phish_rf_model_*.pkl"))

    def ts(fp):
        import re
        from datetime import datetime as _dt
        m = re.search(r"phish_rf_model_(\d{8}_\d{6})\.pkl$", os.path.basename(fp))
        if not m: return _dt.min
        try:
            return _dt.strptime(m.group(1), "%Y%m%d_%H%M%S")
        except Exception:
            return _dt.min

    if versioned:
        latest = max(versioned, key=ts)
        print(f"[INFO] Loaded latest model: {os.path.basename(latest)}")
        return latest
    # fallback (non-versioned)
    fallback = os.path.join(model_dir, "phish_rf_model.pkl")
    print("[WARN] No versioned model found. Falling back to:", os.path.basename(fallback))
    return fallback

MODEL_PATH = get_latest_model_path()
model = joblib.load(MODEL_PATH)

# ------------------------------------------------------------------------------
# Frontend flags in templates (Day 1/4)
# ------------------------------------------------------------------------------
@app.context_processor
def inject_flags_and_now():
    return {
        "SELF_HOSTED": os.getenv("CTU_SELF_HOSTED", "0") == "1",
        "now": datetime.utcnow().strftime("%Y-%m-%d")
    }

# ------------------------------------------------------------------------------
# Own-domain / dev-only local-template flag (THIS FIX)
# ------------------------------------------------------------------------------
CTU_USE_LOCAL_INDEX = os.getenv("CTU_USE_LOCAL_INDEX", "0") == "1"  # dev-only
OUR_HOSTS = {"checkthaturl.com", "www.checkthaturl.com"}
LOCAL_TEMPLATE_INDEX = os.path.join(os.path.dirname(__file__), "templates", "index.html")

def _is_our_domain(u: str) -> bool:
    try:
        host = urlparse(u).netloc.split(":")[0].lower()
        return host in OUR_HOSTS
    except Exception:
        return False

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def resolve_url(raw_url: str | None) -> str | None:
    if not raw_url:
        return None
    raw_url = raw_url.strip()
    if raw_url.startswith(('http://', 'https://')):
        return raw_url
    for scheme in ['https://', 'http://']:
        try:
            test_url = scheme + raw_url
            r = requests.head(test_url, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                return test_url
        except Exception:
            continue
    return None

def choose_verdict(p_phish: float) -> str:
    if p_phish >= PHISHING_THRESHOLD:
        return "Phishing"
    if p_phish <= LEGIT_THRESHOLD:
        return "Legitimate"
    return "Suspicious"

# Heuristic grouping (Day 1)
DOMAIN_HINTS  = ("domain", "whois", "tld", "dns", "registrar", "mx", "spf", "dkim", "age", "subdomain", "punycode", "entropy")
CONTENT_HINTS = ("content", "text", "keyword", "phrase", "login", "form", "credential", "timer", "urgency", "brand", "logo", "tfidf", "nlp", "password")
LINK_HINTS    = ("link", "url", "redirect", "anchor", "href", "shortener", "bit.ly", "t.co", "utm_", "outbound", "mismatch")

def group_from_reasons(reasons):
    domain_risks, content_risks, link_risks, other = [], [], [], []
    for r in reasons or []:
        low = str(r).lower()
        if any(h in low for h in DOMAIN_HINTS):
            domain_risks.append(r)
        elif any(h in low for h in CONTENT_HINTS):
            content_risks.append(r)
        elif any(h in low for h in LINK_HINTS):
            link_risks.append(r)
        else:
            other.append(r)
    if not (domain_risks or content_risks or link_risks) and other:
        content_risks = other
        other = []
    return domain_risks, content_risks, link_risks, other

def category_scores_from_groups(domain_risks, content_risks, link_risks, behavior_events):
    # Simple normalized presence scores (0..1) to feed the UI (Day 3/4 compatibility)
    def s(lst): return min(1.0, len(lst) / 4.0)
    return {
        "domain":   s(domain_risks),
        "content":  s(content_risks),
        "link":     s(link_risks),
        "behavior": s(behavior_events or []),
    }

# ------------------------------------------------------------------------------
# API
# ------------------------------------------------------------------------------
@app.route("/check", methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url') if data else None
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    resolved = resolve_url(url)
    if not resolved:
        return jsonify({'error': 'Could not resolve URL via HTTP/HTTPS'}), 400
    url = resolved

    reasons: list[str] = []
    html_content = ""

    # --- HTML fetch FIX -------------------------------------------------------
    # Dev-only local template if explicitly enabled and scanning our own domain.
    if CTU_USE_LOCAL_INDEX and _is_our_domain(url):
        try:
            with open(LOCAL_TEMPLATE_INDEX, "r", encoding="utf-8") as f:
                html_content = f.read()
        except Exception:
            # Do NOT penalize; just fall back to network fetch silently.
            html_content = ""

    # Always fall back to network fetch if we don't yet have content.
    if not html_content:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            html_content = response.text
        except Exception as e:
            reasons.append(f"⚠ Failed to fetch HTML content: {str(e)}. Partial analysis only.")
            html_content = ""

    # --- Feature extraction ---------------------------------------------------
    features = extract_features(url, html_content)
    features.pop("registrar_name", None)  # avoid high-cardinality categorical leakage
    df = pd.DataFrame([features])

    # --- Model inference ------------------------------------------------------
    try:
        proba = model.predict_proba(df)[0]
        # Assume model.classes_ are [0,1] (0=legit, 1=phish)
        p_phish = float(proba[ list(model.classes_).index(1) ])
        p_legit = 1.0 - p_phish
        phishing_score = round(p_phish * 100.0, 2)
        legit_score    = round(p_legit * 100.0, 2)
        # confidence shaped around distance from 0.5
        confidence = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)
    except Exception as e:
        return jsonify({"error": f"Model failed to predict: {str(e)}"}), 500

    verdict = choose_verdict(p_phish)

    # --- Reasons (lightweight, refine over time) -----------------------------
    if verdict in ('Phishing', 'Suspicious'):
        if features.get('suspicious_keyword_found'): reasons.append("🔑 Suspicious keywords present. (content)")
        if features.get('suspicious_tld'): reasons.append("🌐 Suspicious TLD. (domain)")
        if features.get('domain_entropy', 0) > 4.0: reasons.append("🎲 Domain name has high entropy. (domain)")
        if features.get('num_forms', 0) > 0: reasons.append("📝 Form(s) found; potential credential capture. (content)")
        if features.get('has_password_field'): reasons.append("🔒 Password field present. (content)")
        if features.get('keyword_density', 0) > 0.02: reasons.append("📌 Elevated phishing keyword density. (content)")
        if features.get('duplicate_phrases', 0) > 1: reasons.append("📋 Repeating suspicious phrases. (content)")
        if features.get('mismatched_anchor_ratio', 0) > 0.3: reasons.append("🔗 Anchor text vs link mismatch. (link)")
        if features.get('link_density', 0) > 0.4: reasons.append("🌐 Link density is unusually high. (link)")
        if features.get('external_link_ratio', 0) > 0.5: reasons.append("🌍 Too many external links. (link)")
        if sum([features.get(f'tfidf_{i}', 0) for i in range(20)]) < 0.1: reasons.append("📉 Low informational content. (content)")
        if features.get('has_js_timer') or features.get('has_html_timer'): reasons.append("⏳ Urgency timer detected. (content)")
    else:
        reasons = ["✅ Low or no phishing patterns detected."]

    # Group by category for UI
    domain_risks, content_risks, link_risks, _ = group_from_reasons(reasons)

    # Category scores for UI progress bars (Day 3/4 compatibility)
    category_scores = category_scores_from_groups(domain_risks, content_risks, link_risks, behavior_events=[])

    # Explanation line
    explanation = (
        f"{confidence}% confidence • {verdict}. See grouped risk signals below."
        if verdict != "Legitimate"
        else "Looks legitimate based on current checks."
    )

    # Minimal stubs for Day 3/4 fields (keeps UI happy even if modules are optional)
    structure = {"score": 0.0, "template": None}
    visual    = {"score": 0.0, "closest": None}
    behavior  = {"mode": "requests", "score": 0.0, "redirect_chain": [], "events": []}

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
        "behavior_risks": behavior["events"],
        "features_triggered": reasons,
        "category_scores": category_scores,
        "structure": structure,
        "visual": visual,
        "behavior": behavior,
        # v2 explanations compatibility (summary string)
        "explanations": {
            "summary": explanation,
            "domain": domain_risks,
            "content": content_risks,
            "link": link_risks,
            "behavior": behavior["events"]
        }
    })

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

# ------------------------------------------------------------------------------
# Health/version (Day 4)
# ------------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"ok": True})

@app.route("/version")
def version():
    return jsonify({"model_path": os.path.abspath(MODEL_PATH), "server_time_utc": datetime.utcnow().isoformat() + "Z"})

# ------------------------------------------------------------------------------
# Feedback blueprint (Day 4)
# ------------------------------------------------------------------------------
try:
    from app.feedback import feedback_bp  # type: ignore
except Exception:
    try:
        from feedback import feedback_bp  # type: ignore
    except Exception:
        feedback_bp = None

if feedback_bp is not None:
    app.register_blueprint(feedback_bp)

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    if "gunicorn" not in (sys.argv[0] if sys.argv else ""):
        app.run(debug=True)
