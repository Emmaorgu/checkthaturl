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

# Robust import
if __package__ in (None, "",):
    sys.path.insert(0, os.path.dirname(__file__))
    from extract_features import extract_features
    from replay_engine import simulate as simulate_behavior
    from dom_diff import structure_similarity
    try:
        from visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str): return {"score":0.0,"closest":None,"distance":None}
else:
    from .extract_features import extract_features
    from .replay_engine import simulate as simulate_behavior
    from .dom_diff import structure_similarity
    try:
        from .visual_signals import visual_similarity
    except Exception:
        def visual_similarity(url: str): return {"score":0.0,"closest":None,"distance":None}

app = Flask(__name__)
CORS(app)

# --- Tunable verdict thresholds ---
PHISHING_THRESHOLD = 0.70
LEGIT_THRESHOLD    = 0.30

# --- Policy toggles ---
STRICT_SURFACE_GUARD = True
STARTUP_EXCEPTION_GUARD = True

def get_latest_model_path():
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'model')
    versioned = glob.glob(os.path.join(model_dir, "phish_rf_model_*.pkl"))
    def ts(fp):
        from datetime import datetime as _dt
        s = os.path.basename(fp).replace("phish_rf_model_", "").replace(".pkl", "")
        try: return _dt.strptime(s, "%Y%m%d_%H%M%S")
        except ValueError: return _dt.min
    if versioned:
        latest = max(versioned, key=ts)
        print(f"[INFO] Loaded latest model: {os.path.basename(latest)}")
        return latest
    fallback = os.path.join(model_dir, "phish_rf_model.pkl")
    print("[WARN] No versioned model found. Falling back to:", os.path.basename(fallback))
    return fallback

MODEL_PATH = get_latest_model_path()
model = joblib.load(MODEL_PATH)

def align_to_model(df: pd.DataFrame, model) -> pd.DataFrame:
    if hasattr(model, "feature_names_in_"):
        need = list(model.feature_names_in_)
        for c in need:
            if c not in df.columns: df[c] = 0.0
        df = df[need]
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df

LOCAL_HOMEPAGE_PATH = os.path.join(os.path.dirname(__file__), 'index.html')

@app.context_processor
def inject_flags():
    return {"SELF_HOSTED": os.getenv("CTU_SELF_HOSTED", "0") == "1"}

def resolve_url(raw_url):
    if not raw_url: return None
    raw_url = raw_url.strip()
    if raw_url.startswith(('http://', 'https://')): return raw_url
    for scheme in ['https://', 'http://']:
        try:
            test = scheme + raw_url
            r = requests.head(test, timeout=5, allow_redirects=True)
            if r.status_code < 400: return test
        except: pass
    return None

def choose_verdict(p_phish: float) -> str:
    if p_phish >= PHISHING_THRESHOLD: return "Phishing"
    if p_phish <= LEGIT_THRESHOLD:    return "Legitimate"
    return "Suspicious"

# Grouping
DOMAIN_HINTS  = ("domain","whois","tld","dns","registrar","mx","spf","dkim","age","subdomain","punycode","entropy")
CONTENT_HINTS = ("content","text","keyword","phrase","login","form","credential","timer","urgency","brand","logo","tfidf","nlp","password")
LINK_HINTS    = ("link","url","redirect","anchor","href","shortener","bit.ly","t.co","utm_","outbound","mismatch")
BEHAV_HINTS   = ("redirect","cta","mutation","hidden","sandbox","behavior","post-action")

def group_from_reasons(reasons):
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

def guarded_verdict(p_phish: float, feats: dict) -> str:
    base = choose_verdict(p_phish)
    if not STRICT_SURFACE_GUARD and not STARTUP_EXCEPTION_GUARD: return base
    surface = int(feats.get("is_new_domain",0)==1) + int(feats.get("has_https",1)==0) + int(feats.get("suspicious_tld",0)==1)
    non_surface = int(feats.get("non_surface_red_flags",0))
    if STRICT_SURFACE_GUARD and base=="Phishing" and non_surface==0 and surface>0:
        return "Suspicious" if p_phish>=0.45 else "Legitimate"
    if STARTUP_EXCEPTION_GUARD and base=="Phishing":
        if feats.get("startup_like",0)==1 and feats.get("is_new_domain",0)==1 and non_surface<=1 and p_phish<0.85:
            return "Suspicious"
    return base

def clip01(x): return max(0.0, min(1.0, float(x)))

def compute_category_scores(feats: dict, p_phish: float, behavior_score: float) -> dict:
    domain = 0.0
    domain += 0.35 * int(feats.get("suspicious_tld",0)==1)
    domain += 0.35 * int(feats.get("is_new_domain",0)==1)
    domain += 0.30 * min(1.0, float(feats.get("domain_entropy",0))/4.5)
    link = clip01(int(feats.get("link_red_flags",0))/3.0)
    nlp = float(feats.get("phish_context_score",0.0))
    content_flags = int(feats.get("content_red_flags",0))
    content = clip01(0.6*nlp + 0.4*(content_flags/7.0))
    behavior = clip01(behavior_score)
    return {"domain":round(domain,3), "link":round(link,3), "content":round(content,3), "behavior":round(behavior,3)}

@app.route("/check", methods=['POST'])
def check_url():
    data = request.json or {}
    url = data.get('url')
    if not url: return jsonify({'error':'No URL provided'}), 400

    resolved = resolve_url(url)
    if not resolved: return jsonify({'error':'Could not resolve URL via HTTP/HTTPS'}), 400
    url = resolved

    html_content, reasons = "", []

    if "checkthaturl.com" in url:
        try:
            with open(LOCAL_HOMEPAGE_PATH, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            reasons.append(f"⚠ Failed to load local homepage HTML: {str(e)}. Partial analysis only.")
    else:
        try:
            headers = {'User-Agent':'Mozilla/5.0','Accept':'text/html,application/xhtml+xml','Accept-Language':'en-US,en;q=0.9','Connection':'keep-alive'}
            r = requests.get(url, headers=headers, timeout=10); r.raise_for_status()
            html_content = r.text
        except Exception as e:
            reasons.append(f"⚠ Failed to fetch HTML content: {str(e)}. Partial analysis only.")

    # Static features
    features = extract_features(url, html_content)
    features.pop("registrar_name", None)
    df = align_to_model(pd.DataFrame([features]), model)

    # Model inference
    try:
        proba = model.predict_proba(df)[0]
        proba_dict = dict(zip(model.classes_, proba))
        p_phish = float(proba_dict.get(1, 0.0))
        phishing_score, legit_score = round(p_phish*100.0,2), round((1.0-p_phish)*100.0,2)
        confidence = round(100 * (1 - math.exp(-4 * abs(p_phish - 0.5))), 1)
    except Exception as e:
        return jsonify({"error": f"Model failed to predict: {str(e)}"}), 500

    # Dynamic: behavior sandbox (quick; richer if Playwright is available)
    behavior = simulate_behavior(url)
    behavior_score = float(behavior.get("score", 0.0))

    # Structural similarity (DOM)
    struct = structure_similarity(html_content or "")
    struct_score = float(struct.get("score", 0.0))
    if struct_score >= 0.85:
        reasons.append(f"🧩 DOM layout highly similar to template '{struct.get('template')}'.")

    # Optional visual similarity (off by default)
    visual = visual_similarity(url)
    visual_score = float(visual.get("score", 0.0))
    if visual_score >= 0.90:
        reasons.append(f"🖼️ Visual appearance matches known template '{visual.get('closest')}'.")

    # Compute categories (with behavior)
    category_scores = compute_category_scores(features, p_phish, behavior_score)
    verdict = guarded_verdict(p_phish, features)

    # Reasons
    if verdict in ('Phishing','Suspicious'):
        if features.get('suspicious_keyword_found'): reasons.append("🔑 Suspicious keywords present.")
        if features.get('suspicious_tld'):           reasons.append("🌐 Suspicious TLD.")
        if features.get('domain_entropy',0)>4.0:     reasons.append("🎲 Domain name has high entropy.")
        if features.get('num_forms',0)>0:            reasons.append("📝 Form(s) found; potential credential capture.")
        if features.get('has_password_field'):       reasons.append("🔒 Password field present.")
        if features.get('keyword_density',0)>0.02:   reasons.append("📌 Elevated phishing keyword density.")
        if features.get('duplicate_phrases',0)>1:    reasons.append("📋 Repeating suspicious phrases.")
        if features.get('mismatched_anchor_ratio',0)>0.3: reasons.append("🔗 Anchor text vs link mismatch.")
        if features.get('link_density',0)>0.4:       reasons.append("🌐 Link density is unusually high.")
        if features.get('external_link_ratio',0)>0.5:reasons.append("🌍 Too many external links.")
        if sum([features.get(f'tfidf_{i}',0) for i in range(20)])<0.1: reasons.append("📉 Low informational content.")
        if features.get('has_js_timer') or features.get('has_html_timer'): reasons.append("⏳ Urgency timer detected.")
        # Behavior-derived notes
        if int(behavior.get("post_action_redirects",0))>0: reasons.append("➡️ Redirect occurred after CTA/form action (behavior).")
        if int(behavior.get("js_redirects_detected",0))>0: reasons.append("↪ JS-driven redirect detected (behavior).")
        if float(behavior.get("dom_mutation_score",0))>=0.05: reasons.append("🧪 Significant DOM mutation after load (behavior).")
    else:
        reasons = ["✅ Low or no phishing patterns detected."]

    domain_risks, content_risks, link_risks, behavior_risks, _ = group_from_reasons(reasons)

    summary_bits = []
    if features.get("startup_like"):               summary_bits.append("startup-like pattern detected")
    if features.get("is_new_domain"):              summary_bits.append("young domain")
    if features.get("non_surface_red_flags",0)>0:  summary_bits.append(f"{int(features.get('non_surface_red_flags',0))} non-surface signal(s)")
    if behavior_score >= 0.35:                     summary_bits.append("dynamic behavior observed")
    summary_tail = (" • " + ", ".join(summary_bits)) if summary_bits else ""

    explanation = (
        f"{confidence}% confidence • {verdict}{summary_tail}. See grouped risk signals below."
        if verdict != "Legitimate"
        else "Looks legitimate based on current checks. We avoid penalizing new/startup sites without other red flags."
    )

    v2_summary = (
        "This site appears mostly safe but shows content/behavior cues associated with phishing. Proceed with caution."
        if ((float(features.get("phish_context_score",0)) >= 0.35 or behavior_score >= 0.35) and verdict == "Suspicious")
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
        "structure": struct,
        "visual": visual,
        "policy": {
            "strict_surface_guard": STRICT_SURFACE_GUARD,
            "startup_exception_guard": STARTUP_EXCEPTION_GUARD
        },
        "counters": {
            "surface_flags": int(features.get("is_new_domain",0)==1) + int(features.get("has_https",1)==0) + int(features.get("suspicious_tld",0)==1),
            "non_surface_red_flags": int(features.get("non_surface_red_flags",0))
        },
        "startup_like": int(features.get("startup_like",0))
    })

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

@app.context_processor
def inject_globals():
    return {"SELF_HOSTED": os.getenv("CTU_SELF_HOSTED","0")=="1", "now": datetime.utcnow().strftime("%Y-%m-%d")}

if __name__ == "__main__":
    if "gunicorn" not in sys.argv[0]:
        app.run(debug=True)
