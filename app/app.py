import os
import sys
import glob
import requests
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from datetime import datetime

sys.path = ['..'] + sys.path
from app.extract_features import extract_features

app = Flask(__name__)
CORS(app)

def get_latest_model_path():
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'model')
    versioned_models = glob.glob(os.path.join(model_dir, "phish_rf_model_*.pkl"))

    def extract_timestamp(filepath):
        filename = os.path.basename(filepath)
        ts_str = filename.replace("phish_rf_model_", "").replace(".pkl", "")
        try:
            return datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
        except ValueError:
            return datetime.min

    if versioned_models:
        latest_model = max(versioned_models, key=extract_timestamp)
        print(f"[INFO] Loaded latest model: {os.path.basename(latest_model)}")
        return latest_model

    fallback = os.path.join(model_dir, "phish_rf_model.pkl")
    print("[WARN] No versioned model found. Falling back to:", os.path.basename(fallback))
    return fallback

MODEL_PATH = get_latest_model_path()
model = joblib.load(MODEL_PATH)

LOCAL_HOMEPAGE_PATH = os.path.join(os.path.dirname(__file__), 'index.html')

def resolve_url(raw_url):
    if raw_url.startswith(('http://', 'https://')):
        return raw_url
    for scheme in ['https://', 'http://']:
        try:
            test_url = scheme + raw_url
            response = requests.head(test_url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                return test_url
        except:
            continue
    return None

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

    html_content = ""
    reasons = []

    if "checkthaturl.com" in url:
        try:
            with open(LOCAL_HOMEPAGE_PATH, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            reasons.append(f"⚠ Failed to load local homepage HTML: {str(e)}. Partial analysis only.")
            html_content = ''
    else:
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
            html_content = ''

    features = extract_features(url, html_content)
    features.pop("registrar_name", None)
    df = pd.DataFrame([features])

    try:
        proba = model.predict_proba(df)[0]
        proba_dict = dict(zip(model.classes_, proba))
        phishing_score = round(proba_dict.get(1, 0.0) * 100, 2)
        legit_score = round(proba_dict.get(0, 0.0) * 100, 2)
        confidence = round(max(phishing_score, legit_score), 2)
    except Exception as e:
        return jsonify({"error": f"Model failed to predict: {str(e)}"}), 500

    prediction = 'Phishing' if phishing_score > legit_score else 'Legitimate'

    if prediction == 'Phishing':
        if features.get('suspicious_keyword_found'): reasons.append("🔑 Suspicious keywords present.")
        if features.get('suspicious_tld'): reasons.append("🌐 Suspicious TLD.")
        if features.get('domain_entropy', 0) > 4.0: reasons.append("🎲 Domain name is suspicious.")
        if features.get('num_forms', 0) > 0: reasons.append("📝 Suspicious form.")
        if features.get('has_password_field'): reasons.append("🔒 Password field present.")
        if features.get('keyword_density', 0) > 0.02: reasons.append("📌 High phishing keyword density.")
        if features.get('duplicate_phrases', 0) > 1: reasons.append("📋 Repeating suspicious phrases.")
        if features.get('mismatched_anchor_ratio', 0) > 0.3: reasons.append("🔗 Anchor text vs link mismatch.")
        if features.get('link_density', 0) > 0.4: reasons.append("🌐 Link density is high.")
        if features.get('external_link_ratio', 0) > 0.5: reasons.append("🌍 Too many external links.")
        if sum([features.get(f'tfidf_{i}', 0) for i in range(20)]) < 0.1: reasons.append("📉 Low informational content.")
        if features.get('has_js_timer') or features.get('has_html_timer'): reasons.append("⏳ Urgent countdown timer detected.")
    else:
        reasons = ["✅ Low or no phishing patterns."]

    summary = f"{confidence}% likely to be {prediction.lower()}. Reasons: " + "; ".join(reasons)

    return jsonify({
        "verdict": prediction,
        "confidence": f"{confidence}%",
        "phishing_score": phishing_score,
        "legit_score": legit_score,
        "explanation": summary,
        "features_triggered": reasons
    })

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

if __name__ == "__main__":
    if "gunicorn" not in sys.argv[0]:
        app.run(debug=True)
