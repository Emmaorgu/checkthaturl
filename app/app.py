import os
import glob
import sys
import requests
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

sys.path = ['..'] + sys.path
from extract_features import extract_features

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

def load_latest_model(model_dir):
    """Load the most recently trained phish_rf_model from directory."""
    model_files = glob.glob(os.path.join(model_dir, "phish_rf_model_*"))
    if not model_files:
        raise FileNotFoundError("No trained phish_rf_model files found.")
    return joblib.load(max(model_files, key=os.path.getctime))

# Load model from the /model directory
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'model'))
model = load_latest_model(MODEL_DIR)

@app.route("/check", methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url') if data else None

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    html_content = ""
    reasons = []

    try:
        response = requests.get(url, timeout=10)
        html_content = response.text
    except Exception:
        reasons.append("⚠ Failed to fetch HTML content. Partial analysis only.")
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

    # Explanations
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

@app.route("/", methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
