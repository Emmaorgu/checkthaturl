import traceback
from flask import Flask, render_template, request, session, jsonify
import joblib
import os
from feature_extractor import extract_features

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load model and encoders
MODEL_PATH = "phishing_rf_model.pkl"
REG_ENCODER_PATH = "registrar_encoder.pkl"
COUNTRY_ENCODER_PATH = "country_encoder.pkl"

model = joblib.load(MODEL_PATH)
reg_encoder = joblib.load(REG_ENCODER_PATH)
country_encoder = joblib.load(COUNTRY_ENCODER_PATH)

# Make sure this list has the exact feature order used in training
FEATURE_ORDER = [
    'url_length', 'num_dots', 'has_https', 'num_subdomains', 'has_ip',
    'has_at_symbol', 'has_dash', 'has_multiple_slashes', 'domain_age_days',
    'whois_registrar', 'whois_country', 'form_count', 'keyword_score',
    'favicon_match', 'url_entropy', 'suspicious_tld', 'high_risk_keyword_count'
]


def generate_explanation(features, prediction):
    if prediction == 0:
        return ["No phishing patterns detected."]

    explanation = []
    if features.get("has_ip"):
        explanation.append("Uses an IP address instead of a domain.")
    if features.get("has_at_symbol"):
        explanation.append("Contains an '@' symbol, often used in phishing URLs.")
    if features.get("has_multiple_slashes"):
        explanation.append("Has multiple '//' which may indicate redirection.")
    if features.get("form_count", 0) > 1:
        explanation.append("Contains multiple forms, which is suspicious.")
    if features.get("keyword_score", 0) > 2:
        explanation.append("Contains phishing-related keywords.")
    if features.get("high_risk_keyword_count", 0) > 0:
        explanation.append("Includes high-risk phishing keywords.")
    if features.get("url_entropy", 0) > 4.0:
        explanation.append("URL has high entropy, indicating randomness.")
    if features.get("suspicious_tld"):
        explanation.append("Uses a suspicious top-level domain.")
    if 0 <= features.get("domain_age_days", 9999) < 180:
        explanation.append("Domain is very new.")
    return explanation if explanation else ["Phishing patterns detected."]


def vectorize_features(features):
    input_vector = []
    for feat in FEATURE_ORDER:
        val = features.get(feat, 0)
        if feat == "whois_registrar":
            try:
                val = reg_encoder.transform([val.lower()])[0] if val else 0
            except:
                val = 0
        elif feat == "whois_country":
            try:
                val = country_encoder.transform([val.lower()])[0] if val else 0
            except:
                val = 0
        input_vector.append(val)
    return input_vector


@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    confidence = None
    explanation = None
    error = None

    if "history" not in session:
        session["history"] = []

    if request.method == "POST":
        url = request.form.get("url")

        if not url:
            error = "Please enter a URL."
        else:
            try:
                features = extract_features(url)
                input_vector = vectorize_features(features)

                prediction = int(model.predict([input_vector])[0])
                confidence = round(float(model.predict_proba([input_vector])[0][prediction]) * 100, 2)
                explanation = generate_explanation(features, prediction)

                session["history"].append({
                    "url": url,
                    "result": "Phishing" if prediction == 1 else "Legit",
                    "confidence": confidence
                })

            except Exception as e:
                error = f"Error processing URL: {str(e)}"

    return render_template("index.html",
                           history=session["history"],
                           prediction=prediction,
                           confidence=confidence,
                           explanation=explanation,
                           error=error)


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        features = extract_features(url)
        input_vector = vectorize_features(features)

        prediction = int(model.predict([input_vector])[0])
        confidence = round(float(model.predict_proba([input_vector])[0][prediction]), 4)
        explanation = generate_explanation(features, prediction)

        return jsonify({
            "url": url,
            "is_phishing": prediction,
            "confidence": confidence,
            "explanation": explanation
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
