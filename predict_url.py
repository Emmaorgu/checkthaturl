import sys
import joblib
import pandas as pd
from extract_features import extract_features

MODEL_PATH = 'model/phish_rf_model.pkl'

def predict_url(url, html_content=None):
    # Load trained model
    model = joblib.load(MODEL_PATH)

    # Extract features
    features = extract_features(url, html_content)
    df = pd.DataFrame([features])

    # Predict
    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]

    label = "Phishing" if prediction == 1 else "Legitimate"
    confidence = round(max(probabilities) * 100, 2)

    print(f"\n[+] URL: {url}")
    print(f"[✓] Prediction: {label}")
    print(f"[✓] Confidence: {confidence}%")

    # Optional: Show suspicious reasons (basic explanation)
    if prediction == 1:
        print("[!] Possible reasons:")
        if features.get('has_suspicious_keywords'):
            print("- Contains phishing-related keywords")
        if features.get('has_suspicious_tld'):
            print("- Uses suspicious TLD")
        if features.get('high_entropy'):
            print("- URL has high randomness")
        if features.get('contains_form'):
            print("- Page contains form elements")
    else:
        print("[✓] No major phishing indicators found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict_url.py <url>")
        sys.exit(1)

    test_url = sys.argv[1]
    predict_url(test_url)
