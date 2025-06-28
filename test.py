import joblib
import requests
from extract_feature import extract_features
from urllib.parse import urlparse
import os
import warnings

# Ignore warnings from sklearn or HTML parsing
warnings.filterwarnings("ignore")

# === Paths ===
MODEL_PATH = 'model/phish_rf_model.pkl'

# === Load model ===
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Please train it first.")
clf = joblib.load(MODEL_PATH)

# === Get test URL ===
test_url = input("Enter URL to test: ").strip()
if not test_url.startswith('http'):
    test_url = 'http://' + test_url

# === Fetch HTML content ===
try:
    print(f"[+] Fetching content from {test_url}...")
    response = requests.get(test_url, timeout=10)
    html = response.text
except Exception as e:
    print(f"[!] Failed to fetch page: {e}")
    html = ""

# === Extract features ===
print("[+] Extracting features...")
features = extract_features(test_url, html)

# Keep only numerical features (required by model)
X_test = [val for key, val in features.items() if isinstance(val, (int, float))]

# === Predict ===
print("[+] Predicting...")
label = clf.predict([X_test])[0]
proba = clf.predict_proba([X_test])[0]
phishing_score = round(proba[1] * 100, 2)
legit_score = round(proba[0] * 100, 2)

# === Show result ===
print("\n--- Prediction Result ---")
print(f"Prediction: {'Phishing 🚨' if label == 1 else 'Legitimate ✅'}")
print(f"Phishing Confidence: {phishing_score}%")
print(f"Legitimate Confidence: {legit_score}%")
