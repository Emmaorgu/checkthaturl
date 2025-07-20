import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from app import extract_features

# File paths
real_phishing_file = 'real_phishing_urls.txt'
legit_urls_file = 'legitimate_urls.txt'
output_file = 'dataset/phishing_dataset.csv'

# Ensure output folder exists
os.makedirs('dataset', exist_ok=True)

# Load URLs from file
def load_urls(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# Expected columns (updated to match new extract_features output)
EXPECTED_COLUMNS = [
    "url", "url_length", "num_dots", "has_https", "num_subdomains", "has_ip", "has_at_symbol",
    "has_dash", "has_multiple_slashes", "domain_age_days", "whois_registrar", "whois_country",
    "form_count", "favicon_match", "url_entropy", "suspicious_tld",
    "high_risk_keyword_count", "contextual_keyword_count", "high_risk_keywords", "contextual_keywords", "label"
]

# Generate and save dataset
def generate_dataset():
    data = []

    print("🔴 Processing real phishing URLs...")
    for url in load_urls(real_phishing_file):
        try:
            features = extract_features(url)
            features['label'] = 1
            data.append(features)
        except Exception as e:
            print(f"❌ Failed phishing URL: {url} - {e}")

    print("🔴 Processing locally hosted phishing URLs...")
    local_urls = [
        # Add your 30 cloned phishing URLs here
    ]
    for url in local_urls:
        try:
            features = extract_features(url)
            features['label'] = 1
            data.append(features)
        except Exception as e:
            print(f"❌ Failed local phishing: {url} - {e}")

    print("🟢 Processing legitimate URLs...")
    for url in load_urls(legit_urls_file):
        try:
            features = extract_features(url)
            features['label'] = 0
            data.append(features)
        except Exception as e:
            print(f"❌ Failed legit URL: {url} - {e}")

    print(f"💾 Saving dataset to {output_file}")
    df = pd.DataFrame(data)

    # Ensure all expected columns are present
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = None

    df = df[EXPECTED_COLUMNS]
    df.to_csv(output_file, index=False)
    print(f"✅ Dataset saved: {len(df)} samples.")

if __name__ == "__main__":
    generate_dataset()
