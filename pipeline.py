#!/usr/bin/env python
# pipeline.py - Sustainable ML pipeline for phishing detection

import os
import subprocess
import sys
import pandas as pd
import csv
from datetime import datetime
from global_sources import fetch_all_sources


def timestamp():
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def log(msg):
    """Print messages with a timestamp."""
    print(f"{timestamp()} {msg}")


# Paths
DATA_DIR = "data"
MODEL_DIR = "model"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

GLOBAL_PHISHING_PATH = os.path.join(DATA_DIR, "global_phishing_urls.csv")
FEATURE_DATASET_PATH = os.path.join(DATA_DIR, "feature_dataset.csv")
BALANCED_DATASET_PATH = os.path.join(DATA_DIR, "balanced_feature_dataset.csv")
FINAL_MODEL_PATH = os.path.join(MODEL_DIR, "phish_rf_model.pkl")


def main():
    """Main pipeline process."""
    # 0. Fetch phishing URLs from external sources
    log("Fetching phishing URLs from OpenPhish, Abuse.ch.")
    phishing_urls = fetch_all_sources()
    new_df = pd.DataFrame({"url": phishing_urls})

    if os.path.exists(GLOBAL_PHISHING_PATH):
        existing_df = pd.read_csv(GLOBAL_PHISHING_PATH)
        combined = pd.concat([existing_df, new_df], ignore_index=True)
        combined = combined.drop_duplicates(subset='url')
        combined.to_csv(GLOBAL_PHISHING_PATH, index=False, quoting=csv.QUOTE_ALL)
        log(f"✅ Appended and deduplicated. {len(combined)} unique phishing URLs.")
    else:
        new_df.to_csv(GLOBAL_PHISHING_PATH, index=False, quoting=csv.QUOTE_ALL)
        log(f"✅ Saved {len(new_df)} phishing URLs to {GLOBAL_PHISHING_PATH}")

    # 1. Validate files
    expected_files = {
        "Legitimate URLs": os.path.join(DATA_DIR, "legit_urls.csv"),
        "Manual Phishing URLs": os.path.join(DATA_DIR, "real_phishing_urls.csv"),
        "Cloned Phishing HTML": os.path.join(DATA_DIR, "cloned_phishing_sites"),
        "Global Phishing URLs": GLOBAL_PHISHING_PATH,
    }
    for label, path in expected_files.items():
        if path.endswith('.csv'):
            if os.path.exists(path) and os.path.getsize(path) > 0:
                log(f"✅ {label}: File found.")
            else:
                log(f"❌ {label}: File missing or empty.")
        else:
            if os.path.exists(path) and any(f.endswith('.html') for f in os.listdir(path)):
                log(f"✅ {label}: HTML files present.")
            else:
                log(f"❌ {label}: Directory missing or empty.")

    # 2. Extract Features
    log("Extracting features from raw data.")
    result = subprocess.run([sys.executable, 'generate_feature_dataset.py'], check=False)
    if result.returncode == 0:
        log("✅ Feature extraction finished.")
    else:
        log("❌ Failed during feature extraction.")
        return

    # 3. Balance Dataset
    df = pd.read_csv(FEATURE_DATASET_PATH)
    phish_df = df[df['label'] == 1]
    legit_df = df[df['label'] == 0]
    min_len = min(len(phish_df), len(legit_df))
    if min_len < 50:
        raise ValueError(f"Not enough data to balance (phish:{len(phish_df)}, legit:{len(legit_df)})")

    balanced_df = pd.concat([
        phish_df.sample(min_len, random_state=42),
        legit_df.sample(min_len, random_state=42)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)

    balanced_df.to_csv(BALANCED_DATASET_PATH, index=False)
    log(f"✅ Balanced dataset saved to {BALANCED_DATASET_PATH} with {len(balanced_df)} samples.")

    # 4. Train Model
    result = subprocess.run([sys.executable, 'train_model.py', BALANCED_DATASET_PATH], check=False)
    if result.returncode == 0:
        log("✅ Model training finished.")
    else:
        log("❌ Model training failed.")
        return

    # 5. Version Model
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    versioned_file = os.path.join(MODEL_DIR, f"phish_rf_model_{timestamp_str}.pkl")
    if os.path.exists(FINAL_MODEL_PATH):
        os.rename(FINAL_MODEL_PATH, versioned_file)
        log(f"✅ Model versioned to {versioned_file}")
    else:
        log("❌ Final model not found.")

    log("🚀 Pipeline finished successfully.")


if __name__ == "__main__":
    main()
