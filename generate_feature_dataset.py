import os
import pandas as pd
import time
from extract_features import safe_extract, extract_features
from concurrent.futures import ThreadPoolExecutor, as_completed

# === File Paths ===
CLONED_HTML_DIR = 'data/cloned_phishing_sites'
LEGIT_URLS_CSV = 'data/legit_urls.csv'
PHISHING_URLS_CSV = 'data/real_phishing_urls.csv'
GLOBAL_PHISHING_CSV = 'data/global_phishing_urls.csv'
OUTPUT_CSV = 'data/feature_dataset.csv'

# === Debug Limit (None = process all) ===
LIMIT = None  # e.g., 50 for quick testing
MAX_WORKERS = 10

def load_url_csv(filepath):
    """Load a CSV file and ensure 'url' column exists."""
    try:
        df = pd.read_csv(filepath)
        if 'url' not in df.columns:
            print(f"[!] 'url' column missing in {filepath}, assuming no header...")
            df = pd.read_csv(filepath, header=None)
            df.columns = ['url']
        return df
    except Exception as e:
        print(f"[✗] Failed to read {filepath}: {e}")
        return pd.DataFrame(columns=['url'])

def process_url_dataset(filepath, label):
    """Extract features from URLs using ThreadPoolExecutor."""
    df = load_url_csv(filepath)
    if LIMIT:
        df = df.head(LIMIT)

    features_list = []
    print(f"[+] Starting parallel extraction for {len(df)} URLs with label {label}...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(safe_extract, url, label) for url in df['url']]
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                features_list.append(result)
                print(f"[{i}/{len(futures)}] ✓ Feature extracted. JS Timer: {result.get('has_js_timer')}, HTML Timer: {result.get('has_html_timer')}")
    return features_list

def process_cloned_html_sites(directory):
    """Extract features from locally saved cloned phishing HTML files (sequentially)."""
    features_list = []

    if not os.path.exists(directory):
        print(f"[✗] Directory not found: {directory}")
        return features_list

    files = [f for f in os.listdir(directory) if f.endswith('.html')]
    if LIMIT:
        files = files[:LIMIT]

    for i, filename in enumerate(files, 1):
        filepath = os.path.join(directory, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                html_content = file.read()
                fake_url = f"http://fake-{filename.replace('.html', '')}.xyz"
                print(f"[{i}/{len(files)}] Extracting features from cloned: {filename}")
                start = time.time()
                features = extract_features(fake_url, html_content)
                features['label'] = 1  # Phishing
                features_list.append(features)
                print(f"[✓] Done in {time.time() - start:.2f} sec. JS Timer: {features.get('has_js_timer')}, HTML Timer: {features.get('has_html_timer')}")
        except Exception as e:
            print(f"[✗] Failed to process {filename}: {e}")
            continue

    return features_list

if __name__ == "__main__":
    start_time = time.time()
    all_features = []

    print("\n[+] Processing legitimate URLs...")
    all_features += process_url_dataset(LEGIT_URLS_CSV, label=0)

    print("\n[+] Processing real phishing URLs...")
    all_features += process_url_dataset(PHISHING_URLS_CSV, label=1)

    print("\n[+] Processing global phishing URLs (OpenPhish, URLhaus)...")
    all_features += process_url_dataset(GLOBAL_PHISHING_CSV, label=1)

    print("\n[+] Processing cloned phishing HTML files...")
    all_features += process_cloned_html_sites(CLONED_HTML_DIR)

    if all_features:
        df = pd.DataFrame(all_features)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n[✓] Feature dataset saved to: {OUTPUT_CSV}")
        print(f"[✓] Total records: {len(df)}")
        print(f"[✓] Total time: {time.time() - start_time:.2f} seconds")
    else:
        print("[✗] No features extracted — dataset not created.")
