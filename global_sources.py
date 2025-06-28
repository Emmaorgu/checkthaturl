import requests
import base64
import json
import time
from pathlib import Path
from dotenv import load_dotenv
import os
import pandas as pd

# Load environment variables
load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Directories
CACHE_DIR = Path("phishing_feeds_cache")
CACHE_DIR.mkdir(exist_ok=True)
GLOBAL_CSV = Path("data/global_phishing_urls.csv")

def fetch_openphish_urls():
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        if response.status_code == 200:
            urls = response.text.strip().splitlines()
            cache_path = CACHE_DIR / "openphish_urls.json"
            with open(cache_path, "w") as f:
                json.dump(urls, f)
            return urls
    except Exception as e:
        print(f"[OpenPhish Error] {e}")
    return []

def fetch_urlhaus_urls():
    try:
        response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = [entry['url'] for entry in data.get("urls", []) if 'url' in entry]
            cache_path = CACHE_DIR / "urlhaus_urls.json"
            with open(cache_path, "w") as f:
                json.dump(urls, f)
            return urls
    except Exception as e:
        print(f"[URLhaus Error] {e}")
    return []

def deduplicate_and_append(new_urls, csv_path):
    if csv_path.exists():
        existing_df = pd.read_csv(csv_path)
        existing_urls = set(existing_df['url'].tolist())
    else:
        existing_df = pd.DataFrame(columns=["url"])
        existing_urls = set()

    unique_new_urls = [url for url in new_urls if url not in existing_urls]
    print(f"[+] {len(unique_new_urls)} new URLs will be appended (out of {len(new_urls)} fetched)")

    if unique_new_urls:
        new_df = pd.DataFrame({"url": unique_new_urls})
        updated_df = pd.concat([existing_df, new_df], ignore_index=True)
        updated_df.to_csv(csv_path, index=False)
        print(f"[✓] Updated global phishing dataset saved to: {csv_path}")
    else:
        print("[✓] No new URLs to append.")

def fetch_all_sources():
    print("[INFO] Fetching from OpenPhish...")
    openphish = fetch_openphish_urls()
    time.sleep(1)

    print("[INFO] Fetching from URLhaus...")
    urlhaus = fetch_urlhaus_urls()
    time.sleep(1)

    all_urls = openphish + urlhaus
    print(f"[INFO] Total URLs fetched: {len(all_urls)}")

    deduplicate_and_append(all_urls, GLOBAL_CSV)

    return all_urls  # Add this

if __name__ == "__main__":
    fetch_all_sources()
