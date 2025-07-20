import os
import csv
import hashlib
import imagehash
import requests
import urllib3
from PIL import Image
from bs4 import BeautifulSoup
from io import BytesIO
from urllib.parse import urlparse

# Disable SSL warnings (use only for scraping/testing purposes)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUTPUT_FILE = "data/bank_favicon_hashes.csv"
DOMAINS = [
    "https://www.accessbankplc.com",
    "https://www.gtbank.com",
    "https://www.firstbanknigeria.com",
    "https://www.zenithbank.com",
    "https://www.unionbankng.com",
    "https://www.fidelitybank.ng",
    "https://www.ecobank.com/ng/personal-banking",
    "https://www.stanbicibtcbank.com",
    "https://www.keystonebankng.com",
    "https://www.ubagroup.com",
    "https://www.polarisbanklimited.com/"
]

def get_favicon_url(domain_url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(domain_url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Try link[rel=icon]
        icon_link = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if icon_link and icon_link.get("href"):
            href = icon_link["href"]
            if href.startswith("http"):
                return href
            else:
                parsed = urlparse(domain_url)
                return f"{parsed.scheme}://{parsed.netloc}/{href.lstrip('/')}"
        else:
            # Default fallback
            parsed = urlparse(domain_url)
            return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

    except Exception as e:
        print(f"[!] Failed to fetch favicon URL for {domain_url}: {e}")
        return None

def download_favicon(favicon_url):
    try:
        response = requests.get(favicon_url, timeout=10, verify=False)
        if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
            return response.content
        else:
            print(f"[!] Skipped non-image favicon: {favicon_url}")
        return None
    except Exception as e:
        print(f"[!] Error downloading favicon: {e}")
        return None

def compute_image_hash(image_bytes, method='phash'):
    try:
        image = Image.open(BytesIO(image_bytes))
        if image.mode == 'P':
            image = image.convert('RGBA')
        else:
            image = image.convert('RGB')

        if method == 'phash':
            return str(imagehash.phash(image))
        elif method == 'sha256':
            return hashlib.sha256(image_bytes).hexdigest()
    except Exception as e:
        print(f"[!] Error computing hash: {e}")
        return None

def save_hashes(hashes, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["domain", "favicon_url", "phash", "sha256"])
        for entry in hashes:
            writer.writerow([entry['domain'], entry['favicon_url'], entry['phash'], entry['sha256']])

def main():
    hashes = []

    for domain in DOMAINS:
        print(f"[+] Processing {domain}")
        favicon_url = get_favicon_url(domain)
        if not favicon_url:
            continue

        favicon_bytes = download_favicon(favicon_url)
        if not favicon_bytes:
            continue

        phash = compute_image_hash(favicon_bytes, method='phash')
        sha256 = compute_image_hash(favicon_bytes, method='sha256')

        if phash and sha256:
            hashes.append({
                'domain': domain,
                'favicon_url': favicon_url,
                'phash': phash,
                'sha256': sha256
            })

    save_hashes(hashes, OUTPUT_FILE)
    print(f"[✔] Saved favicon hashes to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
