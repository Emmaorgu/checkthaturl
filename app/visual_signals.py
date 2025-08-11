# app/visual_signals.py
import os
from io import BytesIO

ENABLE = os.getenv("CTU_VISUAL", "0") == "1"

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

try:
    from PIL import Image
    import imagehash
    PIL_OK = True
except Exception:
    PIL_OK = False

VISUAL_DB = os.path.join(os.path.dirname(__file__), "..", "data", "visual_hashes")
TMP_DIR = os.path.join(os.path.dirname(__file__), "..", "tmp")

def _ensure_dirs():
    os.makedirs(VISUAL_DB, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)

def page_screenshot_hash(url: str) -> str | None:
    if not (ENABLE and PLAYWRIGHT_AVAILABLE and PIL_OK):
        return None
    _ensure_dirs()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=12000)
            png = page.screenshot(full_page=True)
            browser.close()
        img = Image.open(BytesIO(png))
        return str(imagehash.phash(img))
    except Exception:
        return None

def compare_to_db(phash_hex: str) -> dict:
    if not phash_hex:
        return {"score": 0.0, "closest": None, "distance": None}
    best_name = None; best_dist = None
    try:
        for fn in os.listdir(VISUAL_DB):
            if not fn.endswith(".txt"): continue
            with open(os.path.join(VISUAL_DB, fn), "r", encoding="utf-8") as f:
                ref = f.read().strip()
            d = imagehash.hex_to_hash(phash_hex) - imagehash.hex_to_hash(ref)
            if (best_dist is None) or d < best_dist:
                best_dist = d; best_name = fn.replace(".txt","")
    except Exception:
        pass
    # Map Hamming distance (0..64) to similarity (1..0)
    if best_dist is None: return {"score": 0.0, "closest": None, "distance": None}
    sim = max(0.0, 1.0 - (best_dist / 64.0))
    return {"score": round(sim,3), "closest": best_name, "distance": int(best_dist)}

def visual_similarity(url: str) -> dict:
    if not ENABLE:
        return {"score": 0.0, "closest": None, "distance": None}
    ph = page_screenshot_hash(url)
    return compare_to_db(ph)
