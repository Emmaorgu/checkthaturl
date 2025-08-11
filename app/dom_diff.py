# app/dom_diff.py
import os, math, json
from collections import Counter
from bs4 import BeautifulSoup

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "dom_templates")

def _signature(html: str) -> Counter:
    soup = BeautifulSoup(html or "", "html.parser")
    counts = Counter(el.name for el in soup.find_all())
    # add depth histogram (approx.)
    depths = Counter()
    def depth(n, d=0):
        for c in getattr(n, "children", []):
            try:
                if getattr(c, "name", None): depths[d] += 1; depth(c, d+1)
            except Exception: pass
    try:
        depth(soup, 0)
    except Exception:
        pass
    for k,v in depths.items():
        counts[f"depth_{k}"] = v
    return counts

def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b: return 0.0
    keys = set(a.keys()) | set(b.keys())
    va = [a.get(k,0.0) for k in keys]; vb = [b.get(k,0.0) for k in keys]
    dot = sum(x*y for x,y in zip(va,vb))
    na = math.sqrt(sum(x*x for x in va)); nb = math.sqrt(sum(y*y for y in vb))
    if na==0 or nb==0: return 0.0
    return float(dot/(na*nb))

def structure_similarity(html: str) -> dict:
    sig = _signature(html)
    best = 0.0; best_name = None
    if os.path.isdir(TEMPLATE_DIR):
        for fn in os.listdir(TEMPLATE_DIR):
            if not fn.endswith(".json"): continue
            try:
                with open(os.path.join(TEMPLATE_DIR, fn), "r", encoding="utf-8") as f:
                    ref = Counter(json.load(f))
                sim = _cosine(sig, ref)
                if sim > best:
                    best = sim; best_name = fn.replace(".json","")
            except Exception:
                continue
    return {"score": round(best,3), "template": best_name}

def export_template(name: str, html: str) -> str:
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    sig = _signature(html)
    path = os.path.join(TEMPLATE_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sig, f)
    return path
