# app/replay_engine.py
import os, time, json
from dataclasses import dataclass, asdict

import requests

# Optional Playwright
PLAYWRIGHT = os.getenv("CTU_PLAYWRIGHT", "1") == "1"
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

HEADLESS = os.getenv("CTU_PLAYWRIGHT_HEADLESS", "1") == "1"
ENABLE = os.getenv("CTU_BEHAVIOR", "1") == "1"
TIMEOUT_NAV = int(os.getenv("CTU_BEHAVIOR_NAV_TIMEOUT_MS", "10000"))
TIMEOUT_WAIT = int(os.getenv("CTU_BEHAVIOR_WAIT_MS", "2000"))

@dataclass
class BehaviorResult:
    mode: str
    redirect_chain: list
    final_url: str
    status_code: int | None
    js_redirects_detected: int
    post_action_redirects: int
    hidden_revealed_count: int
    dom_mutation_score: float
    form_count: int
    cta_clicks: int
    score: float
    events: list

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))

def simulate(url: str) -> dict:
    """Returns behavior metrics; runs quickly in requests-lite mode, richer with Playwright."""
    if not ENABLE:
        return BehaviorResult("disabled", [], url, None, 0, 0, 0, 0.0, 0, 0, 0.0, []).__dict__

    # ---------- LITE (requests) ----------
    history = []
    status = None
    events = []
    form_count = 0
    try:
        sess = requests.Session()
        r = sess.get(url, timeout=8, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
        status = getattr(r, "status_code", None)
        history = [h.url for h in (getattr(r, "history", []) or [])] + [r.url]
        # naive form count in lite mode
        html = r.text.lower() if isinstance(r.text, str) else ""
        form_count = html.count("<form")
        if len(history) > 1:
            events.append(f"Followed {len(history)-1} HTTP redirect(s).")
    except Exception as e:
        events.append(f"requests-lite error: {e}")

    redirect_chain_len = max(0, len(history) - 1)

    # Default scores from lite mode
    js_redirects = 0
    post_action = 0
    hidden_revealed = 0
    dom_mut = 0.0
    cta_clicks = 0

    # ---------- Playwright enrichment ----------
    mode = "lite"
    if PLAYWRIGHT and PLAYWRIGHT_AVAILABLE:
        mode = "playwright"
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=HEADLESS)
                page = browser.new_page(java_script_enabled=True)
                js_redirects = 0

                def on_request(req):
                    pass
                def on_response(res):
                    pass
                def on_frame_nav(frame):
                    pass

                page.on("request", on_request)
                page.on("response", on_response)
                page.on("framenavigated", on_frame_nav)
                page.on("console", lambda msg: None)

                page.goto(url, timeout=TIMEOUT_NAV)

                # Detect JS-driven navigations
                start_url = page.url
                time.sleep(TIMEOUT_WAIT/1000)
                mid_url = page.url
                if mid_url != start_url and redirect_chain_len == 0:
                    js_redirects += 1
                    events.append("Detected JS-driven redirect after load.")

                # Count forms
                try:
                    form_count = int(page.eval_on_selector_all("form", "els => els.length") or 0)
                except Exception:
                    pass

                # Try clicking a CTA / submit
                candidates = [
                    "button[type=submit]", "input[type=submit]", "button:has-text('Continue')",
                    "button:has-text('Verify')", "a:has-text('Continue')", "a:has-text('Verify')",
                ]
                cta_before_url = page.url
                for sel in candidates:
                    try:
                        el = page.query_selector(sel)
                        if el:
                            el.click(timeout=1500)
                            cta_clicks += 1
                            page.wait_for_timeout(TIMEOUT_WAIT)
                            break
                    except Exception:
                        continue

                if page.url != cta_before_url:
                    post_action += 1
                    events.append("Redirect occurred after CTA/form action.")

                # Hidden content reveal heuristic: check node count change
                try:
                    pre = int(page.eval_on_selector_all("*", "els => els.length") or 0)
                    page.keyboard.press("End")
                    page.wait_for_timeout(800)
                    post = int(page.eval_on_selector_all("*", "els => els.length") or 0)
                    if post > pre:
                        hidden_revealed = min(5, post - pre)
                        events.append(f"Hidden or lazy content revealed (+{hidden_revealed} nodes).")
                except Exception:
                    pass

                # DOM mutation heuristic by comparing HTML lengths
                try:
                    h1 = page.content(); page.wait_for_timeout(700); h2 = page.content()
                    if h1 and h2:
                        dom_mut = _clip01(abs(len(h2) - len(h1)) / max(1, len(h1)))
                        if dom_mut >= 0.02:
                            events.append("Significant DOM mutation after load.")
                except Exception:
                    pass

                browser.close()
        except Exception as e:
            events.append(f"playwright error: {e}")

    # ---------- Scoring ----------
    score = 0.0
    score += 0.35 if redirect_chain_len >= 2 else 0.0
    score += 0.25 if post_action >= 1 else 0.0
    score += 0.20 if js_redirects >= 1 else 0.0
    score += 0.10 * min(3, hidden_revealed)
    score += 0.20 if dom_mut >= 0.05 else 0.0
    score = _clip01(score)

    return BehaviorResult(
        mode=mode,
        redirect_chain=history,
        final_url=history[-1] if history else url,
        status_code=status,
        js_redirects_detected=js_redirects,
        post_action_redirects=post_action,
        hidden_revealed_count=hidden_revealed,
        dom_mutation_score=round(dom_mut, 4),
        form_count=form_count,
        cta_clicks=cta_clicks,
        score=round(score, 3),
        events=events
    ).__dict__
