# app/replay_engine.py
from __future__ import annotations

"""
Resilient Playwright-based behavior engine for CheckThatURL.

Key improvements (keeps public fields & logic intact):
- Safe Chromium flags via CTU_PW_ARGS (defaults included) for container hosts.
- Stealth hardening to reduce headless/automation fingerprinting.
- Env-configurable budgets/timeouts (CTU_BEHAVIOR_BUDGET, CTU_CONNECT_TIMEOUT, etc.).
- More robust redirect & DOM-mutation capture with MutationObserver and size deltas.
- Cookie/consent auto-click; conservative CTA clicker avoids commerce/payment CTAs.
- Graceful partial results on time budget exhaustion instead of silent failures.
"""

import os
import re
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# -----------------------------
# Playwright import (safe)
# -----------------------------
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PLAYWRIGHT_IMPORT_ERR = None
except Exception as e:
    sync_playwright = None
    PWTimeout = Exception
    _PLAYWRIGHT_IMPORT_ERR = f"{type(e).__name__}: {e}"

# -----------------------------
# Env / tunables
# -----------------------------
def _env_bool(name: str, default: bool = True) -> bool:
    v = os.getenv(name, str(int(default))).strip().lower()
    return v not in {"0", "false", "no", ""}

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

# Overall behavior budget (seconds)
BEHAVIOR_BUDGET = _env_float("CTU_BEHAVIOR_BUDGET", 6.0)

# Default page timeout (ms) for operations inside Playwright
PAGE_TIMEOUT_MS = int(_env_float("CTU_PAGE_TIMEOUT_MS", 30000))

# Headless flag (Render should be headless=1)
HEADLESS = _env_bool("HEADLESS", True)

# Safe Chromium flags for containers
DEFAULT_PW_ARGS = (
    "--no-sandbox,"
    "--disable-dev-shm-usage,"
    "--disable-gpu,"
    "--disable-setuid-sandbox,"
    "--single-process,"
    "--disable-features=IsolateOrigins,site-per-process,"
    "--disable-blink-features=AutomationControlled"
)
PW_ARGS = [a.strip() for a in os.getenv("CTU_PW_ARGS", DEFAULT_PW_ARGS).split(",") if a.strip()]

# Locale / timezone
TZ = os.getenv("TZ", "Africa/Lagos")
LOCALE = os.getenv("CTU_LOCALE", "en-GB")

# Browser UA (close to stable Chrome)
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# -----------------------------
# Heuristics / keyword patterns
# -----------------------------

# CTA candidates (keep 'open' out to avoid benign clicks)
CTA_KEYWORDS = [
    "apply","login","log in","verify","continue","proceed","start","get started","claim",
    "submit","next","update","confirm","access","unlock","activate",
    "finish","complete","protection","secure","agree","accept","allow","grant","verify now",
    "start here","begin"
]
CLICK_CANDIDATE_RE = re.compile("|".join(re.escape(k) for k in CTA_KEYWORDS), re.I)

# Explicitly avoid commerce/payment CTAs
ECOMMERCE_AVOID = [
    "pay","buy","checkout","add to cart","add-to-cart","cart","top up","top-up",
    "deposit","fund wallet","fund-wallet","transfer","send money","pay now","buy now",
]
AVOID_RE = re.compile("|".join(re.escape(k) for k in ECOMMERCE_AVOID), re.I)

# Timer patterns
TIMER_HINT_RE = re.compile(
    r"(count\s*down|countdown|time\s*left|expires\s*in|seconds?\s*left|minutes?\s*left|"
    r"hurry|remaining|offer\s*ends|expires|only\s+\d+\s+(secs?|seconds?|mins?|minutes?)\s+left)",
    re.I
)
MMSS_RE = re.compile(r"\b(\d{1,2})\s*:\s*([0-5]?\d)\b")
MINSEC_RE = re.compile(r"\b(\d{1,2})\s*(?:min|mins|minutes)\s*(\d{1,2})\s*(?:sec|secs|seconds)\b", re.I)
PLAIN_SECS_RE = re.compile(r"\b(\d{1,3})\s*(?:sec|secs|seconds|s)\b", re.I)

TIMER_SELECTORS = [
    "#countdown",".countdown","[data-countdown]","[data-count-down]",
    "#timer",".timer","[data-timer]","[data-time-left]",
    "#countdown-timer",".countdown-timer"
]

# registrable domain helper (light public-suffix handling)
MULTIPART_TLDS = (
    "co.uk","org.uk","gov.uk","ac.uk",
    "com.au","net.au","org.au",
    "com.br","com.mx","com.tr","com.ng","co.jp"
)
def _registrable_domain(u: str) -> str:
    try:
        h = urlparse(u).netloc.split(":")[0].lower()
        parts = h.split(".")
        if len(parts) < 2: return h
        last2, last3 = ".".join(parts[-2:]), ".".join(parts[-3:])
        if any(last3.endswith(tld) for tld in MULTIPART_TLDS) and len(parts) >= 3:
            return last3
        return last2
    except Exception:
        return ""

# -----------------------------
# Result container
# -----------------------------
@dataclass
class BehaviorResult:
    mode: str = "disabled"
    score: float = 0.0
    events: Optional[List[str]] = None
    dom_mutation_score: float = 0.0

    js_redirects_detected: int = 0
    http_redirects: int = 0

    post_action_redirects: int = 0
    client_redirects: int = 0

    js_redirects_same_site: int = 0
    js_redirects_cross_site: int = 0
    client_redirects_same_site: int = 0
    client_redirects_cross_site: int = 0
    post_action_redirects_form: int = 0
    post_action_redirects_click: int = 0

    redirect_chain: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["events"] = d["events"] or []
        d["redirect_chain"] = d["redirect_chain"] or []
        d["post_action_redirects"] = int(d.get("post_action_redirects_form", 0)) + int(d.get("post_action_redirects_click", 0))
        d["client_redirects"] = int(d.get("client_redirects_cross_site", 0)) + int(d.get("client_redirects_same_site", 0))
        d["js_redirects_detected"] = int(d.get("js_redirects_cross_site", 0)) + int(d.get("js_redirects_same_site", 0))
        return d

# -----------------------------
# Scoring
# -----------------------------
def _score_from_signals(
    has_click: bool,
    post_redirects_form: int,
    js_redirs_cross: int,
    client_redirs_cross: int,
    dom_mutation: float,
    timer_found: bool,
    timer_decreasing: bool
) -> float:
    score = 0.0
    if has_click: score += 0.08
    if post_redirects_form: score += min(0.36, 0.20 * post_redirects_form)
    total_soft_cross = (js_redirs_cross or 0) + (client_redirs_cross or 0)
    if total_soft_cross: score += min(0.22, 0.16 * total_soft_cross)
    score += min(0.20, (dom_mutation or 0) * 1.6)
    if timer_found: score += 0.08
    if timer_decreasing: score += 0.18
    return max(0.0, min(1.0, score))

# -----------------------------
# Init scripts (mutation + stealth)
# -----------------------------
def _inject_mutation_observer_script() -> str:
    return """
        (() => {
            try {
                if (!window.__ctu_obs_installed) {
                    window.__ctu_mutations = 0;
                    const obs = new MutationObserver(muts => { window.__ctu_mutations += muts.length; });
                    const root = document.documentElement || document.body;
                    if (root) obs.observe(root, { attributes:true, childList:true, subtree:true, characterData:true });
                    window.__ctu_getMutations = () => window.__ctu_mutations;
                    window.__ctu_obs_installed = true;
                }
            } catch(e) {}
        })();
    """

def _stealth_script() -> str:
    # Minimal stealth to reduce automation fingerprints
    return """
        // webdriver flag
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        // chrome object
        window.chrome = { runtime: {} };
        // languages/plugins
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
        // permissions query stub
        const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
        if (originalQuery) {
            window.navigator.permissions.query = (parameters) =>
              parameters.name === 'notifications'
                ? Promise.resolve({ state: Notification.permission })
                : originalQuery(parameters);
        }
    """

# -----------------------------
# Frame helpers
# -----------------------------
def _frame_text(frame) -> str:
    try:
        return frame.evaluate("() => (document.body && document.body.innerText) || ''")
    except Exception:
        return ""

def _query_timer_nodes(frame) -> List[str]:
    out: List[str] = []
    try:
        for sel in TIMER_SELECTORS:
            try:
                loc = frame.locator(sel)
                n = min(loc.count(), 20)
                for i in range(n):
                    try:
                        t = (loc.nth(i).inner_text() or "").strip()
                        if t: out.append(t)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return out

def _get_mutations(frame) -> int:
    try:
        return int(frame.evaluate("window.__ctu_getMutations ? window.__ctu_getMutations() : 0"))
    except Exception:
        return 0

def _scroll_frame(frame, bumps=(800, 1600, 2600, 3600)) -> None:
    for y in bumps:
        try:
            frame.evaluate(f"window.scrollBy(0,{y});")
            time.sleep(0.30)
        except Exception:
            break

def _click_consent_if_present(page, events) -> bool:
    words = ["accept","agree","allow","continue","got it","ok"]
    try:
        for w in words:
            try:
                el = page.get_by_text(w, exact=False)
                if el and el.count() > 0:
                    el.first.click(timeout=900)
                    events.append(f"consent_click:{w}")
                    time.sleep(0.25)
                    return True
            except Exception:
                continue
        for css in ["#accept", "[aria-label*=accept i]", "button:has-text('Accept')", "#ok", "#agree"]:
            try:
                page.locator(css).first.click(timeout=900)
                events.append(f"consent_click_css:{css}")
                time.sleep(0.25)
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def _avoid_login_without_password(frame, text: str) -> bool:
    try:
        if re.search(r"\blog\s*in\b", text or "", re.I):
            if frame.locator("input[type='password']").count() == 0:
                return True
    except Exception:
        pass
    return False

def _avoid_ecommerce(text: str) -> bool:
    try:
        return bool(AVOID_RE.search(text or ""))
    except Exception:
        return False

def _try_clicks(frame, events) -> bool:
    # Target buttons/links with CTA words but avoid commerce/payment CTAs
    try:
        btns = frame.get_by_role("button")
        n = min(btns.count(), 100)
        for i in range(n):
            el = btns.nth(i)
            try: txt = (el.inner_text() or "").strip()
            except Exception: txt = ""
            if not txt: continue
            if _avoid_ecommerce(txt) or _avoid_login_without_password(frame, txt): continue
            if CLICK_CANDIDATE_RE.search(txt):
                try:
                    el.scroll_into_view_if_needed()
                    el.click(timeout=1500)
                    events.append(f"click(button):{txt[:90]}")
                    return True
                except Exception:
                    continue
    except Exception:
        pass

    try:
        generic = frame.locator("a,button,input[type=submit],input[type=button]")
        n = min(generic.count(), 150)
        for i in range(n):
            el = generic.nth(i)
            try: txt = (el.inner_text() or "").strip()
            except Exception: txt = ""
            if not txt: continue
            if _avoid_ecommerce(txt) or _avoid_login_without_password(frame, txt): continue
            if CLICK_CANDIDATE_RE.search(txt):
                try:
                    el.scroll_into_view_if_needed()
                    el.click(timeout=1500)
                    events.append(f"click(generic):{txt[:90]}")
                    return True
                except Exception:
                    continue
    except Exception:
        pass

    for kw in CTA_KEYWORDS:
        try:
            el = frame.get_by_text(kw, exact=False)
            if el and el.count() > 0:
                if _avoid_login_without_password(frame, kw): continue
                el.first.scroll_into_view_if_needed()
                el.first.click(timeout=1500)
                events.append(f"click(text):{kw}")
                return True
        except Exception:
            continue
    return False

def _try_form_submit(frame, events) -> bool:
    did = False
    try:
        for sel, val in [
            ("input[type='email'], input[name*=email i], input[id*=email i]", "user@example.com"),
            ("input[type='text'][name*=user i], input[name*=login i], input[id*=user i]", "testuser"),
            ("input[type='password']", "Password!23"),
        ]:
            loc = frame.locator(sel)
            if loc.count() > 0:
                try:
                    loc.first.fill(val, timeout=1200)
                    did = True
                except Exception:
                    pass
        btn = frame.locator("button[type='submit'], input[type='submit']")
        if btn.count() > 0:
            try:
                btn.first.scroll_into_view_if_needed()
                btn.first.click(timeout=1500)
                events.append("click:submit")
                return True
            except Exception:
                pass
    except Exception:
        pass
    return did

def _extract_time_candidates(txt: str) -> List[int]:
    if not txt: return []
    vals: List[int] = []
    for m, s in MMSS_RE.findall(txt):
        try: vals.append(int(m)*60 + int(s))
        except Exception: pass
    for m, s in MINSEC_RE.findall(txt):
        try: vals.append(int(m)*60 + int(s))
        except Exception: pass
    for s in PLAIN_SECS_RE.findall(txt):
        try:
            z = int(s)
            if 0 < z <= 600: vals.append(z)
        except Exception: pass
    return vals

def _sample_timer_seconds(page) -> Optional[int]:
    mins: List[int] = []
    try:
        for f in page.frames:
            base_txt = _frame_text(f)
            cands = _extract_time_candidates(base_txt)
            for ttxt in _query_timer_nodes(f):
                cands.extend(_extract_time_candidates(ttxt))
            if cands: mins.append(min(cands))
    except Exception:
        pass
    return min(mins) if mins else None

# -----------------------------
# Main entry
# -----------------------------
def simulate(url: str, max_time: float | None = None) -> Dict[str, Any]:
    """
    Returns dict with keys expected by app.py:
    - score, events, dom_mutation_score
    - js_redirects_detected, http_redirects
    - client_redirects(_same_site/_cross_site), js_redirects_(...)
    - post_action_redirects_form, post_action_redirects_click
    - redirect_chain
    mode: "playwright" or "error"
    """
    if sync_playwright is None:
        msg = _PLAYWRIGHT_IMPORT_ERR or "playwright not installed"
        return BehaviorResult(mode="error", events=[f"playwright import failed: {msg}"]).to_dict()

    budget = float(max_time) if max_time is not None else BEHAVIOR_BUDGET
    t_start = time.monotonic()

    def time_left() -> float:
        return budget - (time.monotonic() - t_start)

    events: List[str] = []
    chain: List[str] = []
    dom_sizes: List[int] = []
    js_cross = js_same = 0
    client_cross = client_same = 0
    post_redirs_form = post_redirs_click = 0
    http_redirs = 0
    clicked = False
    timer_found = False
    timer_decreasing = False

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=HEADLESS,
                args=PW_ARGS
            )
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1366, "height": 900},
                user_agent=BROWSER_UA,
                locale=LOCALE,
                timezone_id=TZ,
                extra_http_headers={
                    "Accept-Language": "en,en-GB;q=0.9,en-NG;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                }
            )
            # Install scripts
            context.add_init_script(_stealth_script())
            context.add_init_script(_inject_mutation_observer_script())
            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)
            page.add_init_script(_stealth_script())
            page.add_init_script(_inject_mutation_observer_script())

            # Prevent blocking dialogs
            try:
                page.on("dialog", lambda d: d.dismiss())
            except Exception:
                pass

            # HTTP redirect detector
            def on_response(resp):
                nonlocal http_redirs
                try:
                    if resp.status in (301, 302, 303, 307, 308):
                        http_redirs += 1
                except Exception:
                    pass
            context.on("response", on_response)

            # Client-side navigation tracker
            main_nav_seen = False
            def on_framenav(frame):
                nonlocal client_cross, client_same, main_nav_seen
                try:
                    if frame == page.main_frame:
                        curr = frame.url or ""
                        if not main_nav_seen:
                            main_nav_seen = True
                            if curr:
                                chain.clear()
                                chain.append(curr)  # seed chain (not a redirect)
                            return
                        prev = chain[-1] if chain else ""
                        if curr and curr != prev:
                            if _registrable_domain(prev) == _registrable_domain(curr):
                                client_same += 1
                                events.append(f"client_nav_intra:{prev}→{curr}")
                            else:
                                client_cross += 1
                                events.append(f"client_redirect:{prev}→{curr}")
                            chain.append(curr)
                except Exception:
                    pass
            page.on("framenavigated", on_framenav)

            # Navigate
            page.goto(url, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass

            if not chain:
                chain.append(page.url)
            events.append(f"load:{page.url}")
            events.append(f"frames:{len(page.frames)}")

            _click_consent_if_present(page, events)

            # Early DOM size samples
            for _ in range(2):
                if time_left() <= 0: break
                time.sleep(0.6)
                try: dom_sizes.append(len(page.content()))
                except Exception: dom_sizes.append(0)

            # Scroll to trigger lazy JS
            for f in [page.main_frame] + [f for f in page.frames if f != page.main_frame]:
                _scroll_frame(f)

            # Timer hint detection (text + common selectors)
            try:
                for f in page.frames:
                    if time_left() <= 0: break
                    txt = _frame_text(f)
                    if TIMER_HINT_RE.search(txt) or MMSS_RE.search(txt) or MINSEC_RE.search(txt) or PLAIN_SECS_RE.search(txt):
                        timer_found = True; break
                    for ttxt in _query_timer_nodes(f):
                        if TIMER_HINT_RE.search(ttxt) or MMSS_RE.search(ttxt) or MINSEC_RE.search(ttxt) or PLAIN_SECS_RE.search(ttxt):
                            timer_found = True; break
                    if timer_found: break
                if timer_found: events.append("timer_hint_detected")
            except Exception:
                pass

            # Try clicks/forms (form redirects influence score more)
            for f in [page.main_frame] + [f for f in page.frames if f != page.main_frame]:
                if time_left() <= 0: break
                if _try_clicks(f, events):
                    clicked = True
                    time.sleep(0.9)
                    if chain and page.url != chain[-1]:
                        prev, curr = chain[-1], page.url
                        post_redirs_click += 1
                        events.append(f"post_action_redirect_click:{prev}→{curr}")
                        chain.append(curr)
                        break
                if _try_form_submit(f, events):
                    time.sleep(0.9)
                    if chain and page.url != chain[-1]:
                        prev, curr = chain[-1], page.url
                        post_redirs_form += 1
                        events.append(f"post_action_redirect_form:{prev}→{curr}")
                        chain.append(curr)
                        break

            # Observe ongoing JS navigations + DOM growth
            last_url = chain[-1] if chain else page.url
            for _ in range(5):
                if time_left() <= 0: break
                time.sleep(0.8)
                try: dom_sizes.append(len(page.content()))
                except Exception: dom_sizes.append(0)
                if page.url != last_url:
                    prev, curr = last_url, page.url
                    if _registrable_domain(prev) == _registrable_domain(curr):
                        js_same += 1
                        events.append(f"js_nav_intra:{prev}→{curr}")
                    else:
                        js_cross += 1
                        events.append(f"js_redirect:{prev}→{curr}")
                    chain.append(curr)
                    last_url = curr

            # Decreasing timer sampler
            t0 = _sample_timer_seconds(page); time.sleep(1.0)
            t1 = _sample_timer_seconds(page); time.sleep(1.0)
            t2 = _sample_timer_seconds(page)
            samples = [t for t in (t0, t1, t2) if t is not None]
            if len(samples) >= 2 and min(samples[1:]) < samples[0]:
                timer_decreasing = True; events.append("timer_decreasing_confirmed")

            # Build DOM mutation score (observer + size variation)
            html_span = (max(dom_sizes) - min(dom_sizes)) if dom_sizes else 0
            baseline = max(5000, min(dom_sizes) if dom_sizes else 5000)
            size_component = min(1.0, html_span / max(5000, baseline))
            try: obs_total = sum(_get_mutations(f) for f in page.frames)
            except Exception: obs_total = 0
            obs_component = 1.0 - pow(0.998, max(0, obs_total))
            dom_mutation = max(size_component, obs_component)

            # Deduplicate redirect chain
            cleaned: List[str] = []
            for u in chain:
                if not cleaned or cleaned[-1] != u:
                    cleaned.append(u)

            score = _score_from_signals(
                clicked, post_redirs_form, js_cross, client_cross,
                dom_mutation, timer_found, timer_decreasing
            )

            try:
                context.close(); browser.close()
            except Exception:
                pass

            return BehaviorResult(
                mode="playwright",
                score=round(score, 3),
                events=events,
                dom_mutation_score=round(dom_mutation, 3),
                js_redirects_detected=js_cross + js_same,
                http_redirects=http_redirs,
                client_redirects=client_cross + client_same,
                js_redirects_same_site=js_same,
                js_redirects_cross_site=js_cross,
                client_redirects_same_site=client_same,
                client_redirects_cross_site=client_cross,
                post_action_redirects_form=post_redirs_form,
                post_action_redirects_click=post_redirs_click,
                redirect_chain=cleaned
            ).to_dict()

    except PWTimeout:
        events.append("timeout")
    except Exception as e:
        events.append(f"error:{type(e).__name__}:{e}")

    # On error, return a structured payload (mode=error) so app.py can still blend safely.
    return BehaviorResult(mode="error", score=0.0, events=events).to_dict()
