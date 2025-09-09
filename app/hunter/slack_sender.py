import os, json, time, sys, csv
from pathlib import Path
import requests
from datetime import datetime

# ENV detection
WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL") or os.environ.get("SLACK_WEBHOOK")
BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")

ROOT = Path(os.getcwd())
DATA_DIR = ROOT / "data"
LOG_DIR  = ROOT / "logs"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

NOTIFIED_PATH = DATA_DIR / "notified_ids.json"
RUNS_CSV      = LOG_DIR  / "notify_runs.csv"

def _load_notified():
    if NOTIFIED_PATH.exists():
        try:
            return set(json.loads(NOTIFIED_PATH.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()

def _save_notified(s: set):
    NOTIFIED_PATH.write_text(json.dumps(sorted(list(s))), encoding="utf-8")

def should_skip_id(pid: str) -> bool:
    pid = str(pid)
    notified = _load_notified()
    return pid in notified

def mark_sent_id(pid: str):
    pid = str(pid)
    notified = _load_notified()
    if pid not in notified:
        notified.add(pid)
        _save_notified(notified)

def post_to_slack(payload: dict, max_retries: int = 3, base_delay: float = 0.8) -> bool:
    """
    Sends a Slack message via either Incoming Webhook (preferred) or Bot Token (fallback).
    Retries on 429/5xx with exponential backoff.
    """
    try:
        if WEBHOOK:
            for attempt in range(1, max_retries + 1):
                r = requests.post(WEBHOOK, json=payload, timeout=12)
                if r.status_code == 200 and r.text.strip() == "ok":
                    return True
                if r.status_code in (429, 500, 502, 503, 504):
                    delay = base_delay * (2 ** (attempt - 1))
                    ra = r.headers.get("Retry-After")
                    if ra and str(ra).isdigit():
                        delay = max(delay, float(ra))
                    print(f"[SLACK RETRY] webhook status={r.status_code} attempt={attempt}/{max_retries} sleep={delay}s", file=sys.stderr)
                    time.sleep(delay)
                    continue
                print(f"[SLACK ERROR] webhook status={r.status_code} body={r.text[:300]}", file=sys.stderr)
                return False
            return False

        if BOT_TOKEN and CHANNEL_ID:
            api = "https://slack.com/api/chat.postMessage"
            body = {"channel": CHANNEL_ID}
            if "text" in payload:
                body["text"] = payload["text"]
            if "blocks" in payload:
                body["blocks"] = payload["blocks"]
            headers = {"Authorization": f"Bearer {BOT_TOKEN}", "Content-Type": "application/json;charset=utf-8"}

            for attempt in range(1, max_retries + 1):
                r = requests.post(api, json=body, headers=headers, timeout=12)
                try:
                    data = r.json()
                except Exception:
                    data = {"ok": False, "raw": r.text[:300]}
                if data.get("ok") is True:
                    return True
                if r.status_code in (429, 500, 502, 503, 504) or data.get("error") in ("ratelimited",):
                    delay = base_delay * (2 ** (attempt - 1))
                    ra = r.headers.get("Retry-After")
                    if ra and str(ra).isdigit():
                        delay = max(delay, float(ra))
                    print(f"[SLACK RETRY] bot status={r.status_code} attempt={attempt}/{max_retries} sleep={delay}s resp={data}", file=sys.stderr)
                    time.sleep(delay)
                    continue
                print(f"[SLACK BOT ERROR] status={r.status_code} resp={data}", file=sys.stderr)
                return False
            return False

        print("[SLACK ERROR] No WEBHOOK or BOT_TOKEN+CHANNEL_ID configured.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[SLACK EXCEPTION] {type(e).__name__}: {e}", file=sys.stderr)
        return False

def log_run(state: str, limit: int, sent: int, failed: int):
    with open(RUNS_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([datetime.utcnow().isoformat(), state, limit, sent, failed])
