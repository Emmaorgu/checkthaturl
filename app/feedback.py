# app/feedback.py
import os, time, json, hashlib, hmac, threading
from flask import Blueprint, request, jsonify

feedback_bp = Blueprint("feedback", __name__)

FEEDBACK_ENABLED = os.getenv("CTU_FEEDBACK", "1") == "1"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

FEEDBACK_PATH = os.path.join(DATA_DIR, "feedback.jsonl")   # up/down votes + notes
REPORTS_PATH  = os.path.join(DATA_DIR, "reports.jsonl")    # false pos/neg reports
SALT          = (os.getenv("CTU_FEEDBACK_SALT") or "ctu_default_salt").encode("utf-8")

_RATE = {}         # { key: [ts, ...] }
_RATE_LOCK = threading.Lock()
MAX_HOURLY = 40    # per anon key, soft limit

def _now() -> int: return int(time.time())

def _anonymize(request) -> str:
    # DO NOT store IP; only a salted HMAC of the User-Agent
    ua = (request.headers.get("User-Agent") or "").encode("utf-8")
    return hmac.new(SALT, ua, hashlib.sha256).hexdigest()[:16]

def _ratelimit(key: str) -> bool:
    with _RATE_LOCK:
        ts = _now()
        L = [t for t in _RATE.get(key, []) if ts - t < 3600]
        allowed = len(L) < MAX_HOURLY
        if allowed:
            L.append(ts)
            _RATE[key] = L
        return allowed

def _append_jsonl(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def _sanitize_url(u: str) -> str:
    return (u or "").strip()[:2048]

@feedback_bp.route("/feedback", methods=["POST"])
def feedback():
    if not FEEDBACK_ENABLED:
        return jsonify({"ok": False, "error": "feedback disabled"}), 403
    try:
        j = request.get_json(force=True) or {}
        url      = _sanitize_url(j.get("url"))
        verdict  = (j.get("verdict") or "").strip()[:32]
        helpful  = bool(j.get("helpful"))
        notes    = (j.get("notes") or "").strip()[:500]
        anon     = _anonymize(request)

        if not _ratelimit(anon):
            return jsonify({"ok": False, "error": "rate_limited"}), 429

        _append_jsonl(FEEDBACK_PATH, {
            "ts": _now(), "anon": anon, "url": url,
            "verdict": verdict, "helpful": helpful, "notes": notes
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@feedback_bp.route("/report", methods=["POST"])
def report():
    if not FEEDBACK_ENABLED:
        return jsonify({"ok": False, "error": "feedback disabled"}), 403
    try:
        j = request.get_json(force=True) or {}
        url         = _sanitize_url(j.get("url"))
        report_type = (j.get("type") or "").lower()[:8]   # "fp" or "fn"
        verdict     = (j.get("verdict") or "").strip()[:32]
        notes       = (j.get("notes") or "").strip()[:500]
        anon        = _anonymize(request)

        if report_type not in ("fp", "fn"):
            return jsonify({"ok": False, "error": "invalid_type"}), 400
        if not _ratelimit(anon):
            return jsonify({"ok": False, "error": "rate_limited"}), 429

        _append_jsonl(REPORTS_PATH, {
            "ts": _now(), "anon": anon, "url": url,
            "type": report_type, "verdict": verdict, "notes": notes
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@feedback_bp.route("/metrics/feedback", methods=["GET"])
def metrics():
    try:
        up = down = total = 0
        if os.path.exists(FEEDBACK_PATH):
            with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    total += 1
                    try:
                        o = json.loads(line)
                        (up if o.get("helpful") else down).__class__  # no-op to keep style
                        if o.get("helpful"): up += 1
                        else: down += 1
                    except Exception:
                        pass
        return jsonify({"ok": True, "total": total, "helpful": up, "not_helpful": down})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
