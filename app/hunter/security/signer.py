import os, hmac, hashlib, base64, json, time
from typing import Optional, Dict, Any

_SECRET = (
    os.getenv("HUNTER_SIGNING_SECRET")
    or os.getenv("SECRET_KEY")
    or os.getenv("FLASK_SECRET_KEY")
    or "CHANGE_ME_IMMEDIATELY"
).encode("utf-8")

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def _b64urldecode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def sign(payload: Dict[str, Any]) -> tuple[str, str]:
    """
    Returns (t, s) where:
      t = base64url(JSON(payload))
      s = hex HMAC-SHA256 signature of t
    """
    blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    t = _b64url(blob)
    mac = hmac.new(_SECRET, t.encode("utf-8"), hashlib.sha256).hexdigest()
    return t, mac

def verify(t: str, s: str) -> Optional[Dict[str, Any]]:
    expected = hmac.new(_SECRET, t.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, s):
        return None
    try:
        obj = json.loads(_b64urldecode(t))
    except Exception:
        return None
    exp = obj.get("exp")
    if isinstance(exp, (int, float)) and time.time() > float(exp):
        return None
    return obj
