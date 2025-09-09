# --------------------------------------------
# Base image
# --------------------------------------------
FROM python:3.11-slim

# Bump to force cache bust on Render when needed
ARG CACHEBUST=2025-09-09-02

# Minimal OS deps; dumb-init for PID1 signals
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dumb-init \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONPATH=/app

WORKDIR /app

# ---- Install Python deps first (best caching) ----
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# ---- Verify critical packages exist (fail fast if not) ----
RUN python - <<'PY'
import importlib, sys
for mod in ("flask", "flask_sqlalchemy", "sqlalchemy"):
    try:
        importlib.import_module(mod)
        print(f"[OK] {mod}")
    except Exception as e:
        print(f"[FAIL] {mod}: {e}")
        sys.exit(1)
PY

# ---- Playwright + Chromium (with system deps) ----
RUN pip install --no-cache-dir playwright \
 && python -m playwright install --with-deps chromium

# ---- App code last ----
COPY . /app

# ---- Gunicorn start ----
ENV PORT=10000
# If you use an app factory, set APP_MODULE to "app.app:create_app()"
ENV APP_MODULE="app.app:app"

# Use dumb-init for clean signal handling
CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "app.app:app"]
# Alternative (use APP_MODULE env):
# CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "${APP_MODULE}"]
