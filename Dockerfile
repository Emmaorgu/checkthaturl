# --------------------------------------------
# Base image
# --------------------------------------------
FROM python:3.11-slim

# Bump to force cache bust when needed
ARG CACHEBUST=2025-09-09-03

# --------------------------------------------
# OS basics + Chromium runtime deps
# --------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dumb-init \
    # Chromium runtime dependencies for Playwright on Debian
    libnss3 libatk-bridge2.0-0 libgtk-3-0 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libasound2 \
    # Fonts (Debian package names)
    fonts-unifont fonts-ubuntu \
 && rm -rf /var/lib/apt/lists/*

# --------------------------------------------
# Environment
# --------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONPATH=/app

WORKDIR /app

# --------------------------------------------
# Install Python deps first (cache friendly)
# --------------------------------------------
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# Verify critical deps exist (fail fast if not installed)
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

# --------------------------------------------
# Playwright + Chromium
# (drop --with-deps; we installed Debian deps already)
# --------------------------------------------
RUN pip install --no-cache-dir playwright \
 && python -m playwright install chromium

# --------------------------------------------
# Copy application code
# --------------------------------------------
COPY . /app

# --------------------------------------------
# Start command
# --------------------------------------------
ENV PORT=10000
# Default app entry; override APP_MODULE if you use factory
ENV APP_MODULE="app.app:app"

CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "app.app:app"]
# Or use APP_MODULE:
# CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "${APP_MODULE}"]
