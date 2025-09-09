# --------------------------------------------
# Base image
# --------------------------------------------
FROM python:3.11-slim

# Bump to force cache bust when needed
ARG CACHEBUST=2025-09-09-05

# --------------------------------------------
# OS basics + Chromium runtime deps (Debian names)
# --------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dumb-init \
    # Chromium/Playwright runtime libraries
    libnss3 libatk-bridge2.0-0 libgtk-3-0 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libasound2 \
    # Fonts (Debian packages; replace unavailable fonts-ubuntu)
    fonts-dejavu fonts-noto-core fonts-noto-color-emoji fonts-unifont \
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
# (no --with-deps; we installed Debian libs above)
# --------------------------------------------
RUN pip install --no-cache-dir playwright \
 && python -m playwright install chromium

# --------------------------------------------
# Copy application code
# --------------------------------------------
COPY . /app

# --------------------------------------------
# Start command (use bash so $PORT expands on Render)
# --------------------------------------------
ENV PORT=10000
# Default app entry; set APP_MODULE to "app.app:create_app()" if you use a factory.
ENV APP_MODULE="app.app:app"

# Use bash so $PORT and APP_MODULE expand correctly
CMD bash -lc 'gunicorn -k gthread -w ${WEB_CONCURRENCY:-2} -b 0.0.0.0:${PORT:-10000} ${APP_MODULE:-app.app:app}'
