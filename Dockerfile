# --------------------------------------------
# Base image
# --------------------------------------------
FROM python:3.11-slim

# --- Optional cache-bust arg (bump value to force a fresh build on Render) ---
ARG CACHEBUST=2025-09-09-01

# --------------------------------------------
# OS basics (small, no bloat)
# --------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dumb-init \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    # Playwright downloads live here so they persist as a layer
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    # Make imports work from /app without fiddling with sys.path
    PYTHONPATH=/app

WORKDIR /app

# --------------------------------------------
# Install Python deps first (better layer caching)
# --------------------------------------------
COPY requirements.txt /app/requirements.txt

# Always upgrade pip and install exact deps (no wheel cache to keep image small)
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# --------------------------------------------
# Playwright + Chromium (with system deps auto-installed)
# NOTE: --with-deps will apt-install required libs for Chromium on Debian slim
# --------------------------------------------
RUN pip install --no-cache-dir playwright \
 && python -m playwright install --with-deps chromium

# --------------------------------------------
# Copy application code
# --------------------------------------------
COPY . /app

# --------------------------------------------
# Start command
# - Render injects $PORT; default to 10000 for local use
# - APP_MODULE is overrideable; defaults to "app.app:app"
# --------------------------------------------
ENV PORT=10000
ENV APP_MODULE="app.app:app"

# dumb-init handles PID 1 signals so Gunicorn shuts down cleanly
CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "app.app:app"]
# If you use a factory instead, set APP_MODULE to "app.app:create_app()" in Render env
# and change the last token above to "${APP_MODULE}" if you prefer:
# CMD ["dumb-init", "gunicorn", "-k", "gthread", "-w", "2", "-b", "0.0.0.0:${PORT}", "${APP_MODULE}"]
