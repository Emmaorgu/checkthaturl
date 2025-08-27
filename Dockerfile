# ✅ Ships Chromium + all native deps for Playwright out of the box
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    TZ=Africa/Lagos \
    SCAN_MODE=playwright \
    CTU_BEHAVIOR_MODE=auto \
    REQUEST_TIMEOUT_SECS=60 \
    HEADLESS=1

WORKDIR /app

# 1) Use the *exact* deps from your working venv (run `pip freeze > requirements.txt` locally first)
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# 2) Copy app
COPY . /app

# Healthcheck route exists in app/app.py as /healthz
EXPOSE 10000

# Gunicorn entry for your structure (module path: app/app.py → app.app:app)
CMD ["gunicorn", "app.app:app", "--bind", "0.0.0.0:10000", "--workers", "2", "--threads", "4", "--timeout", "180"]
