# ---------- Base: Python + system deps ----------
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System deps for Playwright/Chromium + tiny init + curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git tini \
    libatk-bridge2.0-0 libnss3 libxkbcommon0 libdrm2 libgbm1 libasound2 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libatk1.0-0 libcups2 libx11-xcb1 libxss1 \
    libgtk-3-0 libpango-1.0-0 libpangocairo-1.0-0 libffi8 libpci3 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Bake browsers into the image (no runtime downloads)
RUN python -m playwright install --with-deps chromium

# Copy app code
COPY . /app

# Healthcheck (optional; Render can also use /health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/usr/bin/tini","--"]

# Use shell form so ${PORT} is expanded by the shell Render sets
CMD gunicorn -w 2 -k gthread --threads 4 -b 0.0.0.0:${PORT} app.app:app
