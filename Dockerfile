# ---------- Base: Python + system deps ----------
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System deps for Playwright/Chromium + small utils
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git tini \
    libatk-bridge2.0-0 libnss3 libxkbcommon0 libdrm2 libgbm1 libasound2 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libatk1.0-0 libcups2 libx11-xcb1 libxss1 \
    libgtk-3-0 libpango-1.0-0 libpangocairo-1.0-0 libffi8 libpci3 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only deps first for layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Install Playwright browsers into the image (no runtime downloads)
RUN python -m playwright install --with-deps chromium

# App code
COPY . /app

# Render will pass PORT; we’ll bind gunicorn to it
ENV PORT=10000
ENV HOST=0.0.0.0

# Optional container healthcheck (Render can also use /health below)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["gunicorn","-w","2","-k","gthread","--threads","4","-b","0.0.0.0:${PORT}","app.app:app"]
