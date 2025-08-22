# Use Playwright's official image: Python + browsers + OS deps preinstalled
# Pin to your Playwright version so it matches your requirements.txt (1.52.0)
FROM mcr.microsoft.com/playwright/python:v1.52.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python deps first (layer caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY . /app

# Optional healthcheck (Render can also use /health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

# Tini is already in this image; use it as entrypoint
ENTRYPOINT ["/usr/bin/tini","--"]

# Gunicorn; PORT is injected by Render
CMD gunicorn -w 2 -k gthread --threads 4 -b 0.0.0.0:${PORT} app.app:app
