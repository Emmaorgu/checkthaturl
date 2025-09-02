# ---- Dockerfile (CBN-ready) ----
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# System deps for Chromium/Playwright (current Debian names)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg procps \
    libnss3 libnspr4 libxkbcommon0 libx11-6 libxcb1 libxcomposite1 libxdamage1 \
    libxext6 libxfixes3 libxrandr2 libasound2 libpangocairo-1.0-0 libatk1.0-0 \
    libatk-bridge2.0-0 libcups2 libdbus-1-3 libdrm2 libxshmfence1 libgbm1 \
    libegl1 libglib2.0-0 libcairo2 libpango-1.0-0 libjpeg62-turbo libpng16-16 \
    xdg-utils fonts-liberation fonts-unifont fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# Prefer IPv4 at OS level (helps with CDN/WAF flakiness from DC IPs)
RUN sed -i 's/^#precedence ::ffff:0:0\/96 100/precedence ::ffff:0:0\/96 100/' /etc/gai.conf || true

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install the Chromium browser for Playwright (no legacy --with-deps)
RUN python -m playwright install chromium

# App code
COPY . .

# Render injects $PORT at runtime; bind to it
EXPOSE 10000
CMD ["gunicorn", "app.app:app",
     "--bind", "0.0.0.0:${PORT}",
     "--workers", "2", "--threads", "4", "--timeout", "180"]
