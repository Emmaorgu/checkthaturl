# --- Base ---
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# --- System deps incl. Chromium deps for Playwright (kept) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg procps \
    libnss3 libnspr4 libxkbcommon0 libx11-6 libxcb1 libxcomposite1 libxdamage1 \
    libxext6 libxfixes3 libxrandr2 libasound2 libpangocairo-1.0-0 libatk1.0-0 \
    libgtk-3-0 fonts-liberation libgbm1 xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# --- Prefer IPv4 for DNS/address selection (no code change needed) ---
# This sets glibc address selection to pick IPv4 first.
RUN sed -i 's/^#precedence ::ffff:0:0\/96 100/precedence ::ffff:0:0\/96 100/' /etc/gai.conf || true

# --- Python deps ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# (keep Playwright available for when you re-enable behavior mode)
RUN python -m playwright install --with-deps chromium

# --- App code ---
COPY . .

# Render injects $PORT at runtime; we bind to it.
EXPOSE 10000
CMD ["gunicorn", "app.app:app", "--bind", "0.0.0.0:${PORT}", "--workers", "2", "--threads", "4", "--timeout", "180"]
