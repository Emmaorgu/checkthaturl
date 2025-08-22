# Playwright base image with browsers preinstalled (matches your playwright==1.52.0)
FROM mcr.microsoft.com/playwright/python:v1.52.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 1) Install Python deps first (cache-friendly)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 2) Copy the app
COPY . /app

# 3) Add a boot script that verifies import & logs useful info before starting
RUN bash -lc 'cat > /app/boot.sh << "BASH"\n\
#!/usr/bin/env bash\n\
set -euo pipefail\n\
export PORT="${PORT:-10000}"\n\
echo "--- BOOT INFO ---\"\n\
echo "PWD: $(pwd)"; echo "LS /app:"; ls -la /app || true\n\
echo "PYTHON: $(python -V)"; echo "PORT: ${PORT}"; echo "WHOAMI: $(whoami)"\n\
echo "PYTHONPATH: ${PYTHONPATH:-<empty>}"\n\
echo "---------------\"\n\
python - <<\"PY\"\n\
import os, sys, glob\n\
print("[boot] sys.path[0]:", sys.path[0])\n\
print("[boot] trying: import app.app as m …")\n\
try:\n\
    import app.app as m\n\
    print("[boot] IMPORT_OK: app.app")\n\
    print("[boot] Flask app object:", getattr(m, "app", None))\n\
    if not hasattr(m, "app"):\n\
        raise RuntimeError("app.app has no attribute 'app'")\n\
except Exception as e:\n\
    print("[boot] IMPORT_FAIL:", type(e).__name__, e)\n\
    sys.exit(97)\n\
PY\n\
echo "[boot] launching gunicorn …"\n\
exec gunicorn -w ${WORKERS:-2} -k gthread --threads ${THREADS:-4} \\\n\
  --log-level debug --timeout 180 -b 0.0.0.0:${PORT} app.app:app\n\
BASH\n\
chmod +x /app/boot.sh'

# Optional healthcheck (Render can also probe /health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

# Tini is present in image; use it to handle signals cleanly
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/app/boot.sh"]