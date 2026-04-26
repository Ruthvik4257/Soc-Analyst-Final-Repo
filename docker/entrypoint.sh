#!/bin/sh
set -e
export PORT="${PORT:-7860}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export SOC_API_BASE="${SOC_API_BASE:-http://127.0.0.1:8000}"
export STREAMLIT_SERVER_PORT="${STREAMLIT_SERVER_PORT:-8501}"
export STREAMLIT_SERVER_ADDRESS="${STREAMLIT_SERVER_ADDRESS:-127.0.0.1}"
# Match Streamlit app location (config.toml theme lives here)
export STREAMLIT_CONFIG_DIR="/app/.streamlit"

cd /app
export PYTHONPATH="/app${PYTHONPATH:+:$PYTHONPATH}"

echo "[entry] Starting FastAPI on 127.0.0.1:8000"
uvicorn server.app:app --host 127.0.0.1 --port 8000 &
API_PID=$!

echo "[entry] Waiting for /healthz (torch + app import can take several minutes on CPU)"
i=0
while [ "$i" -lt 300 ]; do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://127.0.0.1:8000/healthz" >/dev/null 2>&1; then
      echo "[entry] API up"
      break
    fi
  else
    # wget fallback
    if wget -qO- "http://127.0.0.1:8000/healthz" >/dev/null 2>&1; then
      echo "[entry] API up"
      break
    fi
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$i" -ge 300 ]; then
  echo "[entry] ERROR: API did not become healthy in time" >&2
  kill "$API_PID" 2>/dev/null || true
  exit 1
fi

echo "[entry] Starting Streamlit on ${STREAMLIT_SERVER_ADDRESS}:${STREAMLIT_SERVER_PORT}"
streamlit run /app/streamlit_app.py \
  --server.port "${STREAMLIT_SERVER_PORT}" \
  --server.address "${STREAMLIT_SERVER_ADDRESS}" \
  --server.headless true \
  --browser.gatherUsageStats false &
ST_PID=$!
sleep 2

if ! envsubst '${PORT}' < /app/docker/nginx.conf.template > /tmp/nginx.hf.conf; then
  echo "[entry] envsubst failed" >&2
  exit 1
fi
if ! nginx -t -c /tmp/nginx.hf.conf; then
  echo "[entry] nginx config test failed" >&2
  kill "$API_PID" 2>/dev/null || true
  kill "$ST_PID" 2>/dev/null || true
  exit 1
fi

echo "[entry] Starting nginx (foreground) on 0.0.0.0:${PORT} (public)"
exec nginx -c /tmp/nginx.hf.conf
