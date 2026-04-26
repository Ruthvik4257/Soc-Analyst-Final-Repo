FROM python:3.11-slim

# Reverse proxy: public $PORT (7860) → Streamlit (8501) + FastAPI (8000)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    gettext-base \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/docker/entrypoint.sh

ENV PORT=7860
ENV SOC_API_BASE=http://127.0.0.1:8000
ENV PYTHONUNBUFFERED=1
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_ADDRESS=127.0.0.1

EXPOSE 7860

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/app/docker/entrypoint.sh"]
