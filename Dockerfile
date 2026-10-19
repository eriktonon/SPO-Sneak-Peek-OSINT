FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SPO_PORT=1337 \
    SPO_HOST=0.0.0.0 \
    SPO_DB_PATH=/app/data/spo.db

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r spo && useradd -r -g spo -d /app spo

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data && chown -R spo:spo /app

USER spo

EXPOSE 1337

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:1337/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:1337", "--workers", "2", "--threads", "4", "--timeout", "120", "main:spo"]
