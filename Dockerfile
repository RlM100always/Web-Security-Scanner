# Build the React application.
FROM node:22-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# One service runs Nginx, the Flask API and the SQLite-backed scan worker.
# Keeping API and worker together lets both processes use the same persistent
# SQLite file. Do not scale this service horizontally.
FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    DATABASE_PATH=/data/scanner.sqlite3

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx supervisor gettext-base curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY backend/ /app/backend/
COPY --from=frontend-build /build/frontend/dist/ /usr/share/nginx/html/
COPY deploy/nginx.conf.template /opt/sentinelscope/nginx.conf.template
COPY deploy/supervisord.conf /etc/supervisor/conf.d/sentinelscope.conf
COPY deploy/entrypoint.sh /usr/local/bin/sentinelscope-entrypoint

RUN chmod 0755 /usr/local/bin/sentinelscope-entrypoint \
    && mkdir -p /data /run/nginx /var/cache/nginx /var/log/nginx /var/lib/nginx \
    && chown -R www-data:www-data /run/nginx /var/cache/nginx /var/log/nginx /var/lib/nginx \
    && rm -f /etc/nginx/sites-enabled/default

EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:10000/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/sentinelscope-entrypoint"]
