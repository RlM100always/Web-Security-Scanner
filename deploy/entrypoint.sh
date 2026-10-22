#!/bin/sh
set -eu

export PORT="${PORT:-10000}"
export DATABASE_PATH="${DATABASE_PATH:-/data/scanner.sqlite3}"
export BACKUP_DIR="${BACKUP_DIR:-/data/backups}"
export SCANNER_ALLOW_PRIVATE="${SCANNER_ALLOW_PRIVATE:-0}"
export SESSION_COOKIE_SECURE="${SESSION_COOKIE_SECURE:-1}"
export SESSION_COOKIE_SAMESITE="${SESSION_COOKIE_SAMESITE:-Lax}"
export TRUST_PROXY_HEADERS="${TRUST_PROXY_HEADERS:-1}"
export TRUST_PROXY_HOPS="${TRUST_PROXY_HOPS:-1}"

# Render supplies RENDER_EXTERNAL_URL at runtime. Derive trusted origins from
# the actual assigned URL instead of guessing or hard-coding a public domain.
if [ -z "${PUBLIC_APP_URL:-}" ]; then
  export PUBLIC_APP_URL="${RENDER_EXTERNAL_URL:-http://localhost:${PORT}}"
fi
if [ -z "${CORS_ORIGINS:-}" ]; then
  export CORS_ORIGINS="${RENDER_EXTERNAL_URL:-http://localhost:${PORT}}"
fi

mkdir -p /data /data/backups /run/nginx /var/cache/nginx /var/log/nginx /var/lib/nginx
chown -R appuser:appuser /data
chown -R www-data:www-data /run/nginx /var/cache/nginx /var/log/nginx /var/lib/nginx

envsubst '${PORT}' < /opt/sentinelscope/nginx.conf.template > /etc/nginx/conf.d/default.conf
nginx -t

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
