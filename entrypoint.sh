#!/usr/bin/env bash
set -e

# Fix CRLF just in case
sed -i 's/\r$//' /app/entrypoint.sh || true
sed -i 's/\r$//' /etc/cron.d/2fa-cron || true

# Start cron
service cron start || cron

# Create required dirs
mkdir -p /data /cron
chmod 755 /data /cron

# Start API server
exec uvicorn app:app --host 0.0.0.0 --port 8080
