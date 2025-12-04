#!/usr/bin/env bash
set -e

# Copy cron jobs from /cron to /etc/cron.d and set permissions
if [ -d /cron ]; then
  for f in /cron/*; do
    [ -f "$f" ] || continue
    cp "$f" /etc/cron.d/$(basename "$f")
    chmod 0644 /etc/cron.d/$(basename "$f")
  done
fi

# Normalize line endings in /etc/cron.d
for f in /etc/cron.d/*; do
  [ -f "$f" ] || continue
  sed -i 's/\r$//' "$f"
done

# Start cron
service cron start 2>/dev/null || /etc/init.d/cron start 2>/dev/null || crond 2>/dev/null || true

# Start FastAPI server on port 8080
exec uvicorn app:app --host 0.0.0.0 --port 8080