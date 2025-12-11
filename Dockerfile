FROM python:3.11-slim

ENV TZ=UTC
WORKDIR /app

# Install cron + required tools
RUN apt-get update && \
    apt-get install -y cron && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . /app

# Permissions
RUN chmod +x /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh

# Cron setup
RUN chmod 0644 /app/cron/2fa-cron && \
    cp /app/cron/2fa-cron /etc/cron.d/2fa-cron && \
    crontab /etc/cron.d/2fa-cron

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
