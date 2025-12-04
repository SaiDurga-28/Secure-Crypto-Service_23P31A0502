# ============================
# Stage 1 - Builder
# ============================
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install --prefix=/install -r requirements.txt


# ============================
# Stage 2 - Runtime
# ============================
FROM python:3.11-slim

ENV TZ=UTC
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Configure timezone
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo "UTC" > /etc/timezone

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . /app

# Create required directories
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Expose required port
EXPOSE 8080

# Run entrypoint script
ENTRYPOINT ["./entrypoint.sh"]
