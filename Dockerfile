# Use slim variant to keep image size smaller (~200-300MB final)
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for scapy + some packet manipulation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install Python dependencies
# Pin elasticsearch to match server version 8.12.0
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    scapy==2.5.0 \
    elasticsearch==8.12.0 \
    prometheus_client==0.20.0 \
    requests==2.31.0

# Copy application code
COPY . /app

# Optional: create non-root user for better security (recommended in production)
# RUN useradd -m -r appuser && chown -R appuser:appuser /app
# USER appuser

# Environment variables (can be overridden in docker-compose)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENV_METRICS_PORT=9100

# Expose metrics port (Prometheus)
EXPOSE 9100

# Default command - will be overridden in docker-compose.yml anyway
# This is just a fallback if someone runs the container directly
CMD ["python", "mycode.py", "/app/traffic.pcap"]