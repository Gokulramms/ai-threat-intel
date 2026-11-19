# OpenKai Enterprise Security Platform Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY openkai_engine/ /app/openkai_engine/
COPY config/ /app/config/
COPY .env.example /app/.env.example

# Expose API and SOC Dashboard UI port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production

# Run OpenKai Engine
CMD ["uvicorn", "openkai_engine.main:app", "--host", "0.0.0.0", "--port", "8000"]
