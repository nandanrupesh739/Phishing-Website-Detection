# ==============================================================================
# PhishGuard AI — Backend Container
# ==============================================================================
FROM python:3.11-slim AS backend

WORKDIR /app

# Install system dependencies needed for lightgbm / c-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application backend code
COPY backend/ ./backend/
COPY train.py .

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    FLASK_DEBUG=false

EXPOSE 5000

# Mount notes:
# Mount ./models into /app/models to provide trained weights without rebuilding
# Mount ./data into /app/data to provide training CSV
VOLUME ["/app/models", "/app/data"]

CMD ["python", "-m", "backend.app"]
