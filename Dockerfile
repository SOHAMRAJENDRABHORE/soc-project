FROM python:3.11-slim

# Build deps needed for psutil, cryptography, reportlab
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (separate layer so code changes don't bust cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Runtime dirs
RUN mkdir -p /data reports

EXPOSE 8080

# Default: run the central server (override in docker-compose for the agent)
CMD ["python", "-m", "uvicorn", "central_server.server:app", \
     "--host", "0.0.0.0", "--port", "8080"]
