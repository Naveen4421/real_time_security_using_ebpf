FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Install system dependencies if any are needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and models
COPY . .

# Run Phase 1 demo by default
CMD ["python", "demo_phase1.py"]
