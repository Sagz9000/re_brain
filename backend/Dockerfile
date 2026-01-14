FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
ENV DISPLAY=:99

# Install system dependencies
RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gdb \
    openjdk-21-jdk-headless \
    wine \
    wine32:i386 \
    wine64 \
    xvfb \
    xauth \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Initialize Wine prefix to avoid first-run delay
# We use xvfb-run because wineboot might try to access display
RUN xvfb-run -a wineboot --init || true


# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy logic
COPY . .

# Run API with persistent Xvfb
# Start Xvfb in background, set DISPLAY, then run Uvicorn
CMD Xvfb :99 -screen 0 1024x768x24 > /dev/null 2>&1 & export DISPLAY=:99 && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
