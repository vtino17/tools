FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/ocysec/tools-hacking"
LABEL org.opencontainers.image.description="HackerAI Tools - Penetration Testing Toolkit"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /tools

# ─── System dependencies ──────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    nmap \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# ─── Python dependencies ──────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─── Copy tools ───────────────────────────────────────
COPY . .

# ─── Volume untuk output ───────────────────────────────
VOLUME ["/tools/reports", "/tools/logs", "/tools/wordlists"]

# ─── Entry point ──────────────────────────────────────
ENTRYPOINT ["python", "hackerai.py"]
CMD []
