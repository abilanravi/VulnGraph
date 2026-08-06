FROM python:3.11-slim

# git: needed to shallow-clone GitHub repositories before scanning them.
# curl/ca-certificates: needed to download the OSV Scanner binary below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# OSV Scanner (SCA) ships as a single static binary, not a PyPI/apt package.
RUN curl -sSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64" \
    && chmod +x /usr/local/bin/osv-scanner

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    # Semgrep (SAST) — declared here rather than in requirements.txt so a plain local
    # `pip install -r requirements.txt` stays lightweight (see README).
    && pip install --no-cache-dir semgrep

COPY . .

RUN chmod +x docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
