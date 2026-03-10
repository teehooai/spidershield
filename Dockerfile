FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 spidershield

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir .

USER spidershield

HEALTHCHECK --interval=30s --timeout=5s CMD spidershield --version || exit 1

CMD ["spidershield-server"]
