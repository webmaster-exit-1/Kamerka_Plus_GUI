FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels -r /app/requirements.txt

# ── Tool installer stage ────────────────────────────────────────────────────
FROM debian:bookworm-slim AS tools

ARG NUCLEI_VERSION=3.3.9
ARG NAABU_VERSION=2.3.3
ARG TARGETARCH=amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# nuclei
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
         -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# naabu
RUN curl -sSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" \
         -o /tmp/naabu.zip \
    && unzip -q /tmp/naabu.zip naabu -d /usr/local/bin \
    && chmod +x /usr/local/bin/naabu \
    && rm /tmp/naabu.zip

# wappalyzer-cli
RUN npm install -g wappalyzer

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 nmap nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=tools /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/wappalyzer/cli.js /usr/local/bin/wappalyzer \
    && chmod +x /usr/local/bin/wappalyzer

COPY --from=builder /wheels /wheels
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir /wheels/*

COPY . /app

RUN mkdir -p /app/scans /app/downloads /app/staticfiles \
    && python manage.py collectstatic --noinput || true

EXPOSE 8000

CMD ["gunicorn", "kamerka.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
