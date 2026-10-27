FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md /app/
COPY recguard /app/recguard
RUN pip install --no-cache-dir ".[server,yaml,postgres]" && \
    groupadd --system rg && useradd --system --gid rg --home /app rg && \
    mkdir -p /var/lib/recguard && chown rg:rg /var/lib/recguard
USER rg
EXPOSE 8765
# RECGUARD_WORKERS > 1 needs RECGUARD_DB=postgresql://... (or accepts SQLite file locking on one host).
CMD ["sh", "-c", "exec recguard serve --host 0.0.0.0 --port 8765 --workers ${RECGUARD_WORKERS:-1}"]
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=2)"
