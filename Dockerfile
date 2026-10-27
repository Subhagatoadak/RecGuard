FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md /app/
COPY recguard /app/recguard
RUN pip install --no-cache-dir ".[server,yaml]" && \
    groupadd --system rg && useradd --system --gid rg --home /app rg && \
    mkdir -p /var/lib/recguard && chown rg:rg /var/lib/recguard
USER rg
EXPOSE 8765
CMD ["uvicorn", "recguard.api:from_environment", "--factory", "--host", "0.0.0.0", "--port", "8765", "--workers", "1"]
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=2)"
