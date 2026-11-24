FROM python:3.12-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS base

RUN apk upgrade --no-cache

FROM base AS dependencies
COPY requirements-runtime.txt requirements-test.txt /build/
RUN python -m pip install --no-cache-dir --upgrade pip==26.3 \
    && python -m pip install --no-cache-dir --only-binary=:all: --prefix=/install -r /build/requirements-runtime.txt \
    && python -m pip install --no-cache-dir --only-binary=:all: --target=/test-tools -r /build/requirements-test.txt

# Export test tooling separately; it is never copied into the runtime image.
FROM scratch AS test-tools
COPY --from=dependencies /test-tools /

FROM base AS runtime

WORKDIR /app

RUN addgroup -g 10001 appuser && adduser -D -u 10001 -G appuser appuser \
    && python -m pip uninstall --yes pip

ENV PYTHONDONTWRITEBYTECODE=1

COPY --from=dependencies /install /usr/local

COPY src ./src
COPY config/logging.json ./config/logging.json

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).close()"

CMD ["uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-config", "config/logging.json", "--no-proxy-headers"]
