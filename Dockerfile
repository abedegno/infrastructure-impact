FROM python:3.13-slim AS builder
WORKDIR /build
COPY requirements-build.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock
COPY pyproject.toml README.md LICENSE NOTICE THIRD_PARTY.md ./
COPY infrastructure_impact ./infrastructure_impact
RUN python -m build --wheel --no-isolation

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 IMPACT_HOME=/var/lib/impact IMPACT_PUBLICATIONS=/srv/publications
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir --no-deps /tmp/*.whl && rm /tmp/*.whl && useradd --uid 10001 --create-home impact && mkdir -p /var/lib/impact /srv/publications && chown -R impact:impact /var/lib/impact /srv/publications
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["impact"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
