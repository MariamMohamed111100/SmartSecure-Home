# One Dockerfile for every Python service. Build with --build-arg SERVICE=<folder in services/>
FROM python:3.12-slim
ARG SERVICE
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY libs/common /libs/common
RUN pip install --no-cache-dir /libs/common
COPY services/${SERVICE}/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY services/${SERVICE}/ /app/
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app \
    && mkdir -p /run/app-secrets && chown app:app /run/app-secrets
COPY docker/entrypoint.sh /usr/local/bin/sim-entrypoint
RUN chmod +x /usr/local/bin/sim-entrypoint
# sim-entrypoint runs as root: it copies Docker secrets (root-only, mode 0400
# on Linux) to /run/app-secrets and chowns them to app, then execs `gosu app`.
ENTRYPOINT ["/usr/local/bin/sim-entrypoint"]
CMD ["python", "main.py"]
