FROM python:3.14-slim

# Nuncio has zero third-party runtime dependencies -- this image never runs
# pip install. It just needs a slim Python and the package itself.

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin nuncio

WORKDIR /app
COPY nuncio/ /app/nuncio/
COPY pyproject.toml /app/

RUN mkdir -p /data && chown -R nuncio:nuncio /data /app

USER nuncio

ENV NUNCIO_DATA_DIR=/data \
    NUNCIO_BIND=0.0.0.0 \
    NUNCIO_PORT=8095

EXPOSE 8095
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8095/health', timeout=3)" || exit 1

ENTRYPOINT ["python", "-m", "nuncio"]
