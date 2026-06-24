FROM python:3.13-slim-bookworm

WORKDIR /app

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && pip3 install --no-cache-dir flask requests \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/downloaded_content

COPY wcat_handler.py ./wcat_handler.py

HEALTHCHECK --interval=10s --timeout=5s --retries=3 CMD curl -f http://localhost:8002/is_ready || exit 1

CMD ["python3", "wcat_handler.py"]
