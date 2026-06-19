FROM python:3.13-slim-bookworm
WORKDIR /app

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc g++ curl \
    && pip3 install --no-cache-dir flask requests uwsgi \
    && apt-get autoremove --yes gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup --disabled-password

RUN mkdir -p /app/session_logs
RUN mkdir -p /app/error_logs
RUN mkdir -p /app/downloaded_content
RUN chown appuser /app/session_logs
RUN chown appuser /app/error_logs
RUN chown appuser /app/downloaded_content

USER appuser

COPY log_entry.py ./log_entry.py
COPY log_wrapper.py ./log_wrapper.py
COPY log_handler.py ./log_handler.py
COPY log_wrapper.ini ./log_wrapper.ini

ENTRYPOINT ["uwsgi", "--ini", "log_wrapper.ini"]