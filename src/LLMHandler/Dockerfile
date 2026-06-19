FROM python:3.13-slim-bookworm

WORKDIR /app

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc g++ curl \
    && pip3 install --no-cache-dir flask requests uwsgi langchain-core>=0.3.55 langgraph langchain-community langchain[openai]>=0.3.16 langchain-ollama transformers \
    && apt-get autoremove --yes gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup --disabled-password

USER appuser

COPY prompts/*_prompt.txt ./
COPY llm_wrapper.py ./llm_wrapper.py
COPY llm_handler.py ./llm_handler.py
COPY llm_wrapper.ini ./llm_wrapper.ini

ENTRYPOINT ["uwsgi", "--ini", "llm_wrapper.ini"]