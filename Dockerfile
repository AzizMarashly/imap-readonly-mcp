FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home app
WORKDIR /app

COPY pyproject.toml README.md LICENSE config/accounts.example.yaml ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && pip install .[all]

USER app

ENTRYPOINT ["imap-readonly-mcp"]
CMD ["--config", "/app/config/accounts.yaml"]
