FROM python:3.13-slim-bookworm AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /wheels /wheels

RUN python -m pip install --no-cache-dir --no-index \
        --find-links=/wheels ssh-over-mcp \
    && rm -rf /wheels \
    && groupadd --gid 10001 ssh-over-mcp \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin ssh-over-mcp \
    && mkdir /app \
    && chmod 0555 /app

WORKDIR /app
USER 10001:10001

EXPOSE 8000

CMD ["ssh-over-mcp-server"]
