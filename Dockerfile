ARG SOURCE_DATE_EPOCH=315532800

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS builder
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

WORKDIR /build
COPY requirements/build.lock requirements/runtime.lock ./requirements/
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --require-hashes --no-compile \
        --only-binary=:all: -r requirements/build.lock \
    && mkdir -p /wheelhouse \
    && python -m pip download --require-hashes --only-binary=:all: --no-deps \
        --dest /wheelhouse -r requirements/runtime.lock \
    && python -m pip wheel --no-build-isolation --no-deps \
        --wheel-dir /wheelhouse . \
    && cp requirements/runtime.lock /wheelhouse/runtime.lock \
    && find /wheelhouse -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PATH=/opt/ssh-over-mcp/bin:${PATH} \
    PYTHONPATH=/opt/ssh-over-mcp/lib/python3.13/site-packages

COPY --from=builder /wheelhouse /wheelhouse

RUN python -m pip install --no-cache-dir --no-index --no-compile \
        --prefix=/opt/ssh-over-mcp --find-links=/wheelhouse \
        --require-hashes -r /wheelhouse/runtime.lock \
    && python -m pip install --no-cache-dir --no-index --no-compile \
        --prefix=/opt/ssh-over-mcp --find-links=/wheelhouse \
        --no-deps ssh-over-mcp==0.2.0 \
    && rm -rf /wheelhouse \
    && printf '%s\n' 'ssh-over-mcp:x:10001:' >> /etc/group \
    && printf '%s\n' 'ssh-over-mcp:x:10001:10001:ssh-over-mcp:/nonexistent:/usr/sbin/nologin' >> /etc/passwd \
    && mkdir /app \
    && chmod 0555 /app \
    && find /opt/ssh-over-mcp -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + \
    && touch -h -d "@${SOURCE_DATE_EPOCH}" \
        /opt /tmp /etc /etc/group /etc/passwd /app

WORKDIR /app
USER 10001:10001

EXPOSE 8000

CMD ["ssh-over-mcp-server"]
