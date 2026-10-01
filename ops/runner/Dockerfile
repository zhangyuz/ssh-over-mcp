ARG UBUNTU_VERSION=26.04
FROM ubuntu:${UBUNTU_VERSION}

ARG RUNNER_VERSION=2.337.0
ARG RUNNER_ARCH=x64
ARG RUNNER_SHA256

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_HOME=/opt/actions-runner
ENV RUNNER_WORKDIR=_work
ENV RUNNER_LABELS=ssh-over-mcp-docker
ENV RUNNER_EPHEMERAL=true
ENV RUNNER_DISABLE_UPDATE=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnu-coreutils \
        jq \
        libsqlite3-0 \
        gzip \
        tar \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 runner \
    && useradd --uid 1001 --gid 1001 --create-home --shell /bin/bash runner \
    && mkdir -p "${RUNNER_HOME}" \
    && chown runner:runner "${RUNNER_HOME}"

WORKDIR ${RUNNER_HOME}

RUN test -n "${RUNNER_SHA256}" \
    && case "${RUNNER_ARCH}" in x64|arm64) ;; *) echo "unsupported runner arch: ${RUNNER_ARCH}" >&2; exit 1 ;; esac \
    && curl -fsSL \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" \
        -o /tmp/actions-runner.tgz \
    && echo "${RUNNER_SHA256}  /tmp/actions-runner.tgz" | sha256sum -c - \
    && tar -xzf /tmp/actions-runner.tgz -C "${RUNNER_HOME}" \
    && rm /tmp/actions-runner.tgz \
    && "${RUNNER_HOME}/bin/installdependencies.sh" \
    && chown -R runner:runner "${RUNNER_HOME}"

COPY --chown=runner:runner entrypoint.sh /usr/local/bin/runner-entrypoint
RUN chmod 0555 /usr/local/bin/runner-entrypoint

USER runner

ENTRYPOINT ["/usr/local/bin/runner-entrypoint"]
