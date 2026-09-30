#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="${SCRIPT_DIR}/deploy-runner.sh"

command_name="${1:-up}"
if [[ "${command_name}" =~ ^(up|build|down|status|logs)$ ]]; then
  shift || true
else
  command_name="up"
fi

for arg in "$@"; do
  if [[ "${arg}" == "--persistent" ]]; then
    echo "persistent mode is disabled for the dedicated macOS x86 runner" >&2
    exit 2
  fi
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "this entrypoint is only for the dedicated macOS x86 runner host" >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "this runner is x86-only; Apple Silicon/M4 is intentionally rejected" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker Desktop must be installed and running" >&2
  exit 1
fi

repo_slug="${RUNNER_REPO_SLUG:-zhangyuz/ssh-over-mcp}"
runner_name="${RUNNER_NAME:-ssh-over-mcp-mac-x86}"
runner_labels="${RUNNER_LABELS:-ssh-over-mcp-docker,ssh-over-mcp-mac-x86,ubuntu-26.04,x64}"
container_name="${RUNNER_CONTAINER_NAME:-ssh-over-mcp-runner-mac-x86}"
image="${RUNNER_IMAGE:-ssh-over-mcp-actions-runner:ubuntu26.04-x86}"
ubuntu_version="26.04"

export RUNNER_URL="${RUNNER_URL:-https://github.com/${repo_slug}}"
export RUNNER_NAME="${runner_name}"
export RUNNER_LABELS="${runner_labels}"
export RUNNER_CONTAINER_NAME="${container_name}"
export RUNNER_IMAGE="${image}"
export RUNNER_UBUNTU_VERSION="${ubuntu_version}"

bash "${DEPLOY}" "${command_name}" \
  --ubuntu-version "${ubuntu_version}" \
  --image "${image}" \
  --container "${container_name}" \
  --name "${runner_name}" \
  --labels "${runner_labels}" \
  "$@"

if [[ "${command_name}" != "up" ]]; then
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "runner started; gh unavailable, so online registration was not polled"
  exit 0
fi

deadline=$((SECONDS + 45))
while (( SECONDS < deadline )); do
  status="$(
    gh api "repos/${repo_slug}/actions/runners" \
      --jq ".runners[] | select(.name == \"${runner_name}\") | .status" \
      2>/dev/null | head -1 || true
  )"
  if [[ "${status}" == "online" ]]; then
    echo "Runner online: ${runner_name}"
    echo "Labels: ${runner_labels}"
    echo "Mode: ephemeral; unregisters after one job and container removes itself."
    exit 0
  fi
  sleep 2
done

echo "runner container started but did not report online within 45 seconds" >&2
docker logs --tail 80 "${container_name}" >&2 || true
exit 1
