#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_RUNNER_VERSION="2.337.0"
DEFAULT_SHA_X64="70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
DEFAULT_SHA_ARM64="9b1dc70626422526e3c94767cf024896beb15da5342a3f4819bf2feac13e0393"

command_name="up"
if [[ ${1:-} =~ ^(up|build|down|status|logs)$ ]]; then
  command_name="$1"
  shift
fi

runner_url="${RUNNER_URL:-https://github.com/zhangyuz/ssh-over-mcp}"
runner_name="${RUNNER_NAME:-}"
runner_labels="${RUNNER_LABELS:-ssh-over-mcp-docker}"
runner_token="${RUNNER_TOKEN:-}"
runner_version="${RUNNER_VERSION:-${DEFAULT_RUNNER_VERSION}}"
runner_sha256="${RUNNER_SHA256:-}"
ubuntu_version="${RUNNER_UBUNTU_VERSION:-26.04}"
image="${RUNNER_IMAGE:-ssh-over-mcp-actions-runner:ubuntu${ubuntu_version}}"
container_name="${RUNNER_CONTAINER_NAME:-ssh-over-mcp-runner}"
cpus="${RUNNER_CPUS:-2}"
memory="${RUNNER_MEMORY:-4g}"
pids_limit="${RUNNER_PIDS_LIMIT:-1024}"
ephemeral=true
build_image=true

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy-runner.sh [up|build|down|status|logs] [options]

Commands:
  up       Build (by default) and start the runner container.
  build    Build the configured Ubuntu runner image only.
  down     Stop and remove the runner container.
  status   Show runner container status.
  logs     Follow runner container logs.

Options:
  --url URL             GitHub repository URL.
  --name NAME           Runner name.
  --labels LABELS       Comma-separated custom labels.
  --persistent          Keep the runner registered for multiple jobs.
  --no-build            Reuse an existing local image.
  --image IMAGE         Docker image tag.
  --container NAME      Docker container name.
  --cpus N              Docker CPU limit (default: 2).
  --memory SIZE         Docker memory limit (default: 4g).
  --pids-limit N        Docker PID limit (default: 1024).
  --ubuntu-version VER  Ubuntu base image version (default: 26.04).
  --runner-version VER  GitHub Actions runner version.
  --runner-sha256 SHA   SHA-256 for a non-default runner version.
  -h, --help            Show this help.

Registration token:
  Prefer RUNNER_TOKEN=<one-time-token> in the environment.
  If RUNNER_TOKEN is absent and gh is authenticated, the script requests a
  repository runner registration token via gh api.

Examples:
  RUNNER_TOKEN=... bash scripts/deploy-runner.sh up
  bash scripts/deploy-runner.sh up --name mac-mini-runner
  bash scripts/deploy-runner.sh up --persistent
  bash scripts/deploy-runner.sh logs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      runner_url="${2:?missing value for --url}"
      shift 2
      ;;
    --name)
      runner_name="${2:?missing value for --name}"
      shift 2
      ;;
    --labels)
      runner_labels="${2:?missing value for --labels}"
      shift 2
      ;;
    --persistent)
      ephemeral=false
      shift
      ;;
    --no-build)
      build_image=false
      shift
      ;;
    --image)
      image="${2:?missing value for --image}"
      shift 2
      ;;
    --container)
      container_name="${2:?missing value for --container}"
      shift 2
      ;;
    --cpus)
      cpus="${2:?missing value for --cpus}"
      shift 2
      ;;
    --memory)
      memory="${2:?missing value for --memory}"
      shift 2
      ;;
    --pids-limit)
      pids_limit="${2:?missing value for --pids-limit}"
      shift 2
      ;;
    --ubuntu-version)
      ubuntu_version="${2:?missing value for --ubuntu-version}"
      shift 2
      ;;
    --runner-version)
      runner_version="${2:?missing value for --runner-version}"
      shift 2
      ;;
    --runner-sha256)
      runner_sha256="${2:?missing value for --runner-sha256}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon/Desktop is not running or is not accessible" >&2
    exit 1
  fi
}

detect_platform() {
  local kernel arch
  kernel="$(uname -s)"
  arch="$(uname -m)"

  case "${kernel}" in
    Linux|Darwin) ;;
    *)
      echo "unsupported host OS: ${kernel}; expected Linux or macOS" >&2
      exit 1
      ;;
  esac

  case "${arch}" in
    x86_64|amd64)
      runner_arch="x64"
      docker_platform="linux/amd64"
      default_sha="${DEFAULT_SHA_X64}"
      ;;
    arm64|aarch64)
      runner_arch="arm64"
      docker_platform="linux/arm64"
      default_sha="${DEFAULT_SHA_ARM64}"
      ;;
    *)
      echo "unsupported host architecture: ${arch}" >&2
      exit 1
      ;;
  esac

  host_kernel="${kernel}"
}

resolve_runner_sha() {
  if [[ -n "${runner_sha256}" ]]; then
    return
  fi

  if [[ "${runner_version}" != "${DEFAULT_RUNNER_VERSION}" ]]; then
    echo "RUNNER_SHA256/--runner-sha256 is required for runner version ${runner_version}" >&2
    exit 1
  fi

  runner_sha256="${default_sha}"
}

build_runner_image() {
  echo "Building ${image} for ${docker_platform} (Ubuntu ${ubuntu_version}; Actions Runner ${runner_version})"
  docker build \
    --platform "${docker_platform}" \
    --build-arg "UBUNTU_VERSION=${ubuntu_version}" \
    --build-arg "RUNNER_VERSION=${runner_version}" \
    --build-arg "RUNNER_ARCH=${runner_arch}" \
    --build-arg "RUNNER_SHA256=${runner_sha256}" \
    -t "${image}" \
    "${REPO_ROOT}/ops/runner"
}

repo_slug_from_url() {
  local value
  value="${runner_url#https://github.com/}"
  value="${value#http://github.com/}"
  value="${value%.git}"
  if [[ "${value}" == "${runner_url}" || "${value}" != */* ]]; then
    echo "cannot derive GitHub owner/repository from RUNNER_URL=${runner_url}" >&2
    return 1
  fi
  printf '%s\n' "${value}"
}

resolve_registration_token() {
  if [[ -n "${runner_token}" ]]; then
    return
  fi

  if ! command -v gh >/dev/null 2>&1; then
    echo "RUNNER_TOKEN is required when gh is unavailable" >&2
    exit 1
  fi

  local slug
  slug="$(repo_slug_from_url)"
  echo "Requesting a one-time runner registration token with gh..." >&2
  runner_token="$(gh api \
    --method POST \
    "repos/${slug}/actions/runners/registration-token" \
    --jq .token)"

  if [[ -z "${runner_token}" ]]; then
    echo "failed to obtain runner registration token" >&2
    exit 1
  fi
}

default_runner_name() {
  if [[ -n "${runner_name}" ]]; then
    return
  fi

  local host
  host="$(hostname -s 2>/dev/null || hostname)"
  host="${host//[^A-Za-z0-9._-]/-}"
  runner_name="ssh-over-mcp-${host}-docker"
}

start_runner() {
  resolve_registration_token
  default_runner_name

  if docker inspect "${container_name}" >/dev/null 2>&1; then
    echo "runner container already exists: ${container_name}" >&2
    echo "use 'bash scripts/deploy-runner.sh down' before starting a replacement" >&2
    exit 1
  fi

  local run_args=(
    run
    -d
    --name "${container_name}"
    --hostname "${runner_name}"
    --platform "${docker_platform}"
    --init
    --cap-drop ALL
    --security-opt no-new-privileges:true
    --cpus "${cpus}"
    --memory "${memory}"
    --pids-limit "${pids_limit}"
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=512m
    -e "RUNNER_URL=${runner_url}"
    -e "RUNNER_TOKEN=${runner_token}"
    -e "RUNNER_NAME=${runner_name}"
    -e "RUNNER_LABELS=${runner_labels}"
    -e "RUNNER_EPHEMERAL=${ephemeral}"
    -e "RUNNER_DISABLE_UPDATE=false"
  )

  if [[ "${ephemeral}" == "true" ]]; then
    run_args+=(--rm)
  else
    run_args+=(--restart unless-stopped)
  fi

  run_args+=("${image}")

  local container_id
  container_id="$(docker "${run_args[@]}")"

  echo "Started runner container: ${container_name} (${container_id:0:12})"
  echo "Host: ${host_kernel}; container platform: ${docker_platform}; Ubuntu: ${ubuntu_version}"
  echo "Runner labels: ${runner_labels}"
  if [[ "${ephemeral}" == "true" ]]; then
    echo "Mode: ephemeral (container exits/removes after one GitHub Actions job)"
  else
    echo "Mode: persistent"
  fi
}

need_docker
detect_platform

case "${command_name}" in
  build)
    resolve_runner_sha
    build_runner_image
    ;;
  up)
    resolve_runner_sha
    if [[ "${build_image}" == "true" ]]; then
      build_runner_image
    fi
    start_runner
    ;;
  down)
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
    echo "Removed runner container: ${container_name}"
    ;;
  status)
    docker ps -a --filter "name=^/${container_name}$"
    ;;
  logs)
    docker logs -f "${container_name}"
    ;;
esac
