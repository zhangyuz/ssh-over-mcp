#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEPLOY="${RUNNER_DEPLOY_SCRIPT:-${SCRIPT_DIR}/deploy-mac-x86-runner.sh}"

LABEL="com.ssh-over-mcp.mac-x86-runner"
repo_slug="${RUNNER_REPO_SLUG:-zhangyuz/ssh-over-mcp}"
container_name="${RUNNER_CONTAINER_NAME:-ssh-over-mcp-runner-mac-x86}"
image="${RUNNER_IMAGE:-ssh-over-mcp-actions-runner:ubuntu26.04-x86}"
poll_seconds="${RUNNER_SUPERVISOR_POLL_SECONDS:-2}"
replacement_delay="${RUNNER_SUPERVISOR_REPLACEMENT_DELAY_SECONDS:-2}"
launchd_path="${RUNNER_SUPERVISOR_LAUNCHD_PATH:-/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin}"

home_dir="${HOME:?HOME is required}"
state_dir="${RUNNER_SUPERVISOR_STATE_DIR:-${home_dir}/Library/Application Support/ssh-over-mcp}"
lock_dir="${state_dir}/runner-supervisor.lock"
plist_path="${home_dir}/Library/LaunchAgents/${LABEL}.plist"
stdout_log="${home_dir}/Library/Logs/ssh-over-mcp-runner-supervisor.log"
stderr_log="${home_dir}/Library/Logs/ssh-over-mcp-runner-supervisor.err.log"

stop_requested=0
lock_held=0

log() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

validate_host() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    die "runner supervisor is only supported on the dedicated macOS host"
  fi
  if [[ "$(uname -m)" != "x86_64" ]]; then
    die "runner supervisor is x86-only; Apple Silicon/M4 is intentionally rejected"
  fi
}

require_runtime() {
  command -v docker >/dev/null 2>&1 || die "docker is required"
  docker info >/dev/null 2>&1 || die "Docker Desktop is not running or accessible"
  command -v gh >/dev/null 2>&1 || die "gh is required to mint fresh registration tokens"
  gh auth status >/dev/null 2>&1 || die "gh must be authenticated for ${repo_slug}"

  if [[ -n "${RUNNER_TOKEN:-}" ]]; then
    printf '%s\n'       "error: RUNNER_TOKEN must be unset; the supervisor mints a fresh one-time token per runner"       >&2
    exit 2
  fi
  unset RUNNER_TOKEN
}

acquire_lock() {
  mkdir -p "${state_dir}"
  chmod 700 "${state_dir}" 2>/dev/null || true

  if mkdir "${lock_dir}" 2>/dev/null; then
    printf '%s\n' "$$" >"${lock_dir}/pid"
    lock_held=1
    return
  fi

  local previous_pid=""
  previous_pid="$(cat "${lock_dir}/pid" 2>/dev/null || true)"
  if [[ "${previous_pid}" =~ ^[0-9]+$ ]] && kill -0 "${previous_pid}" 2>/dev/null; then
    die "runner supervisor is already active as pid ${previous_pid}"
  fi

  rm -rf "${lock_dir}"
  mkdir "${lock_dir}" || die "cannot acquire supervisor lock"
  printf '%s\n' "$$" >"${lock_dir}/pid"
  lock_held=1
}

release_lock() {
  if [[ "${lock_held}" -eq 1 ]]; then
    rm -rf "${lock_dir}"
    lock_held=0
  fi
}

request_stop() {
  stop_requested=1
  log "stop requested; no replacement runner will be started"
}

container_exists() {
  docker inspect "${container_name}" >/dev/null 2>&1
}

ensure_image() {
  if [[ "${RUNNER_SUPERVISOR_REBUILD:-false}" == "true" ]]     || ! docker image inspect "${image}" >/dev/null 2>&1; then
    log "building runner image ${image}"
    bash "${DEPLOY}" build
  else
    log "reusing runner image ${image}"
  fi
}

start_ephemeral_runner() {
  log "starting fresh ephemeral runner for ${repo_slug}"
  bash "${DEPLOY}" up --no-build
}

wait_for_container_retirement() {
  while container_exists; do
    if [[ "${stop_requested}" -eq 1 ]]; then
      log "leaving active runner container in place to finish its current job"
      return 130
    fi

    local status=""
    status="$(docker inspect --format '{{.State.Status}}' "${container_name}" 2>/dev/null || true)"
    case "${status}" in
      exited|dead)
        docker rm -f "${container_name}" >/dev/null 2>&1 || true
        log "runner container retired"
        return 0
        ;;
      *)
        sleep "${poll_seconds}"
        ;;
    esac
  done

  log "runner container retired"
  return 0
}

run_supervisor() {
  local mode="$1"
  local backoff=5

  validate_host
  require_runtime
  acquire_lock
  trap release_lock EXIT
  trap request_stop TERM INT HUP

  if ! ensure_image; then
    die "failed to prepare runner image"
  fi

  while [[ "${stop_requested}" -eq 0 ]]; do
    if container_exists; then
      log "adopting existing runner container ${container_name}"
    else
      if ! start_ephemeral_runner; then
        if container_exists; then
          log "runner start command failed after container creation; adopting it"
        elif [[ "${mode}" == "once" ]]; then
          return 1
        else
          log "runner start failed; retrying in ${backoff}s"
          sleep "${backoff}"
          if (( backoff < 60 )); then
            backoff=$((backoff * 2))
            (( backoff > 60 )) && backoff=60
          fi
          continue
        fi
      fi
    fi

    backoff=5
    wait_for_container_retirement || true

    if [[ "${mode}" == "once" || "${stop_requested}" -eq 1 ]]; then
      break
    fi

    sleep "${replacement_delay}"
  done
}

xml_escape() {
  printf '%s' "$1"     | /usr/bin/sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

install_launchd() {
  validate_host
  require_runtime

  local launch_agents_dir logs_dir uid escaped_script escaped_root escaped_home escaped_path
  launch_agents_dir="${home_dir}/Library/LaunchAgents"
  logs_dir="${home_dir}/Library/Logs"
  uid="$(id -u)"
  escaped_script="$(xml_escape "${SCRIPT_DIR}/supervise-mac-x86-runner.sh")"
  escaped_root="$(xml_escape "${REPO_ROOT}")"
  escaped_home="$(xml_escape "${home_dir}")"
  escaped_path="$(xml_escape "${launchd_path}")"

  mkdir -p "${launch_agents_dir}" "${logs_dir}"
  touch "${stdout_log}" "${stderr_log}"

  cat >"${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${escaped_script}</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${escaped_root}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${escaped_home}</string>
    <key>PATH</key>
    <string>${escaped_path}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>15</integer>
  <key>StandardOutPath</key>
  <string>$(xml_escape "${stdout_log}")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "${stderr_log}")</string>
</dict>
</plist>
EOF

  chmod 600 "${plist_path}"
  launchctl bootout "gui/${uid}" "${plist_path}" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/${uid}" "${plist_path}"
  launchctl kickstart -k "gui/${uid}/${LABEL}"

  log "installed launchd supervisor: ${LABEL}"
  log "plist: ${plist_path}"
}

uninstall_launchd() {
  validate_host
  local uid
  uid="$(id -u)"
  launchctl bootout "gui/${uid}" "${plist_path}" >/dev/null 2>&1 || true
  rm -f "${plist_path}"
  log "uninstalled launchd supervisor: ${LABEL}"
}

show_status() {
  validate_host
  local uid
  uid="$(id -u)"
  launchctl print "gui/${uid}/${LABEL}" 2>/dev/null || true
  printf '\nRunner container:\n'
  bash "${DEPLOY}" status || true
}

follow_logs() {
  mkdir -p "$(dirname "${stdout_log}")"
  touch "${stdout_log}" "${stderr_log}"
  tail -n 100 -f "${stdout_log}" "${stderr_log}"
}

usage() {
  cat <<EOF
Usage:
  scripts/supervise-mac-x86-runner.sh run
  scripts/supervise-mac-x86-runner.sh once
  scripts/supervise-mac-x86-runner.sh install
  scripts/supervise-mac-x86-runner.sh uninstall
  scripts/supervise-mac-x86-runner.sh status
  scripts/supervise-mac-x86-runner.sh logs

run        Keep exactly one disposable runner container available.
once       Start/adopt one disposable runner and exit after it retires.
install    Install and start a per-user launchd service.
uninstall  Stop launchd supervision and remove its plist.
status     Show launchd service and runner-container state.
logs       Follow supervisor stdout/stderr logs.
EOF
}

case "${1:-run}" in
  run)
    run_supervisor run
    ;;
  once)
    run_supervisor once
    ;;
  install)
    install_launchd
    ;;
  uninstall)
    uninstall_launchd
    ;;
  status)
    show_status
    ;;
  logs)
    follow_logs
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
