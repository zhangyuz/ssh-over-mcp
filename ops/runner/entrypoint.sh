#!/usr/bin/env bash
set -euo pipefail

cd "${RUNNER_HOME:-/opt/actions-runner}"

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ ! -f .runner ]]; then
  : "${RUNNER_URL:?RUNNER_URL is required for initial registration}"
  : "${RUNNER_TOKEN:?RUNNER_TOKEN is required for initial registration}"

  runner_name="${RUNNER_NAME:-docker-${HOSTNAME:-runner}}"
  runner_labels="${RUNNER_LABELS:-ssh-over-mcp-docker}"
  runner_workdir="${RUNNER_WORKDIR:-_work}"

  config_args=(
    --url "${RUNNER_URL}"
    --token "${RUNNER_TOKEN}"
    --name "${runner_name}"
    --labels "${runner_labels}"
    --work "${runner_workdir}"
    --unattended
    --replace
  )

  if is_true "${RUNNER_EPHEMERAL:-true}"; then
    config_args+=(--ephemeral)
  fi

  if is_true "${RUNNER_DISABLE_UPDATE:-false}"; then
    config_args+=(--disableupdate)
  fi

  ./config.sh "${config_args[@]}"
fi

child_pid=""

forward_signal() {
  local signal_name="$1"
  if [[ -n "${child_pid}" ]]; then
    kill "-${signal_name}" "${child_pid}" 2>/dev/null || true
  fi
}

trap 'forward_signal TERM' TERM
trap 'forward_signal INT' INT

set +e
./run.sh &
child_pid="$!"
wait "${child_pid}"
status="$?"
set -e

exit "${status}"
