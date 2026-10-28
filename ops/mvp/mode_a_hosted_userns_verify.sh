#!/usr/bin/env bash
# On GitHub's one-shot Ubuntu runner ONLY. This never edits system Docker.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test "${RUNNER_OS:-}" = Linux
test "${GITHUB_EVENT_NAME:-}" = pull_request
test "$(id -u)" -ne 0
test -x /usr/bin/dockerd
test -x /usr/bin/sudo
test -s proof/som342-openssh-fs.docker.tar.gz
(cd proof && sha256sum -c OFFLINE_IMAGE_SHA256SUMS)
# Hosted RUNNER_TEMP can have a parent (e.g. /home/runner/work/_temp)
# with owner-only traverse, breaking userns graphroot access. /tmp is a
# disposable Ubuntu runner filesystem with traverseable ancestor directories.
scratch="$(mktemp -d /tmp/som342-userns-XXXXXX)"
# Subordinate Docker IDs must traverse their graphroot's ancestors. Grant
# execute-only, NOT read/list/write, on this ephemeral fixture directory.
chmod 0711 "$scratch"
sudo -n mkdir -p "$scratch/data"
sudo -n chmod 0711 "$scratch/data"
daemon_child=""
cleanup() {
  if [ -s "$scratch/dockerd.pid" ]; then
    pid="$(cat "$scratch/dockerd.pid")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1 ]; then
      sudo -n kill -TERM "$pid" 2>/dev/null || true
    fi
  fi
  if [ -n "$daemon_child" ]; then
    wait "$daemon_child" 2>/dev/null || true
  fi
  sudo -n rm -rf -- "$scratch"
}
trap cleanup EXIT
# This is a SECOND separate daemon/data/exec/socket, not a rewrite/restart
# of runner's default Docker Engine or Yuz.local's persistent Docker Desktop.
sudo -n /usr/bin/dockerd \
  --host "unix://$scratch/docker.sock" \
  --data-root "$scratch/data" \
  --exec-root "$scratch/exec" \
  --pidfile "$scratch/dockerd.pid" \
  --userns-remap=default \
  --bridge=none --iptables=false --ip-forward=false --ip-masq=false \
  --log-level error > "$scratch/dockerd.log" 2>&1 &
daemon_child="$!"
export DOCKER_HOST="unix://$scratch/docker.sock"
ready=false
for _ in $(seq 1 75); do
  if docker info --format '{{json .SecurityOptions}}' > "$scratch/options.json" 2>/dev/null; then
    ready=true
    break
  fi
  if ! kill -0 "$daemon_child" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if [ "$ready" != true ]; then
  tail -30 "$scratch/dockerd.log" >&2
  echo 'Refused: dedicated userns Docker daemon unavailable' >&2
  exit 1
fi
python3 - "$scratch/options.json" <<'PY'
import json,sys
opts=json.loads(open(sys.argv[1],encoding="utf8").read())
assert any("userns" in entry for entry in opts),opts
PY
# dockremap subordinate ranges are created by dockerd on the disposable
# Ubuntu runner, never on the operator's Mac. Both host uid/gid must be
# non-root and disjoint from the runner's login uid.
uidbase="$(awk -F: '$1=="dockremap" {print $2;exit}' /etc/subuid)"
gidbase="$(awk -F: '$1=="dockremap" {print $2;exit}' /etc/subgid)"
test -n "$uidbase" && test -n "$gidbase"
test "$uidbase" -ge 65536 && test "$gidbase" -ge 65536
test "$uidbase" -ne "$(id -u)"
test "$gidbase" -ne "$(id -g)"
# Import the exact image archive that passed the earlier normal OCI smoke.
gzip -dc proof/som342-openssh-fs.docker.tar.gz | docker load
expected="$(sed -n 's/^FS_NATIVE_REVIEW_IMAGE_ID=//p' proof/PROVENANCE.txt)"
actual="$(docker image inspect som-mvp-fs-native-review:local --format '{{.Id}}')"
entrypoint="$(docker image inspect som-mvp-fs-native-review:local --format '{{json .Config.Entrypoint}}')"
printf 'REMAPPED_USERNS_BASE_UID=%s GID=%s\n' "$uidbase" "$gidbase"
printf 'RECEIPT_IMAGE_ID=%s\nIMPORTED_IMAGE_ID=%s\n' "$expected" "$actual"
printf 'IMPORTED_ENTRYPOINT=%s\n' "$entrypoint"
test -n "$expected"
# On userns-remapped imports Docker may re-ID ownership-shifted layers.
# This is TEST-ONLY transport proof, NOT a signed-image release decision.
# Do not silently treat a rewritten image ID as the originally signed ID.
echo "REMAPPED_RUNTIME_IMAGE_ID=$actual" >> proof/PROVENANCE.txt
if [ "$actual" != "$expected" ]; then
  echo 'REMAP_IMAGE_ID_MATCHES_BUILD=false' >> proof/PROVENANCE.txt
  echo 'SIGNED_RUNTIME_ID=false' >> proof/PROVENANCE.txt
fi
test "$entrypoint" = '["/usr/local/libexec/ssh-over-mcp-image-hold"]' || { echo 'STOP78 missing after remapped import' >&2; exit 1; }
echo 'REMAPPED_IMAGE_ADMISSION_REACHED=true'
export SOM342_REMAPPED_ROOT_UID="$uidbase"
export SOM342_REMAPPED_ROOT_GID="$gidbase"
python3 ops/mvp/mode_a_hosted_oci_fs_smoke.py

# Independently import the CI-only RUNNABLE candidate into this second,
# isolated userns-remapped Engine; do not modify the shared/default daemon.
# The untrusted image is exercised only with network=none, synthetic keys.
(cd proof && sha256sum -c ONLINE_PILOT_IMAGE_SHA256SUMS)
gzip -dc proof/som342-online-pilot-review.docker.tar.gz | docker load
online_expected="$(sed -n 's/^ONLINE_PILOT_SOURCE_IMAGE_ID=//p' proof/PROVENANCE.txt)"
online_actual="$(docker image inspect som-mvp-fs-online-pilot-review:local --format '{{.Id}}')"
online_entrypoint="$(docker image inspect som-mvp-fs-online-pilot-review:local --format '{{json .Config.Entrypoint}}')"
online_cmd="$(docker image inspect som-mvp-fs-online-pilot-review:local --format '{{json .Config.Cmd}}')"
test -n "$online_expected" && test -n "$online_actual"
test "$online_entrypoint" = '["/usr/sbin/sshd"]'
test "$online_cmd" = '["-D","-e"]'
python3 ops/mvp/mode_a_hosted_runnable_image_probe.py
echo 'ONLINE_PILOT_REMAPPED_IMPORT_DEFAULT_SSHD_FS_PASS'
echo 'ONLINE_PILOT_REMAPPED_DUAL_MCP_LEDGER=true' >> proof/PROVENANCE.txt
echo "ONLINE_PILOT_REMAPPED_IMAGE_ID=$online_actual" >> proof/PROVENANCE.txt
python3 ops/mvp/mode_a_online_pilot_receipt.py "$online_expected" "$online_actual" "$uidbase" "$gidbase"

# Record the tested import ID only AFTER central MCP/Ledger, negative ACL,
# userns mapping and SSH agent checks all completed successfully.
python3 ops/mvp/mode_a_userns_image_receipt.py "$expected" "$actual" "$uidbase" "$gidbase"
echo 'DEDICATED_USERNS_REMAP_OCI_TWO_NODE_FS_PASS'
