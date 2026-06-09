#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# run_system.sh -- run the cumulative system-tier scenario against the base.
#
# Run from the operator workstation. Resolves the base snapshot by label,
# re-syncs the role tree to the control node, then drives `molecule test -s
# system` there. The system scenario provisions one managed node from the base,
# applies the foundation tier plus the cumulative cloud-testable topic set,
# checks idempotence, performs a real reboot (boot-survival), and verifies every
# applied topic post-reboot plus the OpenSCAP / Lynis / systemd-analyze scores
# against the pre-hardening baseline. The reusable infrastructure (base
# snapshot, network, key, control node) is left intact; the managed node is
# torn down by the scenario.
#
# Usage: run_system.sh

SCRIPT_NAME="system"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${HERE}/lib.sh"

ANSIBLE_TREE="$(cd "${HERE}/../../ansible" && pwd)"
readonly ANSIBLE_TREE
readonly REMOTE_LOG_DIR="/root/suite-logs"

resolve_base_image() {
  local id
  id="$(hcloud image list --type snapshot --selector "${LABEL_BASE}" \
    -o noheader -o columns=id | head -n1)"
  [[ -n "${id}" ]] || die "no base snapshot labelled ${LABEL_BASE}; run bake_base_snapshot.sh"
  printf '%s\n' "${id}"
}

sync_tree() {
  local ip
  ip="$(control_ipv4)"
  log "syncing role tree to control node"
  rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    "${ANSIBLE_TREE}/" "root@${ip}:${REMOTE_ANSIBLE}/"
}

main() {
  require_token
  require_local_key
  hcloud_exists "server" "${CONTROL_NAME}" \
    || die "control node absent; run bootstrap_infra.sh"
  local base_id
  base_id="$(resolve_base_image)"
  log "base image id ${base_id}"
  sync_tree

  log "running the system tier (molecule test -s system)"
  local rc=0
  # The molecule run is guarded so the resolved exit code is reported rather
  # than aborting the driver; the decisive verdict is in the tee'd log.
  ssh_control "set -o pipefail
    source ${VENV_DIR}/bin/activate
    source ${REMOTE_ENV_FILE}
    export LIVETEST_BASE_IMAGE='${base_id}'
    mkdir -p ${REMOTE_LOG_DIR}
    cd ${REMOTE_ANSIBLE}
    molecule test -s system 2>&1 | tee ${REMOTE_LOG_DIR}/system.log" \
    || rc=$?

  if [[ "${rc}" -eq 0 ]]; then
    log "=== SYSTEM TIER PASS ==="
    printf 'system PASS\n'
  else
    log "=== SYSTEM TIER FAIL (rc=${rc}) ==="
    local tail_line
    tail_line="$(ssh_control "grep -aE 'fatal:|failed=|assert|boot-survival|FAIL ' ${REMOTE_LOG_DIR}/system.log 2>/dev/null | tail -n1" || true)"
    printf 'system FAIL :: %s\n' "${tail_line}"
  fi
}

main "$@"
