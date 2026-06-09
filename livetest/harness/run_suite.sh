#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# run_suite.sh -- run the component scenarios serially against the base snapshot.
#
# Run from the operator workstation. Resolves the base snapshot by label,
# re-syncs the role tree to the control node so the latest role edits apply,
# then drives `molecule test` for each topic on the control node. Each scenario
# provisions a managed node from the base, applies the foundation tier and the
# one topic, checks idempotence, verifies in both SELinux contexts, and
# destroys its managed node. The reusable infrastructure (base snapshot,
# network, key, control node) is left intact.
#
# Usage:
#   run_suite.sh [topic ...]
#     With no arguments, runs every role that ships a component scenario.
#     With topic names (with or without the topic_ prefix), runs that subset.

SCRIPT_NAME="suite"
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

discover_topics() {
  # Roles that ship a component scenario, derived from the synced tree.
  ssh_control "cd ${REMOTE_ANSIBLE}/roles 2>/dev/null \
    && for d in topic_*/molecule/default/molecule.yml; do \
         [ -f \"\$d\" ] && echo \"\${d%%/*}\"; done | sort"
}

run_one() {
  local role="$1" base_id="$2" rc=0
  log "=== ${role} START ==="
  # A failed molecule run must be recorded, not abort the suite, so the rc is
  # captured with the command guarded against set -e.
  ssh_control "set -o pipefail
    source ${VENV_DIR}/bin/activate
    source ${REMOTE_ENV_FILE}
    export LIVETEST_BASE_IMAGE='${base_id}'
    mkdir -p ${REMOTE_LOG_DIR}
    cd ${REMOTE_ANSIBLE}/roles/${role}
    molecule test 2>&1 | tee ${REMOTE_LOG_DIR}/${role}.log" \
    >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    log "=== ${role} PASS ==="
    printf '%s PASS\n' "${role}"
  else
    log "=== ${role} FAIL (rc=${rc}) ==="
    # Surface the decisive line for the matrix without dragging the whole log.
    local tail_line
    tail_line="$(ssh_control "grep -E 'fatal:|failed=|assert|FAIL ' ${REMOTE_LOG_DIR}/${role}.log 2>/dev/null | tail -n1" || true)"
    printf '%s FAIL :: %s\n' "${role}" "${tail_line}"
  fi
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

  local -a topics
  if [[ "$#" -gt 0 ]]; then
    local t
    for t in "$@"; do
      [[ "${t}" == topic_* ]] && topics+=("${t}") || topics+=("topic_${t}")
    done
  else
    mapfile -t topics < <(discover_topics)
  fi
  log "running ${#topics[@]} topic(s)"

  printf '=== MATRIX (base image %s) ===\n' "${base_id}"
  local role
  for role in "${topics[@]}"; do
    run_one "${role}" "${base_id}"
  done
  printf '=== SUITE DONE ===\n'
}

main "$@"
