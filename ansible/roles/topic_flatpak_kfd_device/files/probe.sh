#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_flatpak_kfd_device.
#
# Reports current state of the bwrap compute-device bind-source
# surface: package presence and the installed Flatpak version (the
# 1.18 boundary is the trigger discriminator), the operator-installed
# Flatpak inventory (with dri-vs-non-dri discrimination on the
# per-application permissions column), the /dev/kfd device-node state
# including the label-read attempt from the current domain (a failing
# read from staff_t on an existing node is the live symptom signal),
# the operator's runtime SELinux mapping, the priority-400 module
# slot, and the single allow surface of the topic-owned CIL module.
#
# The probe runs NO ausearch stage: the denial class this topic
# patches is dontaudit-suppressed and produces no AVC record in
# either the broken or the healthy state.
#
# The probe never gates on observed state; the end-state of an applied
# host is the priority-400 module installed and the single allow
# surface present in the loaded policy.
#
# Stages that need policy-store reads (semodule, sesearch) are gated
# behind a sysadm_t domain check and reported as SKIP from a staff_t
# shell.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="flatpak_kfd_device"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly DRI_PERMISSION_SUBSTRING="dri"
readonly KFD_NODE_PATH="/dev/kfd"
readonly -a CORE_PACKAGES=(
  "flatpak"
  "bubblewrap"
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

current_type() {
  id -Z 2>/dev/null | awk -F: '{print $3}'
}

is_sysadm_t() {
  [[ "$(current_type)" == "sysadm_t" ]]
}

print_header() {
  printf '=== probe: flatpak-kfd-device ===\n'
}

probe_packages() {
  printf -- '--- packages and flatpak version ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf 'rpm: not available\n'
    return
  fi
  local pkg
  for pkg in "${CORE_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      printf 'core      %s: installed (%s)\n' "${pkg}" "$(rpm -q "${pkg}")"
    else
      printf 'core      %s: missing\n' "${pkg}"
    fi
  done
  if command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak --version: %s\n' "$(flatpak --version 2>/dev/null)"
    printf '(Flatpak 1.18 or later includes %s in the dri device-bind set)\n' \
      "${KFD_NODE_PATH}"
  fi
}

probe_application_inventory() {
  printf -- '--- flatpak application inventory (dri / non-dri discrimination) ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak list --columns=application,permissions 2>/dev/null || true)
  if [[ -z "${listing}" ]]; then
    printf '(no flatpak applications installed)\n'
    return
  fi
  printf '%s\n' "${listing}"
  local dri_count=0
  local total_count=0
  local line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    total_count=$(( total_count + 1 ))
    if [[ "${line}" == *"${DRI_PERMISSION_SUBSTRING}"* ]]; then
      dri_count=$(( dri_count + 1 ))
    fi
  done <<< "${listing}"
  printf 'application_total_count: %d\n' "${total_count}"
  printf 'dri_permission_application_count: %d\n' "${dri_count}"
  if (( dri_count == 0 )); then
    printf 'applicability: no application declares the %s device permission; gap currently unreachable\n' \
      "${DRI_PERMISSION_SUBSTRING}"
    printf '               (the policy patch still applies pre-emptively for future application installs)\n'
  fi
}

probe_device_node() {
  printf -- '--- device node %s ---\n' "${KFD_NODE_PATH}"
  # A bare [[ -e ]] cannot discriminate here: the existence test is
  # itself a stat(2), and on an unpatched staff_t host it fails with
  # EACCES — the very symptom under probe — which would misreport an
  # existing node as absent. Inspect the stat error message instead.
  local stat_out
  if stat_out=$(LC_ALL=C stat -c '%C %A %U:%G %n' "${KFD_NODE_PATH}" 2>&1); then
    printf 'stat from %s succeeds: %s\n' "$(current_type)" "${stat_out}"
  elif [[ "${stat_out}" == *"No such file"* ]]; then
    printf '%s: not present (no AMD GPU or amdgpu driver not loaded); gap unreachable on this host\n' \
      "${KFD_NODE_PATH}"
  else
    printf 'stat from %s fails: %s\n' "$(current_type)" "${stat_out}"
    printf '  the live symptom signal: the stat that fails here is the same\n'
    printf '  access bwrap performs on the bind source at sandbox-construction\n'
    printf '  time (dontaudit-suppressed, no AVC record; the functional allow\n'
    printf '  rule is absent or rolled back)\n'
  fi
}

probe_operator_mapping() {
  printf -- '--- operator runtime SELinux mapping ---\n'
  local id_z
  id_z=$(id -Z 2>/dev/null || true)
  printf 'id -Z: %s\n' "${id_z}"
  if [[ "${id_z}" == *"${EXPECTED_SEUSER_SUBSTRING}"* ]]; then
    printf 'applicability: matches anchor %s\n' "${EXPECTED_SEUSER_SUBSTRING}"
  else
    printf 'applicability: does NOT match anchor %s; topic does not apply\n' \
      "${EXPECTED_SEUSER_SUBSTRING}"
  fi
}

probe_module_slot() {
  printf -- '--- priority-%s module slot ---\n' "${MODULE_PRIORITY}"
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t (run via `sudo -r sysadm_r -t sysadm_t bash probe.sh`)\n'
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    printf 'semodule: not available\n'
    return
  fi
  semodule -lfull \
    | grep -wE "^[ ]*${MODULE_PRIORITY}.*${MODULE_NAME}" \
    || printf '(module not installed at priority %s)\n' "${MODULE_PRIORITY}"
}

probe_rule() {
  printf -- '--- functional rule (staff_t × hsa_device_t : chr_file getattr) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A \
    -s staff_t \
    -t hsa_device_t \
    -c chr_file \
    || printf '(no allow surface)\n'
}

probe_avc_note() {
  printf -- '--- AVC stream note ---\n'
  printf 'no ausearch stage: the getattr denial this topic patches is\n'
  printf 'dontaudit-suppressed; the audit stream is empty in both the\n'
  printf 'broken and the healthy state and carries no signal for this\n'
  printf 'class. The device-node label-read stage above is the\n'
  printf 'functional signal surface.\n'
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_application_inventory
  probe_device_node
  probe_operator_mapping
  probe_module_slot
  probe_rule
  probe_avc_note
  printf -- '--- end of probe ---\n'
}

main "$@"
