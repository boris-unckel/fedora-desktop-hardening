#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_staff_wayland_memfd.
#
# Reports current state of the Wayland-compositor shared-memory buffer
# surface: compositor-package presence, the operator session type, the
# operator's runtime SELinux mapping, the priority-400 module slot, the
# two permissions of the functional allow vector (staff_t × tmpfs_t :
# file { write map }), and the AVC stream filtered for the functional
# class since boot.
#
# The probe never gates on observed state; the end-state of an applied
# host is the priority-400 module installed and both permissions of the
# functional vector present in the loaded policy.
#
# Stages that need policy-store reads (semodule, sesearch, ausearch) are
# gated behind a sysadm_t domain check and reported as SKIP from a
# staff_t shell.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="staff_wayland_memfd"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly EXPECTED_SESSION_TYPE="wayland"
readonly MMAP_BOOLEAN="domain_can_mmap_files"
readonly -a CORE_PACKAGES=(
  "gnome-shell"
  "mutter"
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
  printf '=== probe: staff-wayland-memfd ===\n'
}

probe_packages() {
  printf -- '--- compositor packages ---\n'
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
}

probe_session_type() {
  printf -- '--- operator session type (applicability hint) ---\n'
  local session_type=""
  if command -v loginctl >/dev/null 2>&1; then
    session_type=$(loginctl show-session "${XDG_SESSION_ID:-self}" \
                     -p Type --value 2>/dev/null || true)
  fi
  if [[ -z "${session_type}" ]]; then
    session_type="${XDG_SESSION_TYPE:-unknown}"
  fi
  printf 'session type: %s\n' "${session_type}"
  if [[ "$(printf '%s' "${session_type}" | tr '[:upper:]' '[:lower:]')" \
        == "${EXPECTED_SESSION_TYPE}" ]]; then
    printf 'applicability: matches hint %s\n' "${EXPECTED_SESSION_TYPE}"
  else
    printf 'applicability: not %s; gap unreachable until a Wayland login\n' \
      "${EXPECTED_SESSION_TYPE}"
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

probe_rule_write() {
  printf -- '--- functional permission (staff_t × tmpfs_t : file write) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A -s staff_t -t tmpfs_t -c file -p write \
    || printf '(no allow surface)\n'
}

probe_rule_map() {
  printf -- '--- functional permission (staff_t × tmpfs_t : file map) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  local merged unconditional
  merged=$(sesearch -A -s staff_t -t tmpfs_t -c file -p map 2>/dev/null || true)
  if [[ -z "${merged}" ]]; then
    printf '(no allow surface)\n'
    return
  fi
  printf '%s\n' "${merged}"
  unconditional=$(printf '%s\n' "${merged}" | grep -v "${MMAP_BOOLEAN}" || true)
  printf 'unconditional_map_present: '
  if [[ -n "${unconditional}" ]]; then
    printf 'yes\n'
  else
    printf 'no (only the stock %s boolean-conditional line)\n' "${MMAP_BOOLEAN}"
  fi
}

probe_avc_stream() {
  printf -- '--- AVC stream since boot (functional class only) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    printf 'ausearch: not available\n'
    return
  fi
  ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
    | grep -E 'staff_t.*tmpfs_t.*file' \
    | head -10 \
    || printf '(no functional-class denials since boot)\n'
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_session_type
  probe_operator_mapping
  probe_module_slot
  probe_rule_write
  probe_rule_map
  probe_avc_stream
  printf -- '--- end of probe ---\n'
}

main "$@"
