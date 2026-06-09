#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only inventory of staff_u and sudo role-transition state.
#
# Reports the values found in each source. Performs no state change. Reads
# that need sysadm_t (the policy-store and selabel inspection commands) are
# wrapped: when the current shell is not in sysadm_t, the wrapper reports
# "(skipped: needs sysadm_t)" rather than failing the probe.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly SEUSERS="/etc/selinux/targeted/seusers"
readonly SUDOERS="/etc/sudoers"
readonly SUDOERS_D="/etc/sudoers.d"
readonly CIL_MODULE_NAME="staff_extras"

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
  printf '=== probe: foundation_sudo_roles ===\n'
}

probe_seusers() {
  printf -- '--- %s ---\n' "${SEUSERS}"
  if [[ -r "${SEUSERS}" ]]; then
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "${SEUSERS}" \
      || printf '(no mapping rows present)\n'
  else
    printf '(unreadable from current domain)\n'
  fi
}

probe_semanage_login() {
  printf -- '--- semanage login --list ---\n'
  if is_sysadm_t; then
    semanage login --list 2>/dev/null \
      || printf '(semanage login --list failed)\n'
  else
    printf '(skipped: needs sysadm_t)\n'
  fi
}

probe_seinfo() {
  printf -- '--- seinfo -u staff_u / -r sysadm_r ---\n'
  if command -v seinfo >/dev/null 2>&1; then
    seinfo -u staff_u 2>/dev/null \
      || printf '(seinfo -u staff_u failed)\n'
    seinfo -r sysadm_r 2>/dev/null \
      || printf '(seinfo -r sysadm_r failed)\n'
  else
    printf '(seinfo not installed; expected from setools-console)\n'
  fi
}

probe_semodule() {
  printf -- '--- semodule -lfull | grep %s ---\n' "${CIL_MODULE_NAME}"
  if is_sysadm_t; then
    semodule -lfull 2>/dev/null | grep -E "[[:space:]]${CIL_MODULE_NAME}[[:space:]]" \
      || printf '(module %s not present at any priority)\n' "${CIL_MODULE_NAME}"
  else
    printf '(skipped: needs sysadm_t)\n'
  fi
}

probe_id_z() {
  printf -- '--- id -Z (current shell) ---\n'
  id -Z 2>/dev/null \
    || printf '(id -Z unavailable)\n'
}

probe_sudoers_secure_path() {
  printf -- '--- %s | secure_path ---\n' "${SUDOERS}"
  if [[ -r "${SUDOERS}" ]]; then
    grep -nE '^[[:space:]]*Defaults[[:space:]]+secure_path' "${SUDOERS}" \
      || printf '(no secure_path Defaults found)\n'
  else
    printf '(unreadable from current domain)\n'
  fi
}

probe_sudoers_global_logfile() {
  printf -- '--- %s | logfile ---\n' "${SUDOERS}"
  if [[ -r "${SUDOERS}" ]]; then
    grep -nE '^[[:space:]]*Defaults[[:space:]]+logfile=' "${SUDOERS}" \
      || printf '(no global Defaults logfile= directive)\n'
  else
    printf '(unreadable from current domain)\n'
  fi
}

probe_sudoers_d_drop_ins() {
  printf -- '--- %s/ ---\n' "${SUDOERS_D}"
  if [[ -d "${SUDOERS_D}" ]] && [[ -r "${SUDOERS_D}" ]]; then
    local entries
    # shellcheck disable=SC2012
    # ls -lZ is intentional here: the probe surfaces SELinux labels, mode,
    # and owner together for human inspection. find -printf cannot reproduce
    # the -Z column inline.
    entries=$(ls -lZ "${SUDOERS_D}" 2>/dev/null | awk 'NR>1 {print}')
    if [[ -z "${entries}" ]]; then
      printf '(empty)\n'
    else
      printf '%s\n' "${entries}"
    fi
    printf -- '--- drop-ins with custom logfile= directive ---\n'
    local hits
    hits=$(grep -lE '^[[:space:]]*Defaults![^[:space:]]+[[:space:]]+logfile=' \
             "${SUDOERS_D}"/* 2>/dev/null || true)
    if [[ -z "${hits}" ]]; then
      printf '(none)\n'
    else
      printf '%s\n' "${hits}"
    fi
  else
    printf '(unreadable from current domain)\n'
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_seusers
  probe_semanage_login
  probe_seinfo
  probe_semodule
  probe_id_z
  probe_sudoers_secure_path
  probe_sudoers_global_logfile
  probe_sudoers_d_drop_ins
  printf -- '--- end of probe ---\n'
}

main "$@"
