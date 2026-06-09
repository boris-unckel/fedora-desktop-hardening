#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only inventory of the SELinux custom-CIL loader contract.
#
# Reports the values found in each source. Performs no state change. Reads
# that need sysadm_t (semodule -lfull) are wrapped: when the current shell
# is not in sysadm_t, the wrapper reports "(skipped: needs sysadm_t)"
# rather than failing the probe.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly SELINUX_CONFIG="/etc/selinux/config"
readonly CIL_DIR="/usr/local/share/selinux"
readonly REQUIRED_PACKAGES=(
  "policycoreutils-python-utils"
  "selinux-policy-targeted"
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
  printf '=== probe: foundation_selinux_cil_bootstrap ===\n'
}

probe_runtime_mode() {
  printf -- '--- getenforce ---\n'
  if command -v getenforce >/dev/null 2>&1; then
    getenforce 2>/dev/null || printf '(getenforce failed)\n'
  else
    printf '(getenforce not installed)\n'
  fi
}

probe_selinux_config() {
  printf -- '--- %s ---\n' "${SELINUX_CONFIG}"
  if [[ -r "${SELINUX_CONFIG}" ]]; then
    grep -E '^[[:space:]]*(SELINUX|SELINUXTYPE)=' "${SELINUX_CONFIG}" \
      || printf '(no SELINUX= or SELINUXTYPE= directives found)\n'
  else
    printf '(unreadable from current domain)\n'
  fi
}

probe_cil_dir() {
  printf -- '--- %s ---\n' "${CIL_DIR}"
  if [[ -d "${CIL_DIR}" ]]; then
    # shellcheck disable=SC2012
    # ls -lZ is intentional here: the probe surfaces SELinux labels, mode,
    # and owner together for human inspection. find -printf cannot reproduce
    # the -Z column inline.
    ls -ldZ "${CIL_DIR}" 2>/dev/null \
      || printf '(ls -ldZ failed)\n'
    printf -- '--- %s/ contents ---\n' "${CIL_DIR}"
    # shellcheck disable=SC2012
    # ls -lZ is intentional here for the same reason as above; the directory
    # listing is part of the human-inspectable surface.
    ls -lZ "${CIL_DIR}" 2>/dev/null | awk 'NR>1 {print}' \
      || printf '(empty or unreadable)\n'
  else
    printf '(directory not present)\n'
  fi
}

probe_packages() {
  printf -- '--- rpm -q tooling packages ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf '(rpm not available; cannot query package state)\n'
    return
  fi
  local pkg
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    rpm -q "${pkg}" 2>/dev/null || printf '%s: not installed\n' "${pkg}"
  done
}

probe_semodule() {
  printf -- '--- semodule -lfull (priority 400 only) ---\n'
  if ! command -v semodule >/dev/null 2>&1; then
    printf '(semodule not installed)\n'
    return
  fi
  if is_sysadm_t; then
    local out
    out=$(semodule -lfull 2>/dev/null | awk '$1 == "400"')
    if [[ -z "${out}" ]]; then
      printf '(no priority-400 modules present)\n'
    else
      printf '%s\n' "${out}"
    fi
  else
    printf '(skipped: needs sysadm_t)\n'
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_runtime_mode
  probe_selinux_config
  probe_cil_dir
  probe_packages
  probe_semodule
  printf -- '--- end of probe ---\n'
}

main "$@"
