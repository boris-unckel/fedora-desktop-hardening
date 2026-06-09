#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_udisks2.
#
# Reports current state of the udisks2.service unit and the three drop-in
# files this role manages. Read-only: performs no state change. Runnable
# from a staff_t-confined shell; checks that need sysadm_t are reported
# but not gated.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="udisks2.service"
readonly DROPIN_DIR="/etc/systemd/system/udisks2.service.d"
readonly -a CORE_PACKAGES=(
  "udisks2"
)
readonly -a OPTIONAL_PACKAGES=(
  "udisks2-iscsi"
  "udisks2-lvm2"
  "udisks2-btrfs"
)
readonly -a TRACKED_DIRECTIVES=(
  NoNewPrivileges
  MemoryDenyWriteExecute
  CapabilityBoundingSet
  RestrictAddressFamilies
  SystemCallFilter
  PrivateMounts
  MainPID
)
readonly -a TRACKED_DROPINS=(
  "99-hardening.conf"
  "99-nnp.conf"
  "99-process-restrict.conf"
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

print_header() {
  printf '=== probe: %s ===\n' "${UNIT}"
}

probe_packages() {
  printf -- '--- packages ---\n'
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
  for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      printf 'optional  %s: installed (%s)\n' "${pkg}" "$(rpm -q "${pkg}")"
    else
      printf 'optional  %s: absent (informational, not required)\n' "${pkg}"
    fi
  done
}

probe_unit_state() {
  printf -- '--- unit state ---\n'
  systemctl is-active "${UNIT}" || true
  systemctl is-enabled "${UNIT}" || true
}

probe_dropin_files() {
  printf -- '--- drop-in files ---\n'
  if [[ ! -d "${DROPIN_DIR}" ]]; then
    printf 'directory missing: %s\n' "${DROPIN_DIR}"
    return
  fi
  # ls -ldZ shows the SELinux label alongside the mode/owner. The probe is
  # read-only diagnostics; parsing ls output is acceptable here because
  # only the label and mode are surfaced for operator inspection.
  # shellcheck disable=SC2012
  ls -ldZ "${DROPIN_DIR}" || true
  local f path
  for f in "${TRACKED_DROPINS[@]}"; do
    path="${DROPIN_DIR}/${f}"
    if [[ -f "${path}" ]]; then
      # shellcheck disable=SC2012
      ls -lZ "${path}" || true
    else
      printf 'missing: %s\n' "${path}"
    fi
  done
}

probe_merged_unit() {
  printf -- '--- merged unit drop-ins and tracked directives ---\n'
  systemctl cat "${UNIT}" 2>&1 \
    | grep -E '99-(hardening|nnp|process-restrict)\.conf|NoNewPrivileges|MemoryDenyWriteExecute|CapabilityBoundingSet|RestrictAddressFamilies|SystemCallFilter|PrivateMounts' \
    || true
}

probe_directives() {
  printf -- '--- effective directive values ---\n'
  local prop value
  for prop in "${TRACKED_DIRECTIVES[@]}"; do
    value=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
    printf '%-26s : %s\n' "${prop}" "${value}"
  done
}

probe_selinux_domain() {
  printf -- '--- SELinux domain of running PID ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" != "0" && -d "/proc/${pid}" ]]; then
    awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null || true
  else
    printf 'no MainPID present\n'
  fi
}

probe_dbus_status() {
  printf -- '--- udisksctl status (D-Bus client view) ---\n'
  if ! command -v udisksctl >/dev/null 2>&1; then
    printf 'udisksctl: not available\n'
    return
  fi
  udisksctl status 2>&1 | head -20 || true
}

main() {
  require_tool systemctl
  print_header
  probe_packages
  probe_unit_state
  probe_dropin_files
  probe_merged_unit
  probe_directives
  probe_selinux_domain
  probe_dbus_status
  printf -- '--- end of probe ---\n'
}

main "$@"
