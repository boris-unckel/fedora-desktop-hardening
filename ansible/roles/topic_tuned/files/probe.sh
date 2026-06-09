#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_tuned.
#
# Reports current state of the tuned.service unit and the single drop-in
# file. The probe is read-only and runnable from a staff_t-confined shell.
# The probe never gates on observed state.
#
# Deliberate omission: tuned-adm verify is NOT invoked. The command would
# report platform-side mismatches (for example, AHCI ALPM EOPNOTSUPP on
# SATA host ports whose driver does not expose ALPM) that are not topic-
# owned drift signals. The smoketest is tuned-adm active.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="tuned.service"
readonly DROPIN_DIR="/etc/systemd/system/tuned.service.d"
readonly BINARY_PATH_CANONICAL="/usr/bin/tuned"
readonly BINARY_PATH_PREMERGE="/usr/sbin/tuned"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/tuned.service"
readonly -a CORE_PACKAGES=(
  "tuned"
)
readonly -a TRACKED_DIRECTIVES=(
  Type
  ActiveState
  SubState
  Result
  ConditionResult
  ProtectSystem
  ProtectHome
  ProtectKernelTunables
  ProtectKernelModules
  ProtectKernelLogs
  ProtectControlGroups
  PrivateTmp
  ProtectClock
  ProtectHostname
  LockPersonality
  RestrictRealtime
  RestrictSUIDSGID
  SystemCallArchitectures
  MainPID
)
readonly -a EXPLICIT_ABSENCE_DIRECTIVES=(
  NoNewPrivileges
  MemoryDenyWriteExecute
  SystemCallFilter
  CapabilityBoundingSet
  RestrictAddressFamilies
)
readonly -a TRACKED_DROPINS=(
  "99-hardening.conf"
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
}

probe_unit_state() {
  printf -- '--- unit state ---\n'
  systemctl is-active "${UNIT}" || true
  systemctl is-enabled "${UNIT}" || true
}

probe_stock_unit_directives() {
  printf -- '--- stock unit directive recon ---\n'
  if [[ ! -f "${STOCK_UNIT_PATH}" ]]; then
    printf 'stock unit missing: %s\n' "${STOCK_UNIT_PATH}"
    return
  fi
  grep -E '^(Type|ExecStart|EnvironmentFile|Condition|RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory|ProtectSystem|ProtectHome|ProtectKernel|ProtectControl|ProtectClock|ProtectHostname|PrivateTmp|PrivateDevices|RestrictNamespaces|RestrictRealtime|RestrictSUIDSGID|RestrictAddressFamilies|LockPersonality|MemoryDenyWriteExecute|SystemCallFilter|SystemCallArchitectures|DeviceAllow|CapabilityBoundingSet|NoNewPrivileges|UMask|User|Group|RefuseManualStop|RefuseManualStart|Restart|PIDFile|BusName)=' \
    "${STOCK_UNIT_PATH}" || printf '(no matching directive in stock unit)\n'
}

probe_dropin_files() {
  printf -- '--- drop-in files ---\n'
  if [[ ! -d "${DROPIN_DIR}" ]]; then
    printf 'directory missing: %s\n' "${DROPIN_DIR}"
    return
  fi
  # ls -ldZ surfaces the SELinux label alongside the mode/owner. The
  # probe is read-only diagnostics; surfacing the label and mode for
  # operator inspection is the intent of this section.
  # shellcheck disable=SC2012
  ls -ldZ "${DROPIN_DIR}" || true
  local f path
  for f in "${TRACKED_DROPINS[@]}"; do
    path="${DROPIN_DIR}/${f}"
    if [[ -f "${path}" ]]; then
      # ls -lZ surfaces the SELinux label for the operator.
      # shellcheck disable=SC2012
      ls -lZ "${path}" || true
    else
      printf 'missing: %s\n' "${path}"
    fi
  done
}

probe_merged_unit() {
  printf -- '--- merged unit drop-in and tracked directives ---\n'
  systemctl cat "${UNIT}" 2>&1 \
    | grep -E '99-hardening\.conf|ProtectSystem|ProtectHome|ProtectKernel|ProtectControl|PrivateTmp|ProtectClock|ProtectHostname|LockPersonality|RestrictRealtime|RestrictSUIDSGID|SystemCallArchitectures' \
    || true
}

probe_directives() {
  printf -- '--- effective directive values (topic-owned) ---\n'
  local prop value
  for prop in "${TRACKED_DIRECTIVES[@]}"; do
    value=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
    printf '%-26s : %s\n' "${prop}" "${value}"
  done
}

probe_explicit_absence_directives() {
  printf -- '--- effective directive values (explicit-absence baseline) ---\n'
  local prop value
  for prop in "${EXPLICIT_ABSENCE_DIRECTIVES[@]}"; do
    value=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
    printf '%-26s : %s\n' "${prop}" "${value}"
  done
}

probe_fcontext() {
  printf -- '--- fcontext mapping (canonical and pre-merge paths) ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${BINARY_PATH_CANONICAL}" 2>/dev/null || true
  matchpathcon "${BINARY_PATH_PREMERGE}" 2>/dev/null || true
  matchpathcon "${DROPIN_DIR}/99-hardening.conf" 2>/dev/null || true
}

probe_selinux_domain() {
  printf -- '--- SELinux domain of running PID ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    printf 'SKIP — service inactive (no MainPID)\n'
    return
  fi
  awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null || true
}

probe_tuned_adm_active() {
  printf -- '--- tuned-adm active (smoketest) ---\n'
  if ! command -v tuned-adm >/dev/null 2>&1; then
    printf 'tuned-adm: not available\n'
    return
  fi
  tuned-adm active 2>&1 || true
}

probe_journal_heartbeat() {
  printf -- '--- daemon journal heartbeat ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl: not available\n'
    return
  fi
  journalctl -u "${UNIT}" -n 20 --no-pager 2>/dev/null \
    || printf '(no journal entries)\n'
}

main() {
  require_tool systemctl
  print_header
  probe_packages
  probe_unit_state
  probe_stock_unit_directives
  probe_dropin_files
  probe_merged_unit
  probe_directives
  probe_explicit_absence_directives
  probe_fcontext
  probe_selinux_domain
  probe_tuned_adm_active
  probe_journal_heartbeat
  printf -- '--- end of probe ---\n'
}

main "$@"
