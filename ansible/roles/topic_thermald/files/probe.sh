#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_thermald.
#
# Reports current state of the thermald.service unit and the three drop-in
# files. The probe is read-only and runnable from a staff_t-confined shell.
# The probe never gates on observed state and accepts both Soll states:
# DPTF-bearing host (active/running) and DPTF-less host (inactive/dead).
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="thermald.service"
readonly DROPIN_DIR="/etc/systemd/system/thermald.service.d"
readonly BINARY_PATH="/usr/bin/thermald"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/thermald.service"
readonly -a CORE_PACKAGES=(
  "thermald"
)
readonly -a TRACKED_DIRECTIVES=(
  Type
  ActiveState
  SubState
  Result
  ConditionResult
  NoNewPrivileges
  MemoryDenyWriteExecute
  CapabilityBoundingSet
  RestrictAddressFamilies
  SystemCallFilter
  SystemCallArchitectures
  ProtectSystem
  MainPID
)
readonly -a TRACKED_DROPINS=(
  "99-hardening.conf"
  "99-nnp.conf"
  "99-process-restrict.conf"
)
readonly -a FORBIDDEN_POLICY_TYPES=(
  thermald_t
  thermald_exec_t
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
  grep -E '^(Type|ExecStart|EnvironmentFile|Condition|RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory|ProtectSystem|SystemCallFilter|MemoryDenyWriteExecute|RestrictNamespaces|RestrictAddressFamilies|DeviceAllow|User|Group)=' \
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
  printf -- '--- merged unit drop-ins and tracked directives ---\n'
  systemctl cat "${UNIT}" 2>&1 \
    | grep -E '99-(hardening|nnp|process-restrict)\.conf|NoNewPrivileges|MemoryDenyWriteExecute|CapabilityBoundingSet|RestrictAddressFamilies|SystemCallFilter|SystemCallArchitectures|ProtectSystem' \
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

probe_fcontext() {
  printf -- '--- fcontext mapping (no service-specific subtype expected) ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${BINARY_PATH}" 2>/dev/null || true
}

probe_stock_policy_absence() {
  printf -- '--- stock policy domain absence (expected: empty) ---\n'
  if ! command -v seinfo >/dev/null 2>&1; then
    printf 'seinfo: not available\n'
    return
  fi
  local pattern
  pattern=$(IFS='|'; printf '%s' "${FORBIDDEN_POLICY_TYPES[*]}")
  local hits
  hits=$(seinfo --type 2>/dev/null | grep -wE "${pattern}" || true)
  if [[ -z "${hits}" ]]; then
    printf '(no thermald-related types in stock policy — Soll on F44)\n'
  else
    printf 'unexpected types present:\n%s\n' "${hits}"
  fi
}

probe_selinux_domain() {
  printf -- '--- SELinux domain of running PID (DPTF-bearing branch) ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    printf 'SKIP — service inactive (Soll on hosts without DPTF)\n'
    return
  fi
  awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null || true
}

probe_live_uid_gid() {
  printf -- '--- live UID/GID of running PID (DPTF-bearing branch) ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    printf 'SKIP — service inactive (Soll on hosts without DPTF)\n'
    return
  fi
  awk '/^Uid:/{print "Uid: " $2; next} /^Gid:/{print "Gid: " $2}' \
    "/proc/${pid}/status" 2>/dev/null || true
}

probe_journal_heartbeat() {
  printf -- '--- daemon journal heartbeat ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl: not available\n'
    return
  fi
  # On hosts without DPTF the journal typically shows "Unsupported cpu
  # model or platform" plus a clean exit; on hosts with DPTF the journal
  # shows the loaded thermal table and ongoing dbus activity.
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
  probe_fcontext
  probe_stock_policy_absence
  probe_selinux_domain
  probe_live_uid_gid
  probe_journal_heartbeat
  printf -- '--- end of probe ---\n'
}

main "$@"
