#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_cron.
#
# Reports current state of the crond.service unit, the three drop-in
# files, and the topic-owned CIL module. The probe is read-only and
# runnable from a staff_t-confined shell. Checks that need sysadm_t are
# reported as informational; the probe never gates on observed state.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="crond.service"
readonly DROPIN_DIR="/etc/systemd/system/crond.service.d"
readonly CIL_DIR="/usr/local/share/selinux"
readonly CIL_MODULE="nnp_crond"
readonly BINARY_CANONICAL="/usr/bin/crond"
readonly BINARY_PRE_MERGE="/usr/sbin/crond"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/crond.service"
readonly SYSCONFIG_PATH="/etc/sysconfig/crond"
readonly -a CORE_PACKAGES=(
  "cronie"
)
readonly -a TRACKED_DIRECTIVES=(
  NoNewPrivileges
  MemoryDenyWriteExecute
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
  RestrictAddressFamilies
  CapabilityBoundingSet
  SystemCallFilter
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

current_type() {
  id -Z 2>/dev/null | awk -F: '{print $3}'
}

is_sysadm_t() {
  [[ "$(current_type)" == "sysadm_t" ]]
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
  grep -E '^(Type|ExecStart|EnvironmentFile|Condition|RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory|ProtectSystem|SystemCallFilter|MemoryDenyWriteExecute|RestrictNamespaces|RestrictAddressFamilies|DeviceAllow|User|Group|RefuseManualStop)=' \
    "${STOCK_UNIT_PATH}" || printf '(no matching directive in stock unit)\n'
}

probe_sysconfig() {
  printf -- '--- /etc/sysconfig/crond recon ---\n'
  if [[ ! -f "${SYSCONFIG_PATH}" ]]; then
    printf 'sysconfig missing: %s\n' "${SYSCONFIG_PATH}"
    return
  fi
  grep -E '^[A-Z]' "${SYSCONFIG_PATH}" \
    || printf '(no uppercase keys in sysconfig)\n'
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

probe_cil_source() {
  printf -- '--- CIL source ---\n'
  local path="${CIL_DIR}/${CIL_MODULE}.cil"
  if [[ -f "${path}" ]]; then
    # ls -lZ surfaces the SELinux label of the CIL source.
    # shellcheck disable=SC2012
    ls -lZ "${path}" || true
  else
    printf 'missing: %s\n' "${path}"
  fi
}

probe_merged_unit() {
  printf -- '--- merged unit drop-ins and tracked directives ---\n'
  systemctl cat "${UNIT}" 2>&1 \
    | grep -E '99-(hardening|nnp|process-restrict)\.conf|NoNewPrivileges|MemoryDenyWriteExecute|CapabilityBoundingSet|RestrictAddressFamilies|SystemCallFilter|SystemCallArchitectures|ProtectSystem|ProtectHome|ProtectKernel|ProtectControlGroups|PrivateTmp|ProtectClock|ProtectHostname|LockPersonality|RestrictRealtime|RestrictSUIDSGID' \
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

probe_fcontext() {
  printf -- '--- fcontext mapping ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${BINARY_CANONICAL}" 2>/dev/null || true
  matchpathcon "${BINARY_PRE_MERGE}" 2>/dev/null || true
}

probe_journal_heartbeat() {
  printf -- '--- daemon journal heartbeat ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl: not available\n'
    return
  fi
  journalctl -u "${UNIT}" -b --no-pager 2>/dev/null \
    | grep -iE '(STARTUP|inotify|cron-mailer)' \
    || printf '(no STARTUP / inotify / cron-mailer lines since boot)\n'
}

probe_cil_module() {
  printf -- '--- CIL module presence ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP (semodule -l requires sysadm_t)\n'
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    printf 'semodule: not available\n'
    return
  fi
  semodule -l 2>/dev/null | grep -w "${CIL_MODULE}" || \
    printf 'CIL module %s: not loaded\n' "${CIL_MODULE}"
}

main() {
  require_tool systemctl
  print_header
  probe_packages
  probe_unit_state
  probe_stock_unit_directives
  probe_sysconfig
  probe_dropin_files
  probe_cil_source
  probe_merged_unit
  probe_directives
  probe_selinux_domain
  probe_fcontext
  probe_journal_heartbeat
  probe_cil_module
  printf -- '--- end of probe ---\n'
}

main "$@"
