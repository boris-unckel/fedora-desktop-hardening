#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_alsa_state.
#
# Reports current state of the alsa-state.service unit, the three drop-in
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

readonly UNIT="alsa-state.service"
readonly DROPIN_DIR="/etc/systemd/system/alsa-state.service.d"
readonly CIL_DIR="/usr/local/share/selinux"
readonly CIL_MODULE="nnp_alsa"
readonly BINARY_BIN_PATH="/usr/bin/alsactl"
readonly BINARY_SBIN_PATH="/usr/sbin/alsactl"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/alsa-state.service"
readonly STATE_FILE_PATH="/var/lib/alsa/asound.state"
readonly -a CORE_PACKAGES=(
  "alsa-utils"
)
readonly -a TRACKED_DIRECTIVES=(
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

probe_live_uid_gid() {
  printf -- '--- live UID/GID of running PID ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    printf 'no MainPID present\n'
    return
  fi
  awk '/^Uid:/{print "Uid: " $2; next} /^Gid:/{print "Gid: " $2}' \
    "/proc/${pid}/status" 2>/dev/null || true
}

probe_live_comm() {
  printf -- '--- live comm of running PID ---\n'
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    printf 'no MainPID present\n'
    return
  fi
  # The vendor ExecStart= carries a leading dash prefix, so a SIGSYS-killed
  # binary would still report an "active" unit to a superficial check; the
  # /proc/<pid>/comm probe surfaces the actual binary name.
  cat "/proc/${pid}/comm" 2>/dev/null || true
}

probe_fcontext() {
  printf -- '--- fcontext mappings (sbin/bin equivalency) ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${BINARY_BIN_PATH}" 2>/dev/null || true
  matchpathcon "${BINARY_SBIN_PATH}" 2>/dev/null || true
}

probe_state_file() {
  printf -- '--- saved-state file ---\n'
  if [[ ! -e "${STATE_FILE_PATH}" ]]; then
    printf 'state file missing: %s\n' "${STATE_FILE_PATH}"
    return
  fi
  stat -c '%n: %s bytes, mtime=%y' "${STATE_FILE_PATH}" 2>/dev/null || true
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
  probe_dropin_files
  probe_cil_source
  probe_merged_unit
  probe_directives
  probe_selinux_domain
  probe_live_uid_gid
  probe_live_comm
  probe_fcontext
  probe_state_file
  probe_journal_heartbeat
  probe_cil_module
  printf -- '--- end of probe ---\n'
}

main "$@"
