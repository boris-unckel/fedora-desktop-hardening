#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_cups.
#
# Reports current state of the cups.service unit, the two drop-in files,
# and the topic-owned CIL module. The probe is read-only and runnable
# from a staff_t-confined shell. Checks that need sysadm_t are reported
# as informational; the probe never gates on observed state.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="cups.service"
readonly DROPIN_DIR="/etc/systemd/system/cups.service.d"
readonly CIL_DIR="/usr/local/share/selinux"
readonly CIL_MODULE="nnp_cups"
readonly DAEMON_SBIN_PATH="/usr/sbin/cupsd"
readonly DAEMON_BIN_PATH="/usr/bin/cupsd"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/cups.service"
readonly -a CORE_PACKAGES=(
  "cups"
)
readonly -a TRACKED_DIRECTIVES=(
  NoNewPrivileges
  ProtectClock
  ProtectKernelLogs
  ProtectKernelModules
  ProtectControlGroups
  SystemCallArchitectures
  MemoryDenyWriteExecute
  RestrictNamespaces
  MainPID
)
readonly -a TRACKED_DROPINS=(
  "99-hardening.conf"
  "99-nnp.conf"
)
readonly -a HELPER_SUBDOMAINS=(
  "cupsd_lpd_t"
  "cupsd_config_t"
  "cups_pdf_t"
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
  grep -E '^(RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory|ProtectSystem|ProtectHome|ProtectKernel|ProtectControl|ProtectClock|ProtectHostname|ProtectProc|PrivateTmp|PrivateDevices|PrivateUsers|RestrictNamespaces|RestrictRealtime|RestrictSUIDSGID|RestrictAddressFamilies|LockPersonality|MemoryDenyWriteExecute|SystemCallFilter|SystemCallArchitectures|DeviceAllow|CapabilityBoundingSet|NoNewPrivileges|AmbientCapabilities|UMask|ProcSubset|User|Group|Type|ExecStart|ExecReload|Slice|Restart|NotifyAccess)=' \
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
    | grep -E '99-(hardening|nnp)\.conf|NoNewPrivileges|ProtectClock|ProtectKernelLogs|ProtectKernelModules|ProtectControlGroups|SystemCallArchitectures|MemoryDenyWriteExecute|RestrictNamespaces' \
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
  matchpathcon "${DAEMON_SBIN_PATH}" 2>/dev/null || true
  matchpathcon "${DAEMON_BIN_PATH}" 2>/dev/null || true
}

probe_listen_sockets() {
  printf -- '--- listening sockets on tcp/631 ---\n'
  if ! command -v ss >/dev/null 2>&1; then
    printf 'ss: not available\n'
    return
  fi
  ss -ltn 'sport = 631' 2>/dev/null || true
}

probe_lpstat() {
  printf -- '--- lpstat -p -d ---\n'
  if ! command -v lpstat >/dev/null 2>&1; then
    printf 'lpstat: not available\n'
    return
  fi
  lpstat -p -d 2>&1 || true
}

probe_lpinfo() {
  printf -- '--- lpinfo -v ---\n'
  if ! command -v lpinfo >/dev/null 2>&1; then
    printf 'lpinfo: not available\n'
    return
  fi
  lpinfo -v 2>&1 || true
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

probe_helper_nnp_rules() {
  printf -- '--- helper-subdomain nnp_transition rule presence ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP (sesearch requires sysadm_t)\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A -s init_t -t cupsd_t -c process2 -p nnp_transition 2>/dev/null \
    || printf '(no init_t -> cupsd_t rule)\n'
  local helper
  for helper in "${HELPER_SUBDOMAINS[@]}"; do
    sesearch -A -s cupsd_t -t "${helper}" -c process2 -p nnp_transition 2>/dev/null \
      || printf '(no cupsd_t -> %s rule)\n' "${helper}"
  done
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
  probe_fcontext
  probe_listen_sockets
  probe_lpstat
  probe_lpinfo
  probe_cil_module
  probe_helper_nnp_rules
  printf -- '--- end of probe ---\n'
}

main "$@"
