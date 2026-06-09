#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_plymouth.
#
# Reports current state of the plymouth-start.service unit, the three
# drop-in files, and the topic-owned CIL module. The probe is read-only
# and runnable from a staff_t-confined shell. Checks that need sysadm_t
# are reported as informational; the probe never gates on observed
# state.
#
# plymouth-start settles into `active (exited)` after the splash hand-off
# completes, so no MainPID is present at probe time. The probe reports
# the static type-transition mapping (sesearch -T) and the binary
# fcontext (matchpathcon) instead of a live SELinux-domain read.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="plymouth-start.service"
readonly QUITWAIT_UNIT="plymouth-quit-wait.service"
readonly DROPIN_DIR="/etc/systemd/system/plymouth-start.service.d"
readonly CIL_DIR="/usr/local/share/selinux"
readonly CIL_MODULE="nnp_plymouth"
readonly DAEMON_BIN_PATH="/usr/bin/plymouthd"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/plymouth-start.service"
readonly EXPECTED_DOMAIN="plymouthd_t"
readonly -a CORE_PACKAGES=(
  "plymouth"
)
readonly -a TRACKED_DIRECTIVES=(
  Type
  Result
  ActiveState
  SubState
  NoNewPrivileges
  ProtectSystem
  ProtectHome
  ProtectKernelTunables
  ProtectKernelModules
  ProtectKernelLogs
  ProtectControlGroups
  ProtectClock
  ProtectHostname
  PrivateTmp
  ReadWritePaths
  LockPersonality
  RestrictRealtime
  RestrictSUIDSGID
  RestrictNamespaces
  SystemCallArchitectures
  PrivateNetwork
  RestrictAddressFamilies
  MemoryDenyWriteExecute
  SystemCallFilter
  CapabilityBoundingSet
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

probe_quitwait_state() {
  printf -- '--- plymouth-quit-wait state (boot-completion anchor) ---\n'
  systemctl show "${QUITWAIT_UNIT}" \
    -p ActiveState,SubState,Result --value 2>/dev/null \
    || printf '(plymouth-quit-wait state read failed)\n'
}

probe_stock_unit_directives() {
  printf -- '--- stock unit directive recon ---\n'
  if [[ ! -f "${STOCK_UNIT_PATH}" ]]; then
    printf 'stock unit missing: %s\n' "${STOCK_UNIT_PATH}"
    return
  fi
  grep -E '^(RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory|ProtectSystem|ProtectHome|ProtectKernel|ProtectControl|ProtectClock|ProtectHostname|ProtectProc|PrivateTmp|PrivateDevices|PrivateUsers|PrivateNetwork|RestrictNamespaces|RestrictRealtime|RestrictSUIDSGID|RestrictAddressFamilies|LockPersonality|MemoryDenyWriteExecute|SystemCallFilter|SystemCallArchitectures|DeviceAllow|CapabilityBoundingSet|NoNewPrivileges|AmbientCapabilities|UMask|ProcSubset|User|Group|Type|ExecStart|ExecReload|Slice|Restart|NotifyAccess)=' \
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
    | grep -E '99-(hardening|nnp|process-restrict)\.conf|NoNewPrivileges|ProtectSystem|ProtectHome|ProtectKernel|ProtectControl|ProtectClock|ProtectHostname|PrivateTmp|ReadWritePaths|LockPersonality|RestrictRealtime|RestrictSUIDSGID|RestrictNamespaces|SystemCallArchitectures|PrivateNetwork|RestrictAddressFamilies|MemoryDenyWriteExecute|SystemCallFilter|CapabilityBoundingSet' \
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

probe_selinux_type_transition() {
  printf -- '--- SELinux type-transition for plymouthd binary ---\n'
  printf 'expected domain: %s\n' "${EXPECTED_DOMAIN}"
  printf 'note: plymouth-start has no MainPID at probe time '
  printf '(active/exited after splash hand-off).\n'
  if ! is_sysadm_t; then
    printf 'SKIP (sesearch requires sysadm_t)\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -T -s init_t -t plymouthd_exec_t -c process 2>/dev/null \
    || printf '(no init_t -> plymouthd_exec_t type-transition rule)\n'
}

probe_fcontext() {
  printf -- '--- fcontext mapping ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${DAEMON_BIN_PATH}" 2>/dev/null || true
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
  probe_quitwait_state
  probe_stock_unit_directives
  probe_dropin_files
  probe_cil_source
  probe_merged_unit
  probe_directives
  probe_selinux_type_transition
  probe_fcontext
  probe_cil_module
  printf -- '--- end of probe ---\n'
}

main "$@"
