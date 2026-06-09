#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_aide.
#
# Reports current state of the aide-check.timer + aide-check.service unit
# pair, the topic-owned CIL module, the AIDE database and configuration
# files, and the most-recent run's exit status. The probe is read-only
# and runnable from a staff_t-confined shell. Checks that need sysadm_t
# are reported as informational; the probe never gates on observed state.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly TIMER_UNIT="aide-check.timer"
readonly SERVICE_UNIT="aide-check.service"
readonly UNIT_DIR="/etc/systemd/system"
readonly CIL_DIR="/usr/local/share/selinux"
readonly CIL_MODULE="aide_extras"
readonly PROFILE_D_DIR="/etc/profile.d"
readonly BANNER_FILE="aide-alert.sh"
readonly BINARY_CANONICAL="/usr/bin/aide"
readonly BINARY_PRE_MERGE="/usr/sbin/aide"
readonly DB_PATH="/var/lib/aide/aide.db.gz"
readonly CONF_PATH="/etc/aide.conf"
readonly DB_DIR="/var/lib/aide"
readonly LOG_DIR="/var/log/aide"
readonly SCOPE_MARKER="topic_aide scope tuning (managed)"
readonly BANNER_ACK_MARKER="_aide_mono"
readonly -a CORE_PACKAGES=(
  "aide"
)
readonly -a TRACKED_RUN_PROPS=(
  ExecMainStatus
  ExecMainExitTimestamp
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
  printf '=== probe: %s + %s ===\n' "${TIMER_UNIT}" "${SERVICE_UNIT}"
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

probe_timer_state() {
  printf -- '--- timer state ---\n'
  systemctl is-active "${TIMER_UNIT}" || true
  systemctl is-enabled "${TIMER_UNIT}" || true
  systemctl list-timers "${TIMER_UNIT}" --no-pager 2>/dev/null || true
}

probe_unit_files() {
  printf -- '--- unit files ---\n'
  local f path
  for f in "${SERVICE_UNIT}" "${TIMER_UNIT}"; do
    path="${UNIT_DIR}/${f}"
    if [[ -f "${path}" ]]; then
      # ls -lZ surfaces the SELinux label for the operator.
      # shellcheck disable=SC2012
      ls -lZ "${path}" || true
    else
      printf 'missing: %s\n' "${path}"
    fi
  done
}

probe_merged_units() {
  printf -- '--- merged unit bodies ---\n'
  systemctl cat "${SERVICE_UNIT}" 2>&1 || true
  printf -- '\n'
  systemctl cat "${TIMER_UNIT}" 2>&1 || true
}

probe_run_props() {
  printf -- '--- most-recent run properties ---\n'
  local prop value
  for prop in "${TRACKED_RUN_PROPS[@]}"; do
    value=$(systemctl show -p "${prop}" --value "${SERVICE_UNIT}" 2>/dev/null \
             || true)
    printf '%-26s : %s\n' "${prop}" "${value}"
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

probe_banner_source() {
  printf -- '--- banner source ---\n'
  local path="${PROFILE_D_DIR}/${BANNER_FILE}"
  if [[ -f "${path}" ]]; then
    # ls -lZ surfaces the SELinux label of the banner.
    # shellcheck disable=SC2012
    ls -lZ "${path}" || true
  else
    printf 'banner not installed: %s\n' "${path}"
  fi
}

probe_db_and_conf() {
  printf -- '--- database and configuration ---\n'
  if [[ -f "${DB_PATH}" ]]; then
    stat -c '%n %a %U %G %C' "${DB_PATH}" 2>/dev/null || true
  else
    printf 'database missing: %s\n' "${DB_PATH}"
  fi
  if [[ -f "${CONF_PATH}" ]]; then
    stat -c '%n %a %U %G %C' "${CONF_PATH}" 2>/dev/null || true
  else
    printf 'configuration missing: %s\n' "${CONF_PATH}"
  fi
}

probe_state_dirs() {
  printf -- '--- state directories ---\n'
  if [[ -d "${DB_DIR}" ]]; then
    # ls -ldZ surfaces the SELinux label of the database directory.
    # shellcheck disable=SC2012
    ls -ldZ "${DB_DIR}" || true
  else
    printf 'database directory missing: %s\n' "${DB_DIR}"
  fi
  if [[ -d "${LOG_DIR}" ]]; then
    # ls -ldZ surfaces the SELinux label of the log directory.
    # shellcheck disable=SC2012
    ls -ldZ "${LOG_DIR}" || true
  else
    printf 'log directory missing: %s\n' "${LOG_DIR}"
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

probe_recent_journal() {
  printf -- '--- recent service journal ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl: not available\n'
    return
  fi
  journalctl -u "${SERVICE_UNIT}" -b 0 --no-pager 2>/dev/null \
    | tail -20 \
    || printf '(no journal entries since boot)\n'
}

probe_scope_block() {
  printf -- '--- aide.conf scope-tuning block ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP (reading %s requires sysadm_t)\n' "${CONF_PATH}"
    return
  fi
  if [[ ! -r "${CONF_PATH}" ]]; then
    printf 'configuration not readable: %s\n' "${CONF_PATH}"
    return
  fi
  if grep -qF "${SCOPE_MARKER}" "${CONF_PATH}"; then
    printf 'scope-tuning marker present\n'
  else
    printf 'scope-tuning marker absent\n'
  fi
}

probe_config_check() {
  printf -- '--- aide --config-check ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP (aide --config-check requires sysadm_t to read %s)\n' \
      "${CONF_PATH}"
    return
  fi
  if ! command -v aide >/dev/null 2>&1; then
    printf 'aide: not available\n'
    return
  fi
  if aide --config-check >/dev/null 2>&1; then
    printf 'config-check: clean parse\n'
  else
    printf 'config-check: parse error (run aide --config-check for detail)\n'
  fi
}

probe_banner_ack() {
  printf -- '--- banner acknowledgement block ---\n'
  local path="${PROFILE_D_DIR}/${BANNER_FILE}"
  if [[ ! -f "${path}" ]]; then
    printf 'banner not installed: %s\n' "${path}"
    return
  fi
  if grep -qF "${BANNER_ACK_MARKER}" "${path}"; then
    printf 'acknowledgement block present (%s)\n' "${BANNER_ACK_MARKER}"
  else
    printf 'acknowledgement block absent (pre-ack banner)\n'
  fi
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
  probe_timer_state
  probe_unit_files
  probe_merged_units
  probe_run_props
  probe_cil_source
  probe_banner_source
  probe_db_and_conf
  probe_state_dirs
  probe_fcontext
  probe_recent_journal
  probe_scope_block
  probe_config_check
  probe_banner_ack
  probe_cil_module
  printf -- '--- end of probe ---\n'
}

main "$@"
