#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only inventory of the audit-and-logging baseline.
#
# Reports the values found in each source. Performs no state change.
# Reads that need sysadm_t (auditctl -s, journalctl --disk-usage) are
# wrapped: when the current shell is not in sysadm_t, the wrapper reports
# "(skipped: needs sysadm_t)" rather than failing the probe.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly JOURNAL_DIR="/var/log/journal"
readonly REQUIRED_PACKAGES=(
  "audit"
  "audit-libs"
  "audit-rules"
  "policycoreutils-python-utils"
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
  printf '=== probe: foundation_audit_logging_baseline ===\n'
}

probe_packages() {
  printf -- '--- rpm -q audit pipeline + diagnosis tooling ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf '(rpm not available; cannot query package state)\n'
    return
  fi
  local pkg
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    rpm -q "${pkg}" 2>/dev/null || printf '%s: not installed\n' "${pkg}"
  done
}

probe_units() {
  printf -- '--- systemctl is-active (auditd, systemd-journald) ---\n'
  if ! command -v systemctl >/dev/null 2>&1; then
    printf '(systemctl not available)\n'
    return
  fi
  local unit
  for unit in auditd systemd-journald; do
    printf '%-22s %s\n' "${unit}" "$(systemctl is-active "${unit}" 2>/dev/null || true)"
  done
}

probe_journal_dir() {
  printf -- '--- %s ---\n' "${JOURNAL_DIR}"
  if [[ -d "${JOURNAL_DIR}" ]]; then
    # shellcheck disable=SC2012
    # ls -ldZ is intentional here: the probe surfaces SELinux labels,
    # mode, and owner together for human inspection. find -printf cannot
    # reproduce the -Z column inline.
    ls -ldZ "${JOURNAL_DIR}" 2>/dev/null \
      || printf '(ls -ldZ failed)\n'
  else
    printf '(directory not present; journald stays volatile)\n'
  fi
}

probe_journald_show() {
  printf -- '--- systemctl show systemd-journald (read-only) ---\n'
  if ! command -v systemctl >/dev/null 2>&1; then
    printf '(systemctl not available)\n'
    return
  fi
  systemctl show systemd-journald \
    --property=Storage,RuntimeMaxUse,SystemMaxUse,SystemKeepFree,Seal \
    2>/dev/null \
    || printf '(systemctl show failed)\n'
}

probe_auditctl_state() {
  printf -- '--- auditctl -s ---\n'
  if ! command -v auditctl >/dev/null 2>&1; then
    printf '(auditctl not installed)\n'
    return
  fi
  if is_sysadm_t; then
    auditctl -s 2>/dev/null || printf '(auditctl -s failed)\n'
  else
    printf '(skipped: needs sysadm_t)\n'
  fi
}

probe_journalctl_disk_usage() {
  printf -- '--- journalctl --disk-usage ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf '(journalctl not available)\n'
    return
  fi
  if is_sysadm_t; then
    journalctl --disk-usage 2>/dev/null \
      || printf '(journalctl --disk-usage failed)\n'
  else
    printf '(skipped: needs sysadm_t)\n'
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_units
  probe_journal_dir
  probe_journald_show
  probe_auditctl_state
  probe_journalctl_disk_usage
  printf -- '--- end of probe ---\n'
}

main "$@"
