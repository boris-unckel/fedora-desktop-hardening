#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for foundation_audit_logging_baseline.
#
# Compares observed state against the baseline declared in
# docs/reference/foundation/audit-logging-baseline.md. Read-only. Reports
# SKIP for checks that need sysadm_t when the current shell is not in
# that domain; SKIP does not count as drift.
#
# The verify script does NOT check for any specific rule content under
# /etc/audit/rules.d/, any specific auditd.conf directive value, or any
# specific journald.conf.d drop-in. Each role that ships such content
# verifies its own content.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly JOURNAL_DIR="/var/log/journal"
readonly EXPECTED_JOURNAL_DIR_MODE="2755"
readonly EXPECTED_JOURNAL_DIR_GROUP="systemd-journal"
readonly REQUIRED_PACKAGES=(
  "audit"
  "audit-libs"
  "audit-rules"
  "policycoreutils-python-utils"
)
readonly REQUIRED_UNITS=(
  "auditd"
  "systemd-journald"
)

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

current_type() {
  id -Z 2>/dev/null | awk -F: '{print $3}'
}

is_sysadm_t() {
  [[ "$(current_type)" == "sysadm_t" ]]
}

report_ok() {
  printf 'OK   %-30s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-30s %s\n' "$1" "$2"
}

report_warn() {
  printf 'WARN %-30s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-30s %s\n' "$1" "$2"
  fail_state=1
}

verify_packages() {
  if ! command -v rpm >/dev/null 2>&1; then
    report_fail "pkg_check" "rpm not available"
    return
  fi
  local pkg label
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    label="pkg_$(printf '%s' "${pkg}" | tr -- '-' '_')"
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      report_ok "${label}" "installed"
    else
      report_fail "${label}" "not installed"
    fi
  done
}

verify_units() {
  if ! command -v systemctl >/dev/null 2>&1; then
    report_fail "unit_check" "systemctl not available"
    return
  fi
  local unit label state
  for unit in "${REQUIRED_UNITS[@]}"; do
    label="unit_$(printf '%s' "${unit}" | tr -- '-' '_')"
    state=$(systemctl is-active "${unit}" 2>/dev/null || true)
    if [[ "${state}" == "active" ]]; then
      report_ok "${label}" "${state}"
    else
      report_fail "${label}" "expected=active actual=${state:-<empty>}"
    fi
  done
}

verify_journal_dir() {
  if [[ ! -d "${JOURNAL_DIR}" ]]; then
    report_fail "journal_dir_present" "${JOURNAL_DIR} not present"
    report_skip "journal_dir_label" "${JOURNAL_DIR} not present"
    return
  fi
  local mode owner group
  mode=$(stat -c '%a' "${JOURNAL_DIR}" 2>/dev/null || true)
  owner=$(stat -c '%U' "${JOURNAL_DIR}" 2>/dev/null || true)
  group=$(stat -c '%G' "${JOURNAL_DIR}" 2>/dev/null || true)
  if [[ "${mode}" == "${EXPECTED_JOURNAL_DIR_MODE}" ]] \
     && [[ "${owner}" == "root" ]] \
     && [[ "${group}" == "${EXPECTED_JOURNAL_DIR_GROUP}" ]]; then
    report_ok "journal_dir_present" \
      "${JOURNAL_DIR} mode=0${mode} owner=${owner}:${group}"
  else
    report_fail "journal_dir_present" \
      "${JOURNAL_DIR} mode=0${mode} owner=${owner}:${group} (expected mode=0${EXPECTED_JOURNAL_DIR_MODE} owner=root:${EXPECTED_JOURNAL_DIR_GROUP})"
  fi
  local label
  label=$(stat -c '%C' "${JOURNAL_DIR}" 2>/dev/null || true)
  if [[ "${label}" == *":var_log_t:"* ]]; then
    report_ok "journal_dir_label" "${label}"
  elif [[ -z "${label}" || "${label}" == "?" ]]; then
    report_skip "journal_dir_label" "label unavailable in current domain"
  else
    report_warn "journal_dir_label" \
      "${label} (expected *:var_log_t:*; non-default label, journald still operational)"
  fi
}

verify_journald_storage() {
  if ! command -v systemctl >/dev/null 2>&1; then
    report_fail "journald_storage_effective" "systemctl not available"
    return
  fi
  # Storage= is a journald.conf setting, not a systemd unit property, so
  # `systemctl show systemd-journald --property=Storage` is always empty.
  # Read the effective value from the merged journald configuration; an unset
  # Storage= defaults to "auto" in journald.
  local storage
  storage=$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null \
              | sed -n 's/^[[:space:]]*Storage[[:space:]]*=[[:space:]]*//p' \
              | tail -1 | tr -d '[:space:]')
  [[ -z "${storage}" ]] && storage="auto"
  case "${storage}" in
    persistent)
      report_ok "journald_storage_effective" "${storage}"
      ;;
    auto)
      if [[ -d "${JOURNAL_DIR}" ]]; then
        report_ok "journald_storage_effective" \
          "auto (flips to persistent given ${JOURNAL_DIR} present)"
      else
        report_warn "journald_storage_effective" \
          "auto without ${JOURNAL_DIR} present; journald is volatile"
      fi
      ;;
    volatile|none)
      report_warn "journald_storage_effective" \
        "${storage} (deliberate operator setting overrides persistent path)"
      ;;
    *)
      report_fail "journald_storage_effective" \
        "unexpected Storage value: ${storage:-<empty>}"
      ;;
  esac
}

verify_auditctl_state() {
  if ! command -v auditctl >/dev/null 2>&1; then
    report_fail "auditctl_state" "auditctl not installed"
    return
  fi
  if ! is_sysadm_t; then
    report_skip "auditctl_state" "needs sysadm_t"
    return
  fi
  local out
  out=$(auditctl -s 2>/dev/null || true)
  if [[ -z "${out}" ]]; then
    report_fail "auditctl_state" "auditctl -s returned empty output"
    return
  fi
  if printf '%s\n' "${out}" | grep -qE '^enabled[[:space:]]+1\b'; then
    local pid_line
    pid_line=$(printf '%s\n' "${out}" \
                | awk '/^pid[[:space:]]/ {print "pid=" $2}')
    report_ok "auditctl_state" "enabled=1 ${pid_line:-pid=?}"
  else
    report_fail "auditctl_state" \
      "enabled flag not set; auditctl -s output: ${out//$'\n'/ | }"
  fi
}

verify_journalctl_disk_usage() {
  if ! command -v journalctl >/dev/null 2>&1; then
    report_fail "journalctl_disk_usage" "journalctl not available"
    return
  fi
  if ! is_sysadm_t; then
    report_skip "journalctl_disk_usage" "needs sysadm_t"
    return
  fi
  local out
  out=$(journalctl --disk-usage 2>/dev/null || true)
  if [[ -n "${out}" ]]; then
    report_ok "journalctl_disk_usage" "${out}"
  else
    report_fail "journalctl_disk_usage" "empty output from journalctl"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool stat
  verify_packages
  verify_units
  verify_journal_dir
  verify_journald_storage
  verify_auditctl_state
  verify_journalctl_disk_usage
  exit "${fail_state}"
}

main "$@"
