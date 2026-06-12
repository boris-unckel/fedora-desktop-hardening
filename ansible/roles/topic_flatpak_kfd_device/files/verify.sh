#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_flatpak_kfd_device.
#
# Compares observed runtime state against the expected end-state
# declared in docs/reference/topics/flatpak-kfd-device.md. The
# end-state is the priority-400 module flatpak_kfd_device loaded
# with the single allow surface present in the loaded policy:
#   - functional: staff_t × hsa_device_t : chr_file getattr
# plus a succeeding stat(2) on /dev/kfd from the staff_t shell.
#
# There is NO AVC-clean check: the denial class this topic patches is
# dontaudit-suppressed and produces no audit record in either the
# broken or the healthy state; an ausearch-based assertion would be
# vacuously green on an unpatched host. The functional stat check is
# the substitute — it exercises exactly the access bwrap performs on
# the bind source at sandbox-construction time, from exactly the
# domain bwrap runs in.
#
# Gating is two-sided. Policy-store reads (semodule, sesearch) need
# sysadm_t and are reported as SKIP from a staff_t shell. The
# functional stat check needs staff_t (a sysadm_t read succeeds
# regardless of the topic-owned rule and proves nothing) and an
# existing /dev/kfd node; it is reported as SKIP otherwise. SKIP is
# accepted as a non-drift outcome.
#
# No live-process probes. Where any liveness inspection is required
# elsewhere, the canonical pattern is `[[ -d /proc/${pid} ]]` (never
# `kill -0`), because cross-user `kill -0` from a staff_t shell
# returns EPERM and would misreport a live process as dead.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for gated checks)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="flatpak_kfd_device"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_MODULE_INSTALLED="yes"
readonly EXPECTED_RULE_PRESENT="yes"
readonly KFD_NODE_PATH="/dev/kfd"
readonly -a CORE_PACKAGES=(
  "flatpak"
  "bubblewrap"
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

is_staff_t() {
  [[ "$(current_type)" == "staff_t" ]]
}

report_ok() {
  printf 'OK   %-48s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-48s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-48s %s\n' "$1" "$2"
  fail_state=1
}

verify_packages() {
  if ! command -v rpm >/dev/null 2>&1; then
    report_fail "pkg_check" "rpm not available"
    return
  fi
  local pkg
  for pkg in "${CORE_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      report_ok "pkg_${pkg}" "installed"
    else
      report_fail "pkg_${pkg}" "not installed"
    fi
  done
}

verify_module_installed() {
  if ! is_sysadm_t; then
    report_skip "module_installed" "needs sysadm_t"
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    report_fail "module_installed" "semodule not available"
    return
  fi
  local hits actual
  hits=$(semodule -lfull 2>/dev/null \
           | grep -cwE "^[ ]*${MODULE_PRIORITY}.*${MODULE_NAME}" \
           || true)
  if [[ "${hits}" == "1" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_MODULE_INSTALLED}" ]]; then
    report_ok "module_installed" \
      "expected=${EXPECTED_MODULE_INSTALLED} actual=${actual} (priority ${MODULE_PRIORITY})"
  else
    report_fail "module_installed" \
      "expected=${EXPECTED_MODULE_INSTALLED} actual=${actual}"
  fi
}

verify_rule() {
  if ! is_sysadm_t; then
    report_skip "rule_present" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "rule_present" "sesearch not available"
    return
  fi
  local out actual
  out=$(sesearch -A \
          -s staff_t \
          -t hsa_device_t \
          -c chr_file \
          -p getattr 2>/dev/null \
          || true)
  if [[ -n "${out}" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_RULE_PRESENT}" ]]; then
    report_ok "rule_present" \
      "expected=${EXPECTED_RULE_PRESENT} actual=${actual} (staff_t × hsa_device_t : chr_file getattr)"
  else
    report_fail "rule_present" \
      "expected=${EXPECTED_RULE_PRESENT} actual=${actual}"
  fi
}

verify_kfd_stat_from_staff_t() {
  if ! is_staff_t; then
    report_skip "kfd_stat_from_staff_t" \
      "needs staff_t (a $(current_type) read proves nothing)"
    return
  fi
  # The existence pre-test cannot use [[ -e ]]: the existence test is
  # itself a stat(2) and fails with EACCES on an unpatched host —
  # the very drift under verification. Discriminate on the stat error
  # message instead.
  local stat_out
  if stat_out=$(LC_ALL=C stat -c '%n' "${KFD_NODE_PATH}" 2>&1); then
    report_ok "kfd_stat_from_staff_t" \
      "stat ${KFD_NODE_PATH} succeeds (the bwrap bind-source access)"
  elif [[ "${stat_out}" == *"No such file"* ]]; then
    report_skip "kfd_stat_from_staff_t" \
      "${KFD_NODE_PATH} not present; gap unreachable on this host"
  else
    report_fail "kfd_stat_from_staff_t" \
      "stat ${KFD_NODE_PATH} fails from staff_t (functional rule absent or rolled back; dontaudit-suppressed, no AVC record)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool stat
  verify_packages
  verify_module_installed
  verify_rule
  verify_kfd_stat_from_staff_t
  exit "${fail_state}"
}

main "$@"
