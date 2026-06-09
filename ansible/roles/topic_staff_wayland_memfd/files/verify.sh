#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_staff_wayland_memfd.
#
# Compares observed runtime state against the expected end-state
# declared in docs/reference/topics/staff-wayland-memfd.md. The
# end-state is the priority-400 module staff_wayland_memfd loaded with
# both permissions of the functional vector present in the loaded
# policy:
#   - staff_t × tmpfs_t : file write
#   - staff_t × tmpfs_t : file map  (unconditional, not the stock
#                                    domain_can_mmap_files boolean line)
# plus a clean AVC stream for the functional class since boot.
#
# Both permissions are asserted independently: the access vector
# requires both, and a partial grant (write without map, or the
# reverse) is itself a drift signal.
#
# Stages that need policy-store reads (semodule, sesearch, ausearch) are
# gated behind a sysadm_t domain check and reported as SKIP from a
# staff_t shell. SKIP is accepted as a non-drift outcome.
#
# No live-process probes. SELinux access checks evaluate the loaded
# policy on each system call; the verify does not need to inspect a live
# compositor. Where any liveness inspection is required elsewhere, the
# canonical pattern is `[[ -d /proc/${pid} ]]` (never `kill -0`),
# because cross-user `kill -0` from a staff_t shell returns EPERM and
# would misreport a live process as dead.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for sysadm_t-gated checks)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="staff_wayland_memfd"
readonly MODULE_PRIORITY="400"
readonly MMAP_BOOLEAN="domain_can_mmap_files"
readonly EXPECTED_MODULE_INSTALLED="yes"
readonly EXPECTED_RULE_WRITE_PRESENT="yes"
readonly EXPECTED_RULE_MAP_PRESENT="yes"
readonly EXPECTED_AVC_CLASS_SINCE_BOOT="0"
readonly -a CORE_PACKAGES=(
  "gnome-shell"
  "mutter"
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
  printf 'OK   %-44s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-44s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-44s %s\n' "$1" "$2"
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

verify_rule_write() {
  if ! is_sysadm_t; then
    report_skip "rule_write_present" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "rule_write_present" "sesearch not available"
    return
  fi
  local out actual
  out=$(sesearch -A -s staff_t -t tmpfs_t -c file -p write 2>/dev/null || true)
  if [[ -n "${out}" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_RULE_WRITE_PRESENT}" ]]; then
    report_ok "rule_write_present" \
      "expected=${EXPECTED_RULE_WRITE_PRESENT} actual=${actual} (staff_t × tmpfs_t : file write)"
  else
    report_fail "rule_write_present" \
      "expected=${EXPECTED_RULE_WRITE_PRESENT} actual=${actual}"
  fi
}

verify_rule_map() {
  if ! is_sysadm_t; then
    report_skip "rule_map_present" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "rule_map_present" "sesearch not available"
    return
  fi
  local merged unconditional actual
  merged=$(sesearch -A -s staff_t -t tmpfs_t -c file -p map 2>/dev/null || true)
  unconditional=$(printf '%s\n' "${merged}" | grep -v "${MMAP_BOOLEAN}" || true)
  if [[ -n "${unconditional}" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_RULE_MAP_PRESENT}" ]]; then
    report_ok "rule_map_present" \
      "expected=${EXPECTED_RULE_MAP_PRESENT} actual=${actual} (staff_t × tmpfs_t : file map, unconditional)"
  else
    report_fail "rule_map_present" \
      "expected=${EXPECTED_RULE_MAP_PRESENT} actual=${actual} (only the stock ${MMAP_BOOLEAN} line present?)"
  fi
}

verify_avc_class_clean() {
  if ! is_sysadm_t; then
    report_skip "avc_class_since_boot" "needs sysadm_t"
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    report_fail "avc_class_since_boot" "ausearch not available"
    return
  fi
  local hits
  hits=$(ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
           | grep -cE 'staff_t.*tmpfs_t.*file' \
           || true)
  if [[ "${hits}" == "${EXPECTED_AVC_CLASS_SINCE_BOOT}" ]]; then
    report_ok "avc_class_since_boot" \
      "expected=${EXPECTED_AVC_CLASS_SINCE_BOOT} actual=${hits}"
  else
    report_fail "avc_class_since_boot" \
      "expected=${EXPECTED_AVC_CLASS_SINCE_BOOT} actual=${hits} (functional rule rolled back or pre-empted)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  verify_packages
  verify_module_installed
  verify_rule_write
  verify_rule_map
  verify_avc_class_clean
  exit "${fail_state}"
}

main "$@"
