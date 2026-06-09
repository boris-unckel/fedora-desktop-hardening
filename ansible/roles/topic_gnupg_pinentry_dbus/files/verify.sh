#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_gnupg_pinentry_dbus.
#
# Compares observed runtime state against the expected end-state
# declared in docs/reference/topics/gnupg-pinentry-dbus.md. The
# end-state is the priority-400 module gnupg_pinentry_dbus loaded with
# both allow surfaces present in the loaded policy:
#   - functional:      gpg_pinentry_t × session_dbusd_tmp_t : sock_file write
#   - audit-cosmetic:  gpg_t × gpg_agent_t : process { noatsecure rlimitinh siginh }
# plus a clean AVC stream for the functional class since boot.
#
# Stages that need policy-store reads (semodule, sesearch, ausearch)
# are gated behind a sysadm_t domain check and reported as SKIP from a
# staff_t shell. SKIP is accepted as a non-drift outcome.
#
# No live-process probes. SELinux access checks evaluate the loaded
# policy on each system call; the verify does not need to inspect a
# live gpg-agent. Where any liveness inspection is required elsewhere,
# the canonical pattern is `[[ -d /proc/${pid} ]]` (never `kill -0`),
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

readonly MODULE_NAME="gnupg_pinentry_dbus"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_MODULE_INSTALLED="yes"
readonly EXPECTED_RULE_A_PRESENT="yes"
readonly EXPECTED_RULE_B_NOATSECURE_PRESENT="yes"
readonly EXPECTED_RULE_B_RLIMITINH_PRESENT="yes"
readonly EXPECTED_RULE_B_SIGINH_PRESENT="yes"
readonly EXPECTED_AVC_CLASS_A_SINCE_BOOT="0"
readonly -a CORE_PACKAGES=(
  "gnupg2"
  "pinentry"
  "pinentry-gnome3"
  "gcr3"
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

verify_rule_a() {
  if ! is_sysadm_t; then
    report_skip "rule_a_present" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "rule_a_present" "sesearch not available"
    return
  fi
  local out actual
  out=$(sesearch -A \
          -s gpg_pinentry_t \
          -t session_dbusd_tmp_t \
          -c sock_file \
          -p write 2>/dev/null \
          || true)
  if [[ -n "${out}" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_RULE_A_PRESENT}" ]]; then
    report_ok "rule_a_present" \
      "expected=${EXPECTED_RULE_A_PRESENT} actual=${actual} (gpg_pinentry_t × session_dbusd_tmp_t : sock_file write)"
  else
    report_fail "rule_a_present" \
      "expected=${EXPECTED_RULE_A_PRESENT} actual=${actual}"
  fi
}

verify_rule_b_perm() {
  local label="$1"
  local perm="$2"
  local expected="$3"
  if ! is_sysadm_t; then
    report_skip "${label}" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "${label}" "sesearch not available"
    return
  fi
  local out actual
  out=$(sesearch -A \
          -s gpg_t \
          -t gpg_agent_t \
          -c process \
          -p "${perm}" 2>/dev/null \
          || true)
  if [[ -n "${out}" ]]; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${expected}" ]]; then
    report_ok "${label}" \
      "expected=${expected} actual=${actual} (gpg_t × gpg_agent_t : process ${perm})"
  else
    report_fail "${label}" \
      "expected=${expected} actual=${actual}"
  fi
}

verify_avc_class_a_clean() {
  if ! is_sysadm_t; then
    report_skip "avc_class_a_since_boot" "needs sysadm_t"
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    report_fail "avc_class_a_since_boot" "ausearch not available"
    return
  fi
  local hits
  hits=$(ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
           | grep -cE 'gpg_pinentry_t.*session_dbusd_tmp_t' \
           || true)
  if [[ "${hits}" == "${EXPECTED_AVC_CLASS_A_SINCE_BOOT}" ]]; then
    report_ok "avc_class_a_since_boot" \
      "expected=${EXPECTED_AVC_CLASS_A_SINCE_BOOT} actual=${hits}"
  else
    report_fail "avc_class_a_since_boot" \
      "expected=${EXPECTED_AVC_CLASS_A_SINCE_BOOT} actual=${hits} (functional rule rolled back or pre-empted)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  verify_packages
  verify_module_installed
  verify_rule_a
  verify_rule_b_perm "rule_b_noatsecure_present" "noatsecure" \
    "${EXPECTED_RULE_B_NOATSECURE_PRESENT}"
  verify_rule_b_perm "rule_b_rlimitinh_present" "rlimitinh" \
    "${EXPECTED_RULE_B_RLIMITINH_PRESENT}"
  verify_rule_b_perm "rule_b_siginh_present" "siginh" \
    "${EXPECTED_RULE_B_SIGINH_PRESENT}"
  verify_avc_class_a_clean
  exit "${fail_state}"
}

main "$@"
