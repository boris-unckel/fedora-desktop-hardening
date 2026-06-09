#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_network_manager.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/network-manager.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against the root-owned daemon. The AVC-clean check
# and the CIL-module-presence check are gated behind a sysadm_t domain
# check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="NetworkManager.service"
readonly EXPECTED_DOMAIN="NetworkManager_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROTECT_SYSTEM="strict"
readonly EXPECTED_RESTRICT_NS="yes"
readonly EXPECTED_LOCK_PERSONALITY="yes"
# RestrictAddressFamilies. systemctl show --value returns the families in
# source order; both observed and expected are normalised to alphabetical
# lower-case-equivalent form before comparison so that a stylistic re-
# ordering in the drop-in does not false-flag as drift.
readonly EXPECTED_RAF="AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX"
readonly EXPECTED_NMCLI_STATE="connected"
readonly REQUIRED_PACKAGE="NetworkManager"
readonly EXPECTED_CIL_MODULE="nnp_network_manager"

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

normalise_families() {
  # Emit a single-line, alphabetically sorted, single-space-separated form
  # of a whitespace-separated address-family list.
  printf '%s\n' "$1" | tr -s '[:space:]' '\n' | sed '/^$/d' | sort | paste -sd ' '
}

report_ok() {
  printf 'OK   %-30s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-30s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-30s %s\n' "$1" "$2"
  fail_state=1
}

verify_package() {
  if ! command -v rpm >/dev/null 2>&1; then
    report_fail "pkg_check" "rpm not available"
    return
  fi
  if rpm -q "${REQUIRED_PACKAGE}" >/dev/null 2>&1; then
    report_ok "pkg_${REQUIRED_PACKAGE}" "installed"
  else
    report_fail "pkg_${REQUIRED_PACKAGE}" "not installed"
  fi
}

verify_unit_active() {
  local actual
  actual=$(systemctl is-active "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "active" ]]; then
    report_ok "unit_${UNIT%.service}" "${actual}"
  else
    report_fail "unit_${UNIT%.service}" \
      "expected=active actual=${actual:-<empty>}"
  fi
}

verify_liveness() {
  # /proc, not `kill -0`: kill -0 from a non-privileged context against a
  # foreign uid returns EPERM, not ESRCH, and would falsely report a live
  # daemon as dead.
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_fail "liveness" "pid=${pid} not present"
    return
  fi
  report_ok "liveness" "pid=${pid}"
}

verify_property() {
  local label="$1"
  local prop="$2"
  local expected="$3"
  local actual
  actual=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "${expected}" ]]; then
    report_ok "${label}" "${actual}"
  else
    report_fail "${label}" "expected='${expected}' actual='${actual}'"
  fi
}

verify_address_families() {
  local actual_raw observed expected
  actual_raw=$(systemctl show -p RestrictAddressFamilies --value "${UNIT}" \
                 2>/dev/null || true)
  observed=$(normalise_families "${actual_raw}")
  expected=$(normalise_families "${EXPECTED_RAF}")
  if [[ "${observed}" == "${expected}" ]]; then
    report_ok "RestrictAddressFamilies" "${observed}"
  else
    report_fail "RestrictAddressFamilies" \
      "expected='${expected}' actual='${observed}'"
  fi
}

verify_selinux_domain() {
  local pid domain
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "selinux_domain" "no MainPID"
    return
  fi
  domain=$(awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null \
           || echo "?")
  if [[ "${domain}" == "${EXPECTED_DOMAIN}" ]]; then
    report_ok "selinux_domain" "${domain}"
  else
    report_fail "selinux_domain" \
      "expected=${EXPECTED_DOMAIN} actual=${domain}"
  fi
}

verify_connectivity() {
  if ! command -v nmcli >/dev/null 2>&1; then
    report_fail "nmcli_state" "nmcli not available"
    return
  fi
  # NetworkManager re-evaluates global connectivity asynchronously. When an
  # earlier step in a cumulative apply restarts the system bus, NM briefly drops
  # to "disconnected" until it reconnects, so poll for it to settle. Accept any
  # "connected" gradation: an IPv6-only cloud node legitimately reports
  # "connected (site only)" or "connected (limited)" because the IPv4
  # connectivity-check endpoint is unreachable, which is environment, not drift.
  local actual _
  for _ in 1 2 3 4 5 6; do
    actual=$(nmcli -t -f STATE general 2>/dev/null || true)
    [[ "${actual}" == connected* ]] && break
    sleep 5
  done
  if [[ "${actual}" == connected* ]]; then
    report_ok "nmcli_state" "${actual}"
  else
    report_fail "nmcli_state" \
      "expected=${EXPECTED_NMCLI_STATE}* actual=${actual:-<empty>}"
  fi
}

verify_cil_module() {
  if ! is_sysadm_t; then
    report_skip "cil_${EXPECTED_CIL_MODULE}" "needs sysadm_t"
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    report_fail "cil_${EXPECTED_CIL_MODULE}" "semodule not available"
    return
  fi
  local hits
  hits=$(semodule -l 2>/dev/null | grep -cw "${EXPECTED_CIL_MODULE}" || true)
  if [[ "${hits}" == "1" ]]; then
    report_ok "cil_${EXPECTED_CIL_MODULE}" "loaded"
  else
    report_fail "cil_${EXPECTED_CIL_MODULE}" \
      "expected=1 line actual=${hits}"
  fi
}

verify_avc_clean() {
  if ! is_sysadm_t; then
    report_skip "avc_clean" "needs sysadm_t"
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    report_fail "avc_clean" "ausearch not available"
    return
  fi
  local hits
  hits=$(ausearch -m AVC -ts boot 2>/dev/null \
           | grep -cE '(NetworkManager_t|nnp_transition|NetworkManager)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool systemctl
  verify_package
  verify_unit_active
  verify_liveness
  verify_property "NoNewPrivileges" "NoNewPrivileges" "${EXPECTED_NNP}"
  verify_property "ProtectSystem" "ProtectSystem" "${EXPECTED_PROTECT_SYSTEM}"
  verify_address_families
  verify_property "RestrictNamespaces" "RestrictNamespaces" \
    "${EXPECTED_RESTRICT_NS}"
  verify_property "LockPersonality" "LockPersonality" \
    "${EXPECTED_LOCK_PERSONALITY}"
  verify_selinux_domain
  verify_connectivity
  verify_cil_module
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
