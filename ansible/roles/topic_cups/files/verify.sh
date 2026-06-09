#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_cups.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/cups.md. Liveness uses /proc, never `kill -0`,
# so the script reports correctly when run from a non-privileged context
# against a foreign-uid PID. The AVC-clean check, the CIL module-presence
# check, and the four positive-rule presence checks against the loaded
# SELinux policy are gated behind a sysadm_t domain check and reported
# as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="cups.service"
readonly EXPECTED_DOMAIN="cupsd_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_RESTRICT_NAMESPACES="yes"
readonly REQUIRED_PACKAGE="cups"
readonly EXPECTED_CIL_MODULE="nnp_cups"
readonly -a EXPECTED_LISTEN_SUBSTRINGS=(
  "127.0.0.1:631"
  "[::1]:631"
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

cups_socket_active() {
  # cups is socket-activated on Fedora 44: cups.socket holds the localhost:631
  # listener and cupsd starts on demand, then idles back out. An inactive
  # cups.service with an active cups.socket is the steady-state, not a fault;
  # this is also the post-reboot state in the system tier.
  [[ "$(systemctl is-active cups.socket 2>/dev/null || true)" == "active" ]]
}

report_ok() {
  printf 'OK   %-32s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-32s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-32s %s\n' "$1" "$2"
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
  elif cups_socket_active; then
    report_ok "unit_${UNIT%.service}" \
      "${actual:-inactive} (socket-activated; cups.socket active, cupsd starts on demand)"
  else
    report_fail "unit_${UNIT%.service}" \
      "expected=active actual=${actual:-<empty>} and cups.socket not active"
  fi
}

verify_liveness() {
  # /proc, not `kill -0`: kill -0 from a non-privileged context against a
  # foreign uid returns EPERM, not ESRCH, and would falsely report a live
  # daemon as dead.
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    if cups_socket_active; then
      report_skip "liveness" \
        "socket-activated; cupsd idle (no MainPID until first request)"
      return
    fi
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

verify_listen_sockets() {
  if ! command -v ss >/dev/null 2>&1; then
    report_fail "listen_631" "ss not available"
    return
  fi
  local out
  out=$(ss -ltn 'sport = 631' 2>/dev/null || true)
  local needle hit=0
  for needle in "${EXPECTED_LISTEN_SUBSTRINGS[@]}"; do
    if [[ "${out}" == *"${needle}"* ]]; then
      hit=1
      report_ok "listen_631" "matched '${needle}'"
      break
    fi
  done
  if (( hit == 0 )); then
    report_fail "listen_631" \
      "neither '127.0.0.1:631' nor '[::1]:631' in ss output"
  fi
}

verify_lpstat() {
  if ! command -v lpstat >/dev/null 2>&1; then
    report_fail "lpstat" "lpstat not available"
    return
  fi
  local out rc=0
  out=$(lpstat -p -d 2>&1) || rc=$?
  if (( rc == 0 )); then
    report_ok "lpstat" "rc=0"
  elif printf '%s' "${out}" | grep -qi 'No destinations added'; then
    # A headless host with no configured printers: lpstat exits non-zero with
    # "No destinations added". The call still reaches cupsd (socket activation
    # answered); the empty-printer state is expected, not drift.
    report_ok "lpstat" "no printers configured (No destinations added)"
  else
    report_fail "lpstat" "lpstat -p -d rc=${rc} out='${out}'"
  fi
}

verify_lpinfo_backends() {
  if ! command -v lpinfo >/dev/null 2>&1; then
    report_fail "lpinfo_backends" "lpinfo not available"
    return
  fi
  local out rc=0
  if ! out=$(lpinfo -v 2>/dev/null); then
    rc=$?
    report_fail "lpinfo_backends" "lpinfo -v rc=${rc}"
    return
  fi
  if [[ -n "${out}" ]]; then
    report_ok "lpinfo_backends" "non-empty backend list"
  else
    report_fail "lpinfo_backends" \
      "empty backend list (sandbox-broken backend lookup suspected)"
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

verify_cil_rule() {
  local label="$1"
  local source_domain="$2"
  local target_domain="$3"
  if ! is_sysadm_t; then
    report_skip "${label}" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "${label}" "sesearch not available"
    return
  fi
  local out
  out=$(sesearch -A -s "${source_domain}" -t "${target_domain}" \
          -c process2 -p nnp_transition 2>/dev/null || true)
  if [[ -n "${out}" ]]; then
    report_ok "${label}" "${source_domain} -> ${target_domain}"
  else
    report_fail "${label}" \
      "no process2 nnp_transition rule for ${source_domain} -> ${target_domain}"
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
           | grep -cE '(cupsd_t|cupsd_exec_t|cupsd_lpd_t|cupsd_config_t|cups_pdf_t|nnp_transition|cups)' \
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
  verify_property "ProtectClock" "ProtectClock" "${EXPECTED_PROTECT_CLOCK}"
  verify_property "ProtectKernelLogs" "ProtectKernelLogs" \
    "${EXPECTED_PROTECT_KERNEL_LOGS}"
  verify_property "ProtectKernelModules" "ProtectKernelModules" \
    "${EXPECTED_PROTECT_KERNEL_MODULES}"
  verify_property "ProtectControlGroups" "ProtectControlGroups" \
    "${EXPECTED_PROTECT_CONTROL_GROUPS}"
  verify_property "SystemCallArchitectures" "SystemCallArchitectures" \
    "${EXPECTED_SYSCALL_ARCH}"
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_property "RestrictNamespaces" "RestrictNamespaces" \
    "${EXPECTED_RESTRICT_NAMESPACES}"
  verify_selinux_domain
  verify_listen_sockets
  verify_lpstat
  verify_lpinfo_backends
  verify_cil_module
  verify_cil_rule "cil_rule_1" "init_t" "cupsd_t"
  verify_cil_rule "cil_rule_2" "cupsd_t" "cupsd_lpd_t"
  verify_cil_rule "cil_rule_3" "cupsd_t" "cupsd_config_t"
  verify_cil_rule "cil_rule_4" "cupsd_t" "cups_pdf_t"
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
