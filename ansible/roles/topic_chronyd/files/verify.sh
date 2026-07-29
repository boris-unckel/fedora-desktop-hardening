#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_chronyd.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/chronyd.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against the daemon-uid-owned long-running process.
# The AVC-clean check and the CIL-module-presence check are gated behind
# a sysadm_t domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="chronyd.service"
readonly EXPECTED_DOMAIN="chronyd_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROCSUBSET="pid"
readonly EXPECTED_UMASK_OCTAL="0027"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly REQUIRED_PACKAGE="chrony"
readonly EXPECTED_CIL_MODULE="nnp_chronyd"
# Only CAP_NET_ADMIN is forbidden. The live test showed chronyd fails to start
# without CAP_NET_BIND_SERVICE / CAP_NET_BROADCAST / CAP_NET_RAW, so those are
# legitimately retained in the bounding set and are not asserted absent.
readonly -a EXPECTED_FORBIDDEN_CAPS=(
  cap_net_admin
)

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/chronyd.service.d"
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

normalise_umask() {
  # systemctl show -p UMask --value returns the umask as a decimal
  # integer (23 for octal 0027). Convert any decimal-or-octal input to
  # the canonical 4-digit octal form used by EXPECTED_UMASK_OCTAL.
  local raw="$1"
  if [[ -z "${raw}" ]]; then
    printf ''
    return
  fi
  if [[ "${raw}" =~ ^0[0-7]+$ ]]; then
    printf '%04o\n' "$((8#${raw#0}))"
    return
  fi
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    printf '%04o\n' "${raw}"
    return
  fi
  printf '%s\n' "${raw}"
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

verify_umask() {
  local raw normalised
  raw=$(systemctl show -p UMask --value "${UNIT}" 2>/dev/null || true)
  normalised=$(normalise_umask "${raw}")
  if [[ "${normalised}" == "${EXPECTED_UMASK_OCTAL}" ]]; then
    report_ok "UMask" "${normalised} (raw=${raw})"
  else
    report_fail "UMask" \
      "expected=${EXPECTED_UMASK_OCTAL} actual=${normalised} (raw=${raw})"
  fi
}

verify_capability_absence() {
  local raw cap hits
  raw=$(systemctl show -p CapabilityBoundingSet --value "${UNIT}" 2>/dev/null \
          || true)
  if [[ -z "${raw}" ]]; then
    report_fail "cap_bounding_set" "empty (no resolved bounding set read)"
    return
  fi
  for cap in "${EXPECTED_FORBIDDEN_CAPS[@]}"; do
    hits=$(printf '%s\n' "${raw}" | tr -s '[:space:]' '\n' \
             | grep -cwx "${cap}" || true)
    if [[ "${hits}" == "0" ]]; then
      report_ok "cap_absent_${cap}" "absent"
    else
      report_fail "cap_absent_${cap}" "still present in bounding set"
    fi
  done
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

verify_port_bind_absence() {
  if ! command -v ss >/dev/null 2>&1; then
    report_fail "port_123_absence" "ss not available"
    return
  fi
  local hits
  hits=$(ss -lnu 2>/dev/null | grep ':123' || true)
  if [[ -z "${hits}" ]]; then
    report_ok "port_123_absence" "no port-123 bind"
  else
    report_fail "port_123_absence" "port-123 bind present"
  fi
}

verify_chronyc_tracking() {
  if ! command -v chronyc >/dev/null 2>&1; then
    report_fail "chronyc_tracking" "chronyc not available"
    return
  fi
  local out rc=0
  if ! out=$(chronyc tracking 2>/dev/null); then
    rc=$?
    report_fail "chronyc_tracking" "chronyc tracking exit=${rc}"
    return
  fi
  if printf '%s\n' "${out}" | grep -qE '^Reference ID[[:space:]]*:.+[^[:space:]]'; then
    report_ok "chronyc_tracking" "Reference ID present"
  else
    report_fail "chronyc_tracking" "Reference ID line missing or empty"
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
           | grep -cE '(chronyd_t|nnp_transition|chronyd)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
  fi
}

# Expected context for one path, honouring the file-type qualifier carried by
# file_contexts entries. A `--` entry matches regular files only, so a
# directory or a symlink at the same path resolves through a different rule;
# without the mode hint the comparison tests against the wrong expectation.
#
# The type comes from `stat`, not from `[[ -d ]]`/`[[ -L ]]`: those operators
# report false when the path cannot be stat'ed, which would silently fall
# through to the regular-file rule and produce a plausible wrong answer.
# LC_ALL=C because `%F` is localised.
expected_context() {
  local path="$1" mode ftype
  ftype=$(LC_ALL=C stat -c '%F' "${path}" 2>/dev/null) || return 1
  case "${ftype}" in
    *"symbolic link"*) mode="link" ;;
    "directory") mode="dir" ;;
    *) mode="file" ;;
  esac
  matchpathcon -m "${mode}" "${path}" 2>/dev/null | sed 's#.*\t##'
}

# Compares the full context, including the SELinux user field. `restorecon -n`
# compares the type alone, so a path differing only in the user field stays
# invisible to it and to any check built on it.
context_matches() {
  local path="$1" expected actual
  actual=$(stat -c '%C' "${path}" 2>/dev/null || true)
  expected=$(expected_context "${path}") || expected=""
  if [[ -z "${expected}" || -z "${actual}" ]]; then
    report_fail "selinux_context" "${path}: context not resolvable"
    return 1
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    report_fail "selinux_context" \
      "${path}: expected=${expected} actual=${actual}"
    return 1
  fi
  return 0
}

verify_selinux_context() {
  local path child drift=0 checked=0
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_skip "selinux_context" "matchpathcon not available"
    return
  fi
  for path in "${CONTEXT_PATHS[@]}"; do
    if [[ ! -e "${path}" ]]; then
      report_fail "selinux_context" "${path}: absent"
      drift=$((drift + 1))
      continue
    fi
    checked=$((checked + 1))
    context_matches "${path}" || drift=$((drift + 1))
    [[ -d "${path}" ]] || continue
    for child in "${path}"/*; do
      [[ -e "${child}" ]] || continue
      checked=$((checked + 1))
      context_matches "${child}" || drift=$((drift + 1))
    done
  done
  if [[ "${drift}" -eq 0 ]]; then
    report_ok "selinux_context" "${checked} paths match file_contexts"
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
  verify_capability_absence
  verify_property "ProcSubset" "ProcSubset" "${EXPECTED_PROCSUBSET}"
  verify_umask
  verify_property "SystemCallArchitectures" "SystemCallArchitectures" \
    "${EXPECTED_SYSCALL_ARCH}"
  verify_selinux_domain
  verify_port_bind_absence
  verify_chronyc_tracking
  verify_cil_module
  verify_avc_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
