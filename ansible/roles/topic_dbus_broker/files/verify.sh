#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_dbus_broker.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/dbus-broker.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against a foreign-uid PID. The AVC-clean check and
# the CIL-module-presence check are gated behind a sysadm_t domain check
# and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="dbus-broker.service"
readonly EXPECTED_DOMAIN="system_dbusd_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_MDWE="yes"
readonly REQUIRED_PACKAGE="dbus-broker"
readonly EXPECTED_CIL_MODULE="nnp_dbus_broker"
readonly WELL_KNOWN_BUS_NAME="org.freedesktop.DBus"

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/dbus-broker.service.d"
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

verify_busctl_list() {
  if ! command -v busctl >/dev/null 2>&1; then
    report_fail "busctl_system_list" "busctl not available"
    return
  fi
  local out rc=0
  if ! out=$(busctl --system list 2>/dev/null); then
    rc=$?
    report_fail "busctl_system_list" "busctl exit=${rc}"
    return
  fi
  if printf '%s\n' "${out}" | grep -qFw "${WELL_KNOWN_BUS_NAME}"; then
    report_ok "busctl_system_list" "contains ${WELL_KNOWN_BUS_NAME}"
  else
    report_fail "busctl_system_list" \
      "missing ${WELL_KNOWN_BUS_NAME} in bus-name list"
  fi
}

verify_dbus_send_roundtrip() {
  if ! command -v dbus-send >/dev/null 2>&1; then
    # dbus-send ships in the optional dbus-tools package, absent on a
    # headless base. The busctl round-trip above already proves the system
    # bus answers method calls, so this is a redundant tool gap, not drift.
    report_skip "dbus_send_roundtrip" "dbus-send not available (busctl covers the round-trip)"
    return
  fi
  local out rc=0
  if ! out=$(dbus-send --system --print-reply \
              --dest=org.freedesktop.DBus \
              /org/freedesktop/DBus \
              org.freedesktop.DBus.ListNames 2>/dev/null); then
    rc=$?
    report_fail "dbus_send_roundtrip" "dbus-send exit=${rc}"
    return
  fi
  if printf '%s\n' "${out}" | grep -q '^method return'; then
    if printf '%s\n' "${out}" | grep -q 'array \[' \
       && printf '%s\n' "${out}" | grep -q 'string "'; then
      report_ok "dbus_send_roundtrip" "method return with non-empty array"
    else
      report_fail "dbus_send_roundtrip" \
        "method return present but array of string is empty"
    fi
  else
    report_fail "dbus_send_roundtrip" "no method return in reply"
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
           | grep -cE '(system_dbusd_t|nnp_transition|dbus_broker|dbusd_exec_t)' \
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
    *"symbolic link"*) mode="lnk_file" ;;
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
  verify_selinux_domain
  verify_busctl_list
  verify_dbus_send_roundtrip
  verify_cil_module
  verify_avc_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
