#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_plymouth.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/plymouth.md. plymouth-start settles into
# `active (exited)` after the splash hand-off completes, so there is no
# MainPID to probe at verify time. Unit-state assertion (ActiveState,
# SubState, Result) replaces PID liveness; the live-domain read off
# /proc/<MainPID>/attr/current is not applicable to this unit.
#
# The AVC-clean check and the CIL module-presence check are gated behind
# a sysadm_t domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="plymouth-start.service"
readonly QUITWAIT_UNIT="plymouth-quit-wait.service"
readonly REQUIRED_PACKAGE="plymouth"
readonly EXPECTED_CIL_MODULE="nnp_plymouth"

readonly EXPECTED_TYPE="forking"
readonly EXPECTED_ACTIVE_STATE="active"
# plymouth-start's SubState depends on whether a display manager performs the
# splash hand-off. On a graphical desktop GDM tells plymouth to quit and the
# unit settles into active (exited); on a headless node plymouth-quit runs with
# --retain-splash and nothing takes over, so plymouthd lingers and the unit
# stays active (running). Both are healthy when ActiveState=active and
# Result=success; only failed/dead is drift. The check accepts either.
readonly -a EXPECTED_SUB_STATES=("exited" "running")
readonly EXPECTED_RESULT="success"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROTECT_SYSTEM="strict"
readonly EXPECTED_PROTECT_HOME="yes"
readonly EXPECTED_PROTECT_KERNEL_TUNABLES="yes"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_HOSTNAME="yes"
readonly EXPECTED_PRIVATE_TMP="yes"
readonly EXPECTED_LOCK_PERSONALITY="yes"
readonly EXPECTED_RESTRICT_REALTIME="yes"
readonly EXPECTED_RESTRICT_SUID_SGID="yes"
readonly EXPECTED_RESTRICT_NAMESPACES="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_PRIVATE_NETWORK="yes"
readonly EXPECTED_RESTRICT_ADDRESS_FAMILIES="AF_UNIX"
readonly EXPECTED_MDWE="yes"

readonly EXPECTED_QUITWAIT_ACTIVE_STATE="active"
readonly EXPECTED_QUITWAIT_SUB_STATE="exited"
readonly EXPECTED_QUITWAIT_RESULT="success"

readonly -a EXPECTED_READ_WRITE_PATHS_SUBSTRINGS=(
  "/run/plymouth"
  "/var/lib/plymouth"
  "/var/spool/plymouth"
)

readonly -a EXPECTED_SYSCALL_FILTER_BASELINE_ANCHORS=(
  "read"
  "write"
  "openat"
  "close"
  "mmap"
  "brk"
  "exit_group"
  "rt_sigaction"
)
readonly REQUIRED_BASELINE_ANCHOR_HITS=4

# The drop-in writes two SystemCallFilter= lines: the allowlist "@system-service"
# and one subtractive line "~@privileged @resources @debug @mount @cpu-emulation
# @obsolete @raw-io @reboot @swap @module @clock". The leading "~" governs the
# whole subtractive list, so only "@privileged" carries the "~" glyph in the
# merged unit; the remaining classes appear bare. The expected tokens mirror that
# exact spelling so the systemctl-cat grep matches what the drop-in actually ships.
readonly -a EXPECTED_SYSCALL_FILTER_CLASS_TOKENS=(
  "@system-service"
  "~@privileged"
  "@resources"
  "@debug"
  "@mount"
  "@cpu-emulation"
  "@obsolete"
  "@raw-io"
  "@reboot"
  "@swap"
  "@module"
  "@clock"
)

# systemctl show -p CapabilityBoundingSet --value renders cap names lower-case
# (cap_sys_admin), so the expected set is lower-case to match; the comparison in
# verify_cap_bounding_set is order-insensitive.
readonly -a EXPECTED_CAP_BOUNDING_SET=(
  "cap_sys_admin"
  "cap_sys_tty_config"
  "cap_chown"
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
  printf 'OK   %-40s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-40s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-40s %s\n' "$1" "$2"
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

verify_property() {
  local label="$1"
  local prop="$2"
  local expected="$3"
  local unit="${4:-${UNIT}}"
  local actual
  actual=$(systemctl show -p "${prop}" --value "${unit}" 2>/dev/null || true)
  if [[ "${actual}" == "${expected}" ]]; then
    report_ok "${label}" "${actual}"
  else
    report_fail "${label}" "expected='${expected}' actual='${actual}'"
  fi
}

verify_unit_state() {
  # plymouth-start is at-boot-only; unit-state assertion replaces PID liveness
  # because no MainPID is guaranteed at verify time. SubState is accepted as a
  # set (exited or running) to cover both the GUI hand-off and the headless
  # lingering case; see EXPECTED_SUB_STATES.
  verify_property "active_state" "ActiveState" "${EXPECTED_ACTIVE_STATE}"
  verify_sub_state
  verify_property "result"       "Result"      "${EXPECTED_RESULT}"
  verify_property "type"         "Type"        "${EXPECTED_TYPE}"
}

verify_sub_state() {
  local actual s
  actual=$(systemctl show -p SubState --value "${UNIT}" 2>/dev/null || true)
  for s in "${EXPECTED_SUB_STATES[@]}"; do
    if [[ "${actual}" == "${s}" ]]; then
      report_ok "sub_state" "${actual}"
      return
    fi
  done
  report_fail "sub_state" \
    "expected one of '${EXPECTED_SUB_STATES[*]}' actual='${actual}'"
}

verify_read_write_paths() {
  local actual
  actual=$(systemctl show -p ReadWritePaths --value "${UNIT}" 2>/dev/null \
           || true)
  local needle missing=0
  for needle in "${EXPECTED_READ_WRITE_PATHS_SUBSTRINGS[@]}"; do
    if [[ "${actual}" != *"${needle}"* ]]; then
      report_fail "rwpaths_${needle}" \
        "substring '${needle}' missing from ReadWritePaths='${actual}'"
      missing=1
    fi
  done
  if (( missing == 0 )); then
    report_ok "rwpaths_substrings" \
      "all three present in ReadWritePaths"
  fi
}

verify_restrict_address_families() {
  local actual normalised
  actual=$(systemctl show -p RestrictAddressFamilies --value "${UNIT}" \
           2>/dev/null || true)
  # Normalise whitespace; the property output may include leading or
  # trailing spaces depending on the systemd version.
  normalised=$(printf '%s' "${actual}" | awk '{$1=$1; print}')
  if [[ "${normalised}" == "${EXPECTED_RESTRICT_ADDRESS_FAMILIES}" ]]; then
    report_ok "restrict_address_families" "${normalised}"
  else
    report_fail "restrict_address_families" \
      "expected='${EXPECTED_RESTRICT_ADDRESS_FAMILIES}' actual='${normalised}'"
  fi
}

verify_syscall_filter_baseline_anchors() {
  local actual hits=0 needle
  actual=$(systemctl show -p SystemCallFilter --value "${UNIT}" \
           2>/dev/null || true)
  for needle in "${EXPECTED_SYSCALL_FILTER_BASELINE_ANCHORS[@]}"; do
    if [[ " ${actual} " == *" ${needle} "* ]]; then
      hits=$((hits + 1))
    fi
  done
  if (( hits >= REQUIRED_BASELINE_ANCHOR_HITS )); then
    report_ok "scf_baseline_anchors" \
      "${hits}/${#EXPECTED_SYSCALL_FILTER_BASELINE_ANCHORS[@]} anchors present (>= ${REQUIRED_BASELINE_ANCHOR_HITS})"
  else
    report_fail "scf_baseline_anchors" \
      "only ${hits}/${#EXPECTED_SYSCALL_FILTER_BASELINE_ANCHORS[@]} anchors present (need >= ${REQUIRED_BASELINE_ANCHOR_HITS})"
  fi
}

verify_syscall_filter_class_tokens() {
  local cat_out missing=0 token
  cat_out=$(systemctl cat "${UNIT}" 2>/dev/null || true)
  for token in "${EXPECTED_SYSCALL_FILTER_CLASS_TOKENS[@]}"; do
    if ! grep -qF -- "${token}" <<<"${cat_out}"; then
      report_fail "scf_class_token_${token}" \
        "class token '${token}' missing from merged unit"
      missing=1
    fi
  done
  if (( missing == 0 )); then
    report_ok "scf_class_tokens" \
      "all ${#EXPECTED_SYSCALL_FILTER_CLASS_TOKENS[@]} class tokens present"
  fi
}

verify_syscall_filter_syslog_allow() {
  # plymouthd calls klogctl (the syslog(2) syscall) on every splash show via
  # ply_show_new_kernel_messages. syslog is not in @system-service, so without
  # the positive SystemCallFilter=syslog re-add the default-deny allowlist
  # SIGSYS-kills plymouthd at boot (status=31/SYS, core-dump). Confirm the
  # effective merged filter actually permits it.
  local actual
  actual=$(systemctl show -p SystemCallFilter --value "${UNIT}" 2>/dev/null \
           || true)
  if [[ " ${actual} " == *" syslog "* ]]; then
    report_ok "scf_syslog_allow" "syslog permitted (no boot SIGSYS)"
  else
    report_fail "scf_syslog_allow" \
      "syslog missing from effective SystemCallFilter (plymouthd would SIGSYS at boot)"
  fi
}

verify_cap_bounding_set() {
  local actual normalised tokens cap missing=0 extra=0
  actual=$(systemctl show -p CapabilityBoundingSet --value "${UNIT}" \
           2>/dev/null || true)
  normalised=$(printf '%s' "${actual}" | awk '{$1=$1; print}')
  IFS=' ' read -r -a tokens <<<"${normalised}"
  for cap in "${EXPECTED_CAP_BOUNDING_SET[@]}"; do
    if [[ " ${normalised} " != *" ${cap} "* ]]; then
      report_fail "cap_${cap}" "missing from CapabilityBoundingSet='${normalised}'"
      missing=1
    fi
  done
  for cap in "${tokens[@]}"; do
    [[ -z "${cap}" ]] && continue
    if [[ " ${EXPECTED_CAP_BOUNDING_SET[*]} " != *" ${cap} "* ]]; then
      report_fail "cap_unexpected_${cap}" "unexpected cap in CapabilityBoundingSet='${normalised}'"
      extra=1
    fi
  done
  if (( missing == 0 && extra == 0 )); then
    report_ok "cap_bounding_set" "${normalised}"
  fi
}

verify_quitwait_anchor() {
  verify_property "quitwait_active_state" "ActiveState" \
    "${EXPECTED_QUITWAIT_ACTIVE_STATE}" "${QUITWAIT_UNIT}"
  verify_property "quitwait_sub_state"    "SubState"    \
    "${EXPECTED_QUITWAIT_SUB_STATE}" "${QUITWAIT_UNIT}"
  verify_property "quitwait_result"       "Result"      \
    "${EXPECTED_QUITWAIT_RESULT}" "${QUITWAIT_UNIT}"
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
           | grep -cE '(plymouthd_t|plymouthd_exec_t|nnp_transition|plymouth)' \
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
  verify_unit_state
  verify_property "nnp"                "NoNewPrivileges"           "${EXPECTED_NNP}"
  verify_property "protect_system"     "ProtectSystem"             "${EXPECTED_PROTECT_SYSTEM}"
  verify_property "protect_home"       "ProtectHome"               "${EXPECTED_PROTECT_HOME}"
  verify_property "protect_kt"         "ProtectKernelTunables"     "${EXPECTED_PROTECT_KERNEL_TUNABLES}"
  verify_property "protect_km"         "ProtectKernelModules"      "${EXPECTED_PROTECT_KERNEL_MODULES}"
  verify_property "protect_kl"         "ProtectKernelLogs"         "${EXPECTED_PROTECT_KERNEL_LOGS}"
  verify_property "protect_cg"         "ProtectControlGroups"      "${EXPECTED_PROTECT_CONTROL_GROUPS}"
  verify_property "protect_clock"      "ProtectClock"              "${EXPECTED_PROTECT_CLOCK}"
  verify_property "protect_hostname"   "ProtectHostname"           "${EXPECTED_PROTECT_HOSTNAME}"
  verify_property "private_tmp"        "PrivateTmp"                "${EXPECTED_PRIVATE_TMP}"
  verify_read_write_paths
  verify_property "lock_personality"   "LockPersonality"           "${EXPECTED_LOCK_PERSONALITY}"
  verify_property "restrict_realtime"  "RestrictRealtime"          "${EXPECTED_RESTRICT_REALTIME}"
  verify_property "restrict_suid_sgid" "RestrictSUIDSGID"          "${EXPECTED_RESTRICT_SUID_SGID}"
  verify_property "restrict_namespaces" "RestrictNamespaces"       "${EXPECTED_RESTRICT_NAMESPACES}"
  verify_property "syscall_arch"       "SystemCallArchitectures"   "${EXPECTED_SYSCALL_ARCH}"
  verify_property "private_network"    "PrivateNetwork"            "${EXPECTED_PRIVATE_NETWORK}"
  verify_restrict_address_families
  verify_property "mdwe"               "MemoryDenyWriteExecute"    "${EXPECTED_MDWE}"
  verify_syscall_filter_baseline_anchors
  verify_syscall_filter_class_tokens
  verify_syscall_filter_syslog_allow
  verify_cap_bounding_set
  verify_quitwait_anchor
  verify_cil_module
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
