#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_smartd.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/smartd.md. Liveness uses /proc, never
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

readonly UNIT="smartd.service"
readonly EXPECTED_DOMAIN="fsdaemon_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
# CapabilityBoundingSet from `systemctl show --value` is rendered lower-case
# in kernel cap-bit order (cap_sys_rawio before cap_sys_admin), which need not
# match the source order; verify_capability_bounding_set compares it as a
# case-insensitive set, so the expected order here is immaterial.
readonly EXPECTED_CAPS="cap_sys_admin cap_sys_rawio"
# RestrictAddressFamilies is a single value on this unit; no source-order
# question arises.
readonly EXPECTED_RAF="AF_UNIX"
readonly EXPECTED_SCF_MIN_BYTES=200
# SystemCallFilter anchors deliberately omit `mount` and `umount2`: this
# unit's filter strips @mount in the subtractive line, and an anchor that
# asserts mount presence would false-flag a correctly hardened smartd.
readonly -a EXPECTED_SCF_ANCHORS=(
  "read"
  "write"
  "openat"
  "close"
  "ioctl"
  "fstat"
)
readonly REQUIRED_PACKAGE="smartmontools"
readonly EXPECTED_CIL_MODULE="nnp_smartd"

# Executable label. The type transition into the confined domain fires on this
# label; if it is wrong the unit still starts and still carries every drop-in
# directive, it simply runs unconfined. Nothing in the unit's behaviour shows
# it, which is why the assertion is explicit.
readonly BINARY_PATH="/usr/bin/smartd"
readonly EXPECTED_EXEC_TYPE="fsdaemon_exec_t"

# The compatibility symlink is expected to keep the generic type: `--` entries
# in file_contexts match regular files only. Asserted so that an over-broad
# local mapping — one added without a file-type qualifier — is caught here
# rather than becoming a permanent context-drift report elsewhere.
readonly BINARY_SYMLINK="/usr/sbin/smartd"
readonly EXPECTED_SYMLINK_TYPE="bin_t"

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/smartd.service.d"
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

condition_unmet() {
  # ConditionResult=no means the stock unit's Condition* gates (smartd.service
  # ships ConditionVirtualization=no) were not met, so systemd never started
  # the daemon. On a virtual machine smartd is legitimately not running; the
  # hardening directives are still merged into the loaded unit and remain
  # verifiable through `systemctl show`.
  local cr
  cr=$(systemctl show -p ConditionResult --value "${UNIT}" 2>/dev/null || true)
  [[ "${cr}" == "no" ]]
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
  elif condition_unmet; then
    report_ok "unit_${UNIT%.service}" \
      "${actual:-inactive} (ConditionVirtualization=no — not started on virtual hardware)"
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
    if condition_unmet; then
      report_skip "liveness" \
        "ConditionVirtualization=no — no MainPID on virtual hardware"
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

verify_capability_bounding_set() {
  # systemctl renders the bounding set lower-case in kernel cap-bit order,
  # which need not match the source order; compare as a case-insensitive set.
  local raw observed expected
  raw=$(systemctl show -p CapabilityBoundingSet --value "${UNIT}" 2>/dev/null \
          || true)
  if [[ -z "${raw}" ]]; then
    report_fail "CapabilityBoundingSet" "empty (no resolved bounding set read)"
    return
  fi
  observed=$(printf '%s\n' "${raw}" \
               | tr '[:upper:]' '[:lower:]' \
               | tr -s '[:space:]' '\n' \
               | grep -v '^$' \
               | sort \
               | tr '\n' ' ' \
               | sed 's/ *$//')
  expected=$(printf '%s\n' "${EXPECTED_CAPS}" \
               | tr '[:upper:]' '[:lower:]' \
               | tr -s '[:space:]' '\n' \
               | grep -v '^$' \
               | sort \
               | tr '\n' ' ' \
               | sed 's/ *$//')
  if [[ "${observed}" == "${expected}" ]]; then
    report_ok "CapabilityBoundingSet" "${raw}"
  else
    report_fail "CapabilityBoundingSet" \
      "expected set='${EXPECTED_CAPS}' actual='${raw}'"
  fi
}

verify_systemcallfilter() {
  # SystemCallFilter --value returns the expanded syscall list, not the
  # @class names. Length plus anchor presence is the robust shape.
  local actual length anchor
  local -a missing=()
  actual=$(systemctl show -p SystemCallFilter --value "${UNIT}" 2>/dev/null \
           || true)
  length=${#actual}
  for anchor in "${EXPECTED_SCF_ANCHORS[@]}"; do
    if ! grep -qw "${anchor}" <<<"${actual}"; then
      missing+=("${anchor}")
    fi
  done
  if (( length < EXPECTED_SCF_MIN_BYTES )); then
    report_fail "SystemCallFilter" \
      "length=${length} below threshold=${EXPECTED_SCF_MIN_BYTES}"
    return
  fi
  if (( ${#missing[@]} > 0 )); then
    report_fail "SystemCallFilter" \
      "length=${length} missing anchors: ${missing[*]}"
    return
  fi
  report_ok "SystemCallFilter" \
    "length=${length} anchors=$(IFS=,; printf '%s' "${EXPECTED_SCF_ANCHORS[*]}")"
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
           | grep -cE '(fsdaemon_t|nnp_transition|smartd)' \
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

# Type field of a path's own context. Distinct from current_type(), which
# reports the context of this process; passing a path to that one would
# silently ignore the argument. `stat` does not follow symlinks, so the link
# and its target can be asserted separately.
#
# The `|| true` is load-bearing. An unreadable path is an EXPECTED outcome
# here -- the caller tests for the empty string and reports it -- but `stat`
# signals it with exit 1, `set -o pipefail` promotes that to a pipeline
# failure, and `set -e` then killed the script at the caller's
# `actual=$(file_type ...)` assignment. The caller's "context not readable"
# branch was unreachable, and the abort surfaced as a bare rc=1: no FAIL line,
# no remaining checks, indistinguishable from ordinary drift.
file_type() {
  stat -c '%C' "$1" 2>/dev/null | awk -F: '{print $3}' || true
}

# Compared against the expected type as a constant, never against
# `matchpathcon`. A table-versus-label comparison passes whenever both are
# wrong together — and a context table can be rebuilt without a mapping that a
# generated module supplied, which is precisely when the label goes wrong.
# Reading the table would therefore confirm the defect instead of reporting it.
# sysadm_t-gated, like every other policy-side check in this script. The gate
# is not a convenience: this topic relabels the binary to fsdaemon_exec_t, and
# staff_t holds no getattr on that type, so the label is structurally
# unreadable from a confined staff shell. Reporting that as drift would make
# the script fail on a correctly hardened host -- the confined shell cannot
# see the very property the relabel established.
verify_exec_label() {
  local actual
  if ! is_sysadm_t; then
    report_skip "exec_label" "needs sysadm_t"
    return
  fi
  actual=$(file_type "${BINARY_PATH}")
  if [[ -z "${actual}" ]]; then
    report_fail "exec_label" "${BINARY_PATH}: context not readable"
    return
  fi
  if [[ "${actual}" == "${EXPECTED_EXEC_TYPE}" ]]; then
    report_ok "exec_label" "${BINARY_PATH}=${actual}"
  else
    report_fail "exec_label" \
      "${BINARY_PATH}: expected=${EXPECTED_EXEC_TYPE} actual=${actual}"
  fi
}

# Same gate, same reason: the link resolves into the relabelled type, and the
# check reads a context either way.
verify_symlink_label() {
  local actual
  if ! is_sysadm_t; then
    report_skip "symlink_label" "needs sysadm_t"
    return
  fi
  if [[ ! -L "${BINARY_SYMLINK}" ]]; then
    report_skip "symlink_label" "${BINARY_SYMLINK} is not a symlink"
    return
  fi
  actual=$(file_type "${BINARY_SYMLINK}")
  if [[ "${actual}" == "${EXPECTED_SYMLINK_TYPE}" ]]; then
    report_ok "symlink_label" "${BINARY_SYMLINK}=${actual}"
  else
    report_fail "symlink_label" \
      "${BINARY_SYMLINK}: expected=${EXPECTED_SYMLINK_TYPE} actual=${actual} (local mapping too broad?)"
  fi
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
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_capability_bounding_set
  verify_property "RestrictAddressFamilies" "RestrictAddressFamilies" \
    "${EXPECTED_RAF}"
  verify_systemcallfilter
  verify_selinux_domain
  verify_exec_label
  verify_symlink_label
  verify_cil_module
  verify_avc_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
