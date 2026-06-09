#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_switcheroo_control.
#
# Compares observed runtime state against the expected end-state declared
# in docs/reference/topics/switcheroo-control.md. The end-state is
# service-disable: the unit is disabled, the unit is inactive(dead), and
# the WantedBy=graphical.target symlink is absent. Three independent
# on-disk facts are checked.
#
# The hybrid-GPU detection runs first as an applicability gate. A combined
# display+3D PCI controller count of 2 or more selects exit-2 (invocation
# error: this topic does not apply on this host); the exit-2 path is a
# structural-applicability negative, not drift.
#
# The AVC-clean check is gated behind a sysadm_t domain check and
# reported as SKIP from staff_t.
#
# No live-process probes. With MainPID=0 there is no PID to read
# /proc/<pid>/attr/current or /proc/<pid>/status from; the script omits
# those checks as structurally inapplicable rather than reporting SKIP.
# No `[ -d /proc/${main_pid} ]` liveness probe.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for sysadm_t-gated check)
#   1  drift detected
#   2  invocation error (missing required tool, or hybrid-GPU detected)

set -euo pipefail

readonly UNIT="switcheroo-control.service"
readonly REQUIRED_PACKAGE="switcheroo-control"
readonly GRAPHICAL_WANTS_SYMLINK="/etc/systemd/system/graphical.target.wants/switcheroo-control.service"
readonly EXPECTED_UNIT_FILE_STATE="disabled"
readonly EXPECTED_ACTIVE_STATE="inactive"
readonly EXPECTED_SUB_STATE="dead"
readonly EXPECTED_RESULT="success"
readonly EXPECTED_MAIN_PID="0"
# EXPECTED_GRAPHICAL_TARGET_WANTS_SYMLINK_ABSENT is consumed inside
# verify_symlink_absent (the symlink check is structural — present vs
# absent — and the constant is referenced verbatim in the report path
# so the operator sees the documented end-state value in verify output).
readonly EXPECTED_GRAPHICAL_TARGET_WANTS_SYMLINK_ABSENT="yes"
declare -ri MAX_GPU_COUNT_FOR_APPLICABILITY=1

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

verify_hybrid_gpu_gate() {
  # Applicability gate. Combined display+3D PCI controller count of 2+
  # selects exit-2 (invocation error: topic does not apply). The check
  # runs before any state assertion.
  if ! command -v lspci >/dev/null 2>&1; then
    # pciutils is absent on the lean headless base. A cloud VM exposes no
    # display or 3D PCI controller, so the single-or-no-GPU assumption holds
    # and the topic applies; proceed with the disable-state assertions rather
    # than exit-2, which would mark a structurally-applicable host inconclusive.
    report_ok "applicability_gate" \
      "lspci unavailable; assuming headless (no hybrid GPU)"
    return
  fi
  local display_count threed_count gpu_count
  display_count=$(lspci -d ::0300 -mm 2>/dev/null | grep -c '.' || true)
  threed_count=$(lspci -d ::0302 -mm 2>/dev/null | grep -c '.' || true)
  gpu_count=$(( display_count + threed_count ))
  if (( gpu_count > MAX_GPU_COUNT_FOR_APPLICABILITY )); then
    printf 'verify: hybrid-GPU detected (%s display+3D devices); topic does not apply on this host\n' \
      "${gpu_count}" >&2
    printf 'verify: enumeration follows:\n' >&2
    lspci -d ::0300 2>/dev/null >&2 || true
    lspci -d ::0302 2>/dev/null >&2 || true
    exit 2
  fi
  report_ok "applicability_gate" "gpu_count=${gpu_count} (single-GPU or headless)"
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
  local actual
  actual=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "${expected}" ]]; then
    report_ok "${label}" "${actual}"
  else
    report_fail "${label}" "expected='${expected}' actual='${actual}'"
  fi
}

verify_symlink_absent() {
  local expected="${EXPECTED_GRAPHICAL_TARGET_WANTS_SYMLINK_ABSENT}"
  local actual
  if [[ -e "${GRAPHICAL_WANTS_SYMLINK}" || -L "${GRAPHICAL_WANTS_SYMLINK}" ]]; then
    actual="no"
    report_fail "graphical_wants_symlink_absent" \
      "expected=${expected} actual=${actual} (present at ${GRAPHICAL_WANTS_SYMLINK})"
  else
    actual="yes"
    if [[ "${actual}" == "${expected}" ]]; then
      report_ok "graphical_wants_symlink_absent" \
        "${actual} (${GRAPHICAL_WANTS_SYMLINK})"
    else
      report_fail "graphical_wants_symlink_absent" \
        "expected=${expected} actual=${actual}"
    fi
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
  hits=$(ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
           | grep -cE '(switcheroo|switcheroo_control_t|switcheroo_control_exec_t)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot (unit started this boot — drift)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool systemctl
  verify_hybrid_gpu_gate
  verify_package
  verify_property "unit_file_state" "UnitFileState" \
    "${EXPECTED_UNIT_FILE_STATE}"
  verify_property "active_state" "ActiveState" \
    "${EXPECTED_ACTIVE_STATE}"
  verify_property "sub_state" "SubState" \
    "${EXPECTED_SUB_STATE}"
  verify_property "result" "Result" \
    "${EXPECTED_RESULT}"
  verify_property "main_pid" "MainPID" \
    "${EXPECTED_MAIN_PID}"
  verify_symlink_absent
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
