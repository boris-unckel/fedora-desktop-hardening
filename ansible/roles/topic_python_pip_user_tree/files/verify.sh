#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_python_pip_user_tree.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/python-pip-user-tree.md. The marker path is
# computed at run time from sysconfig.get_path("stdlib") rather than hard-
# coded; the path varies by Python minor and by Fedora architecture. The
# verify script reads filesystem state only and does not require a
# role-switch; it is runnable from a staff_t-confined shell.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MARKER_FILENAME="EXTERNALLY-MANAGED"
readonly USERLOCAL_LIB="/usr/local/lib"
readonly USERLOCAL_BIN="/usr/local/bin"
readonly USERLOCAL_SBIN="/usr/local/sbin"
readonly EXPECTED_MARKER_MODE="644"
readonly EXPECTED_MARKER_OWNER="root"
readonly EXPECTED_MARKER_GROUP="root"
readonly EXPECTED_MARKER_BODY_FIRST_LINE="[externally-managed]"

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

resolve_user_home() {
  printf '%s' "${HOME:-/home/$(id -un)}"
}

resolve_stdlib() {
  python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' \
    2>/dev/null
}

resolve_marker_path() {
  local stdlib
  stdlib=$(resolve_stdlib)
  if [[ -z "${stdlib}" ]]; then
    return 1
  fi
  printf '%s/%s' "${stdlib}" "${MARKER_FILENAME}"
}

report_ok() {
  printf 'OK   %-36s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-36s %s\n' "$1" "$2"
  fail_state=1
}

verify_marker_present() {
  local label="marker_present"
  local marker_path="$1"
  if [[ -f "${marker_path}" ]]; then
    report_ok "${label}" "${marker_path}"
  else
    report_fail "${label}" "missing: ${marker_path}"
  fi
}

verify_marker_triplet() {
  local marker_path="$1"
  if [[ ! -e "${marker_path}" ]]; then
    return
  fi
  local mode owner group
  mode=$(stat -c '%a' "${marker_path}" 2>/dev/null || true)
  owner=$(stat -c '%U' "${marker_path}" 2>/dev/null || true)
  group=$(stat -c '%G' "${marker_path}" 2>/dev/null || true)
  if [[ "${mode}" == "${EXPECTED_MARKER_MODE}" ]]; then
    report_ok "marker_mode" "mode=${mode}"
  else
    report_fail "marker_mode" \
      "expected=${EXPECTED_MARKER_MODE} actual=${mode}"
  fi
  if [[ "${owner}" == "${EXPECTED_MARKER_OWNER}" \
        && "${group}" == "${EXPECTED_MARKER_GROUP}" ]]; then
    report_ok "marker_owner" "${owner}:${group}"
  else
    report_fail "marker_owner" \
      "expected=${EXPECTED_MARKER_OWNER}:${EXPECTED_MARKER_GROUP} actual=${owner}:${group}"
  fi
}

verify_marker_not_rpm_owned() {
  local marker_path="$1"
  local label="marker_not_rpm_owned"
  if [[ ! -e "${marker_path}" ]]; then
    return
  fi
  if ! command -v rpm >/dev/null 2>&1; then
    report_fail "${label}" "rpm not available"
    return
  fi
  local out rc
  out=$(rpm -qf "${marker_path}" 2>&1 || true)
  rc=$(rpm -qf "${marker_path}" >/dev/null 2>&1; printf '%d' $?)
  if (( rc != 0 )) || [[ "${out}" == *"is not owned by any package"* ]]; then
    report_ok "${label}" "(rc=${rc} out='${out}')"
  else
    report_fail "${label}" \
      "marker is RPM-owned (rc=${rc} out='${out}')"
  fi
}

verify_marker_first_line() {
  local marker_path="$1"
  local label="marker_first_line"
  if [[ ! -f "${marker_path}" ]]; then
    return
  fi
  local first
  first=$(head -n 1 "${marker_path}" 2>/dev/null || true)
  if [[ "${first}" == "${EXPECTED_MARKER_BODY_FIRST_LINE}" ]]; then
    report_ok "${label}" "${first}"
  else
    report_fail "${label}" \
      "expected='${EXPECTED_MARKER_BODY_FIRST_LINE}' actual='${first}'"
  fi
}

verify_marker_has_error_key() {
  local marker_path="$1"
  local label="marker_has_error_key"
  if [[ ! -f "${marker_path}" ]]; then
    return
  fi
  if grep -q '^Error=' "${marker_path}" 2>/dev/null; then
    report_ok "${label}" "Error= line present"
  else
    report_fail "${label}" "no Error= line in ${marker_path}"
  fi
}

verify_no_userlocal_lib_python() {
  local label="userlocal_lib_python_count"
  local pattern="${USERLOCAL_LIB}/python3."
  local count=0
  local d
  for d in "${pattern}"*; do
    [[ -d "${d}" ]] || continue
    count=$(( count + 1 ))
  done
  if (( count == 0 )); then
    report_ok "${label}" "0"
  else
    report_fail "${label}" "expected=0 actual=${count}"
  fi
}

verify_no_userlocal_pip_bins() {
  local label="userlocal_pip_bins_count"
  local count=0
  local f
  for f in "${USERLOCAL_BIN}"/pip* "${USERLOCAL_SBIN}"/pip*; do
    [[ -e "${f}" ]] || continue
    count=$(( count + 1 ))
  done
  if (( count == 0 )); then
    report_ok "${label}" "0"
  else
    report_fail "${label}" "expected=0 actual=${count}"
  fi
}

verify_no_orphan_user_trees() {
  local label="orphan_user_tree_count"
  local home count=0
  home=$(resolve_user_home)
  local d minor
  for d in "${home}"/.local/lib/python3.*; do
    [[ -d "${d}" ]] || continue
    minor=$(basename "${d}" | sed 's/^python//')
    if [[ ! -x "/usr/bin/python${minor}" ]]; then
      count=$(( count + 1 ))
    fi
  done
  if (( count == 0 )); then
    report_ok "${label}" "0"
  else
    report_fail "${label}" "expected=0 actual=${count}"
  fi
}

main() {
  require_tool awk
  require_tool basename
  require_tool grep
  require_tool head
  require_tool python3
  require_tool sed
  require_tool stat
  local marker_path
  if ! marker_path=$(resolve_marker_path); then
    printf 'verify: cannot resolve stdlib path via sysconfig\n' >&2
    exit 2
  fi
  verify_marker_present "${marker_path}"
  verify_marker_triplet "${marker_path}"
  verify_marker_not_rpm_owned "${marker_path}"
  verify_marker_first_line "${marker_path}"
  verify_marker_has_error_key "${marker_path}"
  verify_no_userlocal_lib_python
  verify_no_userlocal_pip_bins
  verify_no_orphan_user_trees
  exit "${fail_state}"
}

main "$@"
