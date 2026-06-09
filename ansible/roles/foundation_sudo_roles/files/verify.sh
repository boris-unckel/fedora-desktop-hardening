#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for foundation_sudo_roles.
#
# Compares observed state against the expected end state declared in
# docs/reference/foundation/sudo-roles.md. Read-only. Reports SKIP for
# checks that need sysadm_t when the current shell is not in that domain;
# SKIP does not count as drift.
#
# Usage:
#   FOUNDATION_SUDO_ROLES_USER=<user> bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIPped checks accepted)
#   1  drift detected
#   2  invocation error (missing required tool, missing operator user var)

set -euo pipefail

readonly SEUSERS="/etc/selinux/targeted/seusers"
readonly SUDOERS="/etc/sudoers"
readonly SUDOERS_D="/etc/sudoers.d"
readonly CIL_MODULE_NAME="staff_extras"
readonly CIL_MODULE_PRIORITY="400"
readonly EXPECTED_SECURE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly EXPECTED_STAFF_T_CONTEXT="staff_u:staff_r:staff_t:s0-s0:c0.c1023"

readonly OPERATOR_USER="${FOUNDATION_SUDO_ROLES_USER:-}"

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
  local label="$1"
  local detail="$2"
  printf 'OK   %-30s %s\n' "${label}" "${detail}"
}

report_skip() {
  local label="$1"
  local detail="$2"
  printf 'SKIP %-30s %s\n' "${label}" "${detail}"
}

report_fail() {
  local label="$1"
  local detail="$2"
  printf 'FAIL %-30s %s\n' "${label}" "${detail}"
  fail_state=1
}

verify_semanage_login_mapping() {
  if [[ -z "${OPERATOR_USER}" ]]; then
    report_fail "semanage_login_mapping" \
      "FOUNDATION_SUDO_ROLES_USER not set in environment"
    return
  fi
  if [[ ! -r "${SEUSERS}" ]]; then
    report_skip "semanage_login_mapping" \
      "${SEUSERS} unreadable from current domain"
    return
  fi
  local row
  row=$(awk -F: -v u="${OPERATOR_USER}" '$1 == u { print; exit }' "${SEUSERS}")
  if [[ -z "${row}" ]]; then
    report_fail "semanage_login_mapping" \
      "no row for ${OPERATOR_USER} in ${SEUSERS}"
    return
  fi
  local seuser
  seuser=$(awk -F: '{print $2}' <<<"${row}")
  if [[ "${seuser}" == "staff_u" ]]; then
    report_ok "semanage_login_mapping" \
      "${OPERATOR_USER}:staff_u:s0-s0:c0.c1023:*"
  else
    report_fail "semanage_login_mapping" \
      "expected=staff_u actual=${seuser:-<missing>}"
  fi
}

verify_seinfo_user_staff_u() {
  if ! command -v seinfo >/dev/null 2>&1; then
    report_skip "seinfo_user_staff_u" "seinfo not installed"
    return
  fi
  if seinfo -u staff_u 2>/dev/null | grep -qE '^[[:space:]]+staff_u$'; then
    report_ok "seinfo_user_staff_u" "present"
  else
    report_fail "seinfo_user_staff_u" \
      "staff_u absent from seinfo -u output"
  fi
}

verify_seinfo_role_sysadm_r() {
  if ! command -v seinfo >/dev/null 2>&1; then
    report_skip "seinfo_role_sysadm_r" "seinfo not installed"
    return
  fi
  if seinfo -r sysadm_r 2>/dev/null | grep -qE '^[[:space:]]+sysadm_r$'; then
    report_ok "seinfo_role_sysadm_r" "present"
  else
    report_fail "seinfo_role_sysadm_r" \
      "sysadm_r absent from seinfo -r output"
  fi
}

verify_semodule_priority_400() {
  if ! is_sysadm_t; then
    report_skip "semodule_${CIL_MODULE_NAME}_p${CIL_MODULE_PRIORITY}" \
      "needs sysadm_t"
    return
  fi
  local row
  # No early `exit` in awk: semodule -lfull emits hundreds of lines, and an
  # awk that exits on first match closes the pipe early, sending SIGPIPE to
  # semodule. Under `set -o pipefail` that surfaces as rc 141 and aborts the
  # script. Letting awk drain all input avoids it; the match is unique.
  row=$(semodule -lfull 2>/dev/null \
        | awk -v p="${CIL_MODULE_PRIORITY}" -v m="${CIL_MODULE_NAME}" \
              '$1 == p && $2 == m { print }')
  if [[ -n "${row}" ]]; then
    report_ok "semodule_${CIL_MODULE_NAME}_p${CIL_MODULE_PRIORITY}" "${row}"
  else
    report_fail "semodule_${CIL_MODULE_NAME}_p${CIL_MODULE_PRIORITY}" \
      "module not present at priority ${CIL_MODULE_PRIORITY}"
  fi
}

verify_id_z_current_shell() {
  local actual
  actual=$(id -Z 2>/dev/null || true)
  if [[ -z "${actual}" ]]; then
    report_fail "id_z_current_shell" "id -Z returned no output"
    return
  fi
  case "${actual}" in
    "${EXPECTED_STAFF_T_CONTEXT}")
      report_ok "id_z_current_shell" "${actual}"
      ;;
    staff_u:sysadm_r:sysadm_t:*)
      report_ok "id_z_current_shell" \
        "${actual} (sysadm_r escalation; not the post-login default)"
      ;;
    *)
      report_fail "id_z_current_shell" \
        "expected=${EXPECTED_STAFF_T_CONTEXT} actual=${actual}"
      ;;
  esac
}

verify_sudoers_secure_path() {
  if [[ ! -r "${SUDOERS}" ]]; then
    report_skip "sudoers_secure_path" \
      "${SUDOERS} unreadable from current domain"
    return
  fi
  local actual
  actual=$(awk '/^[[:space:]]*Defaults[[:space:]]+secure_path[[:space:]]*=/ {
                  sub(/^[^=]*=[[:space:]]*/, "")
                  print
                  exit
                }' "${SUDOERS}")
  if [[ "${actual}" == "${EXPECTED_SECURE_PATH}" ]]; then
    report_ok "sudoers_secure_path" "${actual}"
  else
    report_fail "sudoers_secure_path" \
      "expected=${EXPECTED_SECURE_PATH} actual=${actual:-<missing>}"
  fi
}

verify_sudoers_no_global_logfile() {
  if [[ ! -r "${SUDOERS}" ]]; then
    report_skip "sudoers_no_global_logfile" \
      "${SUDOERS} unreadable from current domain"
    return
  fi
  if grep -qE '^[[:space:]]*Defaults[[:space:]]+logfile=' "${SUDOERS}"; then
    report_fail "sudoers_no_global_logfile" \
      "global Defaults logfile= present in ${SUDOERS}"
  else
    report_ok "sudoers_no_global_logfile" "none"
  fi
}

verify_sudoers_d_custom_logfile_labels() {
  if [[ ! -d "${SUDOERS_D}" ]] || [[ ! -r "${SUDOERS_D}" ]]; then
    report_skip "sudoers_d_drop_ins" \
      "${SUDOERS_D} unreadable from current domain"
    return
  fi
  local -a logfile_paths=()
  local file path
  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    while IFS= read -r path; do
      [[ -z "${path}" ]] && continue
      logfile_paths+=("${path}")
    done < <(awk -F'logfile=' \
                 '/^[[:space:]]*Defaults![^[:space:]]+[[:space:]]+logfile=/ {
                    sub(/[[:space:]]+#.*/, "", $2)
                    sub(/[[:space:]]+$/, "", $2)
                    print $2
                  }' "${file}")
  done < <(grep -lE '^[[:space:]]*Defaults![^[:space:]]+[[:space:]]+logfile=' \
             "${SUDOERS_D}"/* 2>/dev/null || true)
  if (( ${#logfile_paths[@]} == 0 )); then
    report_ok "sudoers_d_drop_ins" "(no custom logfile drop-ins detected)"
    return
  fi
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_skip "sudoers_d_drop_ins" \
      "matchpathcon not installed; cannot verify sudo_log_t labeling"
    return
  fi
  local label_fail=0 mp
  for path in "${logfile_paths[@]}"; do
    mp=$(matchpathcon "${path}" 2>/dev/null | awk '{print $2}')
    if [[ "${mp}" == *":sudo_log_t:"* ]]; then
      report_ok "sudoers_d_drop_ins" "${path} -> ${mp}"
    else
      report_fail "sudoers_d_drop_ins" \
        "${path} expected sudo_log_t actual=${mp:-<no match>}"
      label_fail=1
    fi
  done
  if (( label_fail == 0 )); then
    :
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  verify_semanage_login_mapping
  verify_seinfo_user_staff_u
  verify_seinfo_role_sysadm_r
  verify_semodule_priority_400
  verify_id_z_current_shell
  verify_sudoers_secure_path
  verify_sudoers_no_global_logfile
  verify_sudoers_d_custom_logfile_labels
  exit "${fail_state}"
}

main "$@"
