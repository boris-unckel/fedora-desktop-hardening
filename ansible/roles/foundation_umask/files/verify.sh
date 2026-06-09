#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for foundation_umask.
#
# Compares observed UMASK-related configuration against the expected end state
# declared in docs/reference/foundation/umask.md. All checks are read-only;
# the script is runnable from a non-privileged login shell.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly LOGIN_DEFS="/etc/login.defs"
readonly PAM_POSTLOGIN="/etc/pam.d/postlogin"
readonly PROFILE="/etc/profile"
readonly PROFILE_D="/etc/profile.d"
readonly BASHRC="/etc/bashrc"
readonly SYSTEM_CONF="/etc/systemd/system.conf"
readonly SYSTEM_CONF_D="/etc/systemd/system.conf.d"
readonly EXPECTED_UMASK="027"
readonly EXPECTED_HOME_MODE="0700"
readonly EXPECTED_USERGROUPS_ENAB="yes"
readonly EXPECTED_LIVE_UMASK="0027"
readonly BASHRC_FALLBACK_LINE='[ `umask` -eq 0 ] && umask 022'

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

report_ok() {
  local label="$1"
  local detail="$2"
  printf 'OK   %-30s %s\n' "${label}" "${detail}"
}

report_fail() {
  local label="$1"
  local detail="$2"
  printf 'FAIL %-30s %s\n' "${label}" "${detail}"
  fail_state=1
}

extract_login_defs_value() {
  local key="$1"
  awk -v k="${key}" '$1 == k { print $2; exit }' "${LOGIN_DEFS}"
}

verify_login_defs_umask() {
  local actual
  actual=$(extract_login_defs_value UMASK)
  if [[ "${actual}" == "${EXPECTED_UMASK}" ]]; then
    report_ok "login_defs_umask" "${actual}"
  else
    report_fail "login_defs_umask" \
      "expected=${EXPECTED_UMASK} actual=${actual:-<missing>}"
  fi
}

verify_login_defs_home_mode() {
  local actual
  actual=$(extract_login_defs_value HOME_MODE)
  if [[ "${actual}" == "${EXPECTED_HOME_MODE}" ]]; then
    report_ok "login_defs_home_mode" "${actual}"
  else
    report_fail "login_defs_home_mode" \
      "expected=${EXPECTED_HOME_MODE} actual=${actual:-<missing>}"
  fi
}

verify_login_defs_usergroups_enab() {
  local actual
  actual=$(extract_login_defs_value USERGROUPS_ENAB)
  if [[ "${actual}" == "${EXPECTED_USERGROUPS_ENAB}" ]]; then
    report_ok "login_defs_usergroups_enab" "${actual}"
  else
    report_fail "login_defs_usergroups_enab" \
      "expected=${EXPECTED_USERGROUPS_ENAB} actual=${actual:-<missing>}"
  fi
}

verify_pam_postlogin() {
  if grep -qE '^session[[:space:]]+optional[[:space:]]+pam_umask\.so[[:space:]]+silent' \
       "${PAM_POSTLOGIN}" 2>/dev/null; then
    report_ok "pam_postlogin_umask" "session optional pam_umask.so silent"
  else
    report_fail "pam_postlogin_umask" \
      "expected hook absent from ${PAM_POSTLOGIN}"
  fi
}

verify_no_shell_init_override() {
  local hits
  hits=$(grep -RlE '^[[:space:]]*umask[[:space:]]+[0-7]+' \
           "${PROFILE}" "${PROFILE_D}" 2>/dev/null || true)
  if [[ -z "${hits}" ]]; then
    report_ok "shell_init_no_umask_override" "none"
  else
    report_fail "shell_init_no_umask_override" \
      "umask override in: ${hits//$'\n'/, }"
  fi
}

verify_bashrc_fallback() {
  # The package-default fallback in /etc/bashrc fires only when the inherited
  # umask is 0; under pam_umask=0027 it is a no-op. The line must remain
  # untouched — its absence indicates that /etc/bashrc has been edited and is
  # out of scope for this role to repair.
  if grep -qF -- "${BASHRC_FALLBACK_LINE}" "${BASHRC}" 2>/dev/null; then
    report_ok "bashrc_fallback_unchanged" "${BASHRC_FALLBACK_LINE}"
  else
    report_fail "bashrc_fallback_unchanged" \
      "expected line absent from ${BASHRC}: ${BASHRC_FALLBACK_LINE}"
  fi
}

verify_no_systemd_default_umask() {
  local hits=""
  if [[ -r "${SYSTEM_CONF}" ]]; then
    hits=$(grep -lE '^[[:space:]]*DefaultUMask=' "${SYSTEM_CONF}" 2>/dev/null \
           || true)
  fi
  if [[ -d "${SYSTEM_CONF_D}" ]]; then
    local d_hits
    d_hits=$(grep -RlE '^[[:space:]]*DefaultUMask=' "${SYSTEM_CONF_D}" \
             2>/dev/null || true)
    if [[ -n "${d_hits}" ]]; then
      hits="${hits:+${hits}$'\n'}${d_hits}"
    fi
  fi
  if [[ -z "${hits}" ]]; then
    report_ok "system_conf_no_default_umask" "none"
  else
    report_fail "system_conf_no_default_umask" \
      "active DefaultUMask= override in: ${hits//$'\n'/, }"
  fi
}

verify_live_umask() {
  local actual
  actual=$(umask)
  if [[ "${actual}" == "${EXPECTED_LIVE_UMASK}" ]]; then
    report_ok "live_login_umask" "${actual}"
  else
    report_fail "live_login_umask" \
      "expected=${EXPECTED_LIVE_UMASK} actual=${actual} (run from a fresh login shell)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  verify_login_defs_umask
  verify_login_defs_home_mode
  verify_login_defs_usergroups_enab
  verify_pam_postlogin
  verify_no_shell_init_override
  verify_bashrc_fallback
  verify_no_systemd_default_umask
  verify_live_umask
  exit "${fail_state}"
}

main "$@"
