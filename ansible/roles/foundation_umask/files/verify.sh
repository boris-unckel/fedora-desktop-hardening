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
readonly DNF_ACTIONS_PACKAGE="libdnf5-plugin-actions"
readonly DNF_ACTIONS_CONF="/etc/dnf/libdnf5-plugins/actions.conf"
readonly DNF_ACTIONS_FILE="/etc/dnf/libdnf5-plugins/actions.d/50-system-state-perms.actions"
readonly DNF_STATE_DIR="/usr/lib/sysimage/libdnf5"
readonly DNF_STATE_FILES=(environments groups modules nevras packages system)
readonly EXPECTED_STATE_MODE="644"

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

expected_dnf_action_line() {
  local -a paths=()
  local name
  for name in "${DNF_STATE_FILES[@]}"; do
    paths+=("${DNF_STATE_DIR}/${name}.toml")
  done
  printf 'post_transaction:::enabled=host-only:/usr/bin/chmod 0644 %s' "${paths[*]}"
}

verify_dnf_actions_package() {
  if rpm -q "${DNF_ACTIONS_PACKAGE}" >/dev/null 2>&1; then
    report_ok "pkg_libdnf5_plugin_actions" "installed"
  else
    report_fail "pkg_libdnf5_plugin_actions" "not installed"
  fi
}

verify_dnf_actions_enabled() {
  if grep -qE '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(1|yes|true)[[:space:]]*$' \
       "${DNF_ACTIONS_CONF}" 2>/dev/null; then
    report_ok "dnf_actions_plugin_enabled" "${DNF_ACTIONS_CONF}"
  else
    report_fail "dnf_actions_plugin_enabled" \
      "no 'enabled = 1' in ${DNF_ACTIONS_CONF}"
  fi
}

verify_dnf_state_action_file() {
  if [[ ! -f "${DNF_ACTIONS_FILE}" ]]; then
    report_fail "dnf_state_action_file" "missing: ${DNF_ACTIONS_FILE}"
    return
  fi
  # Exactly one action line, equal to the expected one; comments are free text.
  local actions expected meta
  actions=$(grep -vE '^[[:space:]]*(#|$)' "${DNF_ACTIONS_FILE}" || true)
  expected=$(expected_dnf_action_line)
  meta=$(stat -c '%a %U:%G' "${DNF_ACTIONS_FILE}")
  if [[ "${actions}" != "${expected}" ]]; then
    report_fail "dnf_state_action_file" \
      "action line differs from expected: ${actions:-<none>}"
  elif [[ "${meta}" != "644 root:root" ]]; then
    report_fail "dnf_state_action_file" "expected=644 root:root actual=${meta}"
  else
    report_ok "dnf_state_action_file" "${meta}"
  fi
}

verify_dnf_state_action_label() {
  if [[ ! -f "${DNF_ACTIONS_FILE}" ]]; then
    report_fail "dnf_state_action_label" "missing: ${DNF_ACTIONS_FILE}"
    return
  fi
  # The full context, user field included: restorecon -n compares the type only.
  local actual expected
  actual=$(stat -c '%C' "${DNF_ACTIONS_FILE}")
  expected=$(matchpathcon -n -m file "${DNF_ACTIONS_FILE}" 2>/dev/null || true)
  if [[ -n "${expected}" && "${actual}" == "${expected}" ]]; then
    report_ok "dnf_state_action_label" "${actual}"
  else
    report_fail "dnf_state_action_label" \
      "expected=${expected:-<matchpathcon failed>} actual=${actual}"
  fi
}

verify_dnf_state_files_mode() {
  local name path mode
  local -a drift=()
  for name in "${DNF_STATE_FILES[@]}"; do
    path="${DNF_STATE_DIR}/${name}.toml"
    if [[ ! -e "${path}" ]]; then
      drift+=("${name}.toml=missing")
      continue
    fi
    mode=$(stat -c '%a' "${path}")
    if [[ "${mode}" != "${EXPECTED_STATE_MODE}" ]]; then
      drift+=("${name}.toml=${mode}")
    fi
  done
  if [[ "${#drift[@]}" -eq 0 ]]; then
    report_ok "dnf_state_files_mode" "${#DNF_STATE_FILES[@]} files ${EXPECTED_STATE_MODE}"
  else
    report_fail "dnf_state_files_mode" \
      "expected=${EXPECTED_STATE_MODE} drift: ${drift[*]}"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool rpm
  require_tool stat
  require_tool matchpathcon
  verify_login_defs_umask
  verify_login_defs_home_mode
  verify_login_defs_usergroups_enab
  verify_pam_postlogin
  verify_no_shell_init_override
  verify_bashrc_fallback
  verify_no_systemd_default_umask
  verify_live_umask
  verify_dnf_actions_package
  verify_dnf_actions_enabled
  verify_dnf_state_action_file
  verify_dnf_state_action_label
  verify_dnf_state_files_mode
  exit "${fail_state}"
}

main "$@"
