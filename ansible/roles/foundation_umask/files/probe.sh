#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only inventory of UMASK-relevant configuration sources.
#
# Reports the values found in each source. Performs no state change. Runnable
# from a non-privileged shell against the live filesystem.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly LOGIN_DEFS="/etc/login.defs"
readonly PAM_POSTLOGIN="/etc/pam.d/postlogin"
readonly PROFILE="/etc/profile"
readonly PROFILE_D="/etc/profile.d"
readonly BASHRC="/etc/bashrc"
readonly SYSTEM_CONF="/etc/systemd/system.conf"
readonly SYSTEM_CONF_D="/etc/systemd/system.conf.d"
readonly BASHRC_FALLBACK_LINE='[ `umask` -eq 0 ] && umask 022'

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

print_header() {
  printf '=== probe: foundation_umask ===\n'
}

probe_login_defs() {
  printf -- '--- %s ---\n' "${LOGIN_DEFS}"
  if [[ -r "${LOGIN_DEFS}" ]]; then
    grep -E '^(UMASK|HOME_MODE|USERGROUPS_ENAB)[[:space:]]+' "${LOGIN_DEFS}" \
      || printf '(no UMASK/HOME_MODE/USERGROUPS_ENAB lines found)\n'
  else
    printf '(unreadable)\n'
  fi
}

probe_pam_postlogin() {
  printf -- '--- %s ---\n' "${PAM_POSTLOGIN}"
  if [[ -r "${PAM_POSTLOGIN}" ]]; then
    grep -E 'pam_umask\.so' "${PAM_POSTLOGIN}" \
      || printf '(no pam_umask.so line found)\n'
  else
    printf '(unreadable)\n'
  fi
}

probe_shell_init_overrides() {
  printf -- '--- shell init umask overrides (/etc/profile, /etc/profile.d/) ---\n'
  local hits
  hits=$(grep -RHnE '^[[:space:]]*umask[[:space:]]+[0-7]+' \
           "${PROFILE}" "${PROFILE_D}" 2>/dev/null || true)
  if [[ -z "${hits}" ]]; then
    printf '(no hardcoded umask in /etc/profile or /etc/profile.d/)\n'
  else
    printf '%s\n' "${hits}"
  fi
}

probe_bashrc_fallback() {
  printf -- '--- %s package-default fallback line ---\n' "${BASHRC}"
  if [[ -r "${BASHRC}" ]]; then
    if grep -nF -- "${BASHRC_FALLBACK_LINE}" "${BASHRC}"; then
      :
    else
      printf '(fallback line not present in expected form)\n'
    fi
  else
    printf '(unreadable)\n'
  fi
}

probe_systemd_default_umask() {
  printf -- '--- %s ---\n' "${SYSTEM_CONF}"
  if [[ -r "${SYSTEM_CONF}" ]]; then
    grep -nE '^[[:space:]]*DefaultUMask=' "${SYSTEM_CONF}" \
      || printf '(no active DefaultUMask= in system.conf)\n'
  else
    printf '(unreadable)\n'
  fi
  printf -- '--- %s/ ---\n' "${SYSTEM_CONF_D}"
  if [[ -d "${SYSTEM_CONF_D}" ]]; then
    grep -RnE '^[[:space:]]*DefaultUMask=' "${SYSTEM_CONF_D}" 2>/dev/null \
      || printf '(no active DefaultUMask= override in system.conf.d/)\n'
  else
    printf '(directory absent)\n'
  fi
}

probe_live_umask() {
  printf -- '--- live umask in this shell ---\n'
  printf 'umask=%s\n' "$(umask)"
}

main() {
  require_tool grep
  print_header
  probe_login_defs
  probe_pam_postlogin
  probe_shell_init_overrides
  probe_bashrc_fallback
  probe_systemd_default_umask
  probe_live_umask
  printf -- '--- end of probe ---\n'
}

main "$@"
