#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_gnupg_pinentry_dbus.
#
# Reports current state of the GnuPG-pinentry D-Bus session-bus
# surface: required-package presence, the operator-configured pinentry
# helper, the operator's runtime SELinux mapping, the priority-400
# module slot, the two allow surfaces of the topic-owned CIL module,
# and the AVC stream filtered for the functional-class records since
# boot.
#
# The probe never gates on observed state; the end-state of an applied
# host is the priority-400 module installed and both allow surfaces
# present in the loaded policy.
#
# Stages that need policy-store reads (semodule, sesearch, ausearch)
# are gated behind a sysadm_t domain check and reported as SKIP from a
# staff_t shell.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="gnupg_pinentry_dbus"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_PINENTRY_PROGRAM="/usr/bin/pinentry-gnome3"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly USER_GPG_AGENT_CONF="${HOME}/.gnupg/gpg-agent.conf"
readonly -a CORE_PACKAGES=(
  "gnupg2"
  "pinentry"
  "pinentry-gnome3"
  "gcr3"
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

current_type() {
  id -Z 2>/dev/null | awk -F: '{print $3}'
}

is_sysadm_t() {
  [[ "$(current_type)" == "sysadm_t" ]]
}

print_header() {
  printf '=== probe: gnupg-pinentry-dbus ===\n'
}

probe_packages() {
  printf -- '--- packages ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf 'rpm: not available\n'
    return
  fi
  local pkg
  for pkg in "${CORE_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      printf 'core      %s: installed (%s)\n' "${pkg}" "$(rpm -q "${pkg}")"
    else
      printf 'core      %s: missing\n' "${pkg}"
    fi
  done
}

probe_pinentry_program() {
  printf -- '--- operator pinentry-program selection ---\n'
  if [[ ! -f "${USER_GPG_AGENT_CONF}" ]]; then
    printf 'gpg-agent.conf: not present at %s\n' "${USER_GPG_AGENT_CONF}"
    return
  fi
  local line
  line=$(grep -E '^pinentry-program' "${USER_GPG_AGENT_CONF}" 2>/dev/null \
           || true)
  if [[ -z "${line}" ]]; then
    printf 'pinentry-program: (no explicit setting; gpg-agent default applies)\n'
    return
  fi
  printf '%s\n' "${line}"
  if [[ "${line}" == *"${EXPECTED_PINENTRY_PROGRAM}"* ]]; then
    printf 'applicability: matches anchor %s\n' "${EXPECTED_PINENTRY_PROGRAM}"
  else
    printf 'applicability: does NOT match anchor %s; topic does not apply\n' \
      "${EXPECTED_PINENTRY_PROGRAM}"
  fi
}

probe_operator_mapping() {
  printf -- '--- operator runtime SELinux mapping ---\n'
  local id_z
  id_z=$(id -Z 2>/dev/null || true)
  printf 'id -Z: %s\n' "${id_z}"
  if [[ "${id_z}" == *"${EXPECTED_SEUSER_SUBSTRING}"* ]]; then
    printf 'applicability: matches anchor %s\n' "${EXPECTED_SEUSER_SUBSTRING}"
  else
    printf 'applicability: does NOT match anchor %s; topic does not apply\n' \
      "${EXPECTED_SEUSER_SUBSTRING}"
  fi
}

probe_module_slot() {
  printf -- '--- priority-%s module slot ---\n' "${MODULE_PRIORITY}"
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t (run via `sudo -r sysadm_r -t sysadm_t bash probe.sh`)\n'
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    printf 'semodule: not available\n'
    return
  fi
  semodule -lfull \
    | grep -wE "^[ ]*${MODULE_PRIORITY}.*${MODULE_NAME}" \
    || printf '(module not installed at priority %s)\n' "${MODULE_PRIORITY}"
}

probe_rule_a() {
  printf -- '--- functional rule (gpg_pinentry_t × session_dbusd_tmp_t : sock_file write) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A \
    -s gpg_pinentry_t \
    -t session_dbusd_tmp_t \
    -c sock_file \
    -p write \
    || printf '(no allow surface)\n'
}

probe_rule_b() {
  printf -- '--- audit-cosmetic rule (gpg_t × gpg_agent_t : process triple) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  local merged
  merged=$(sesearch -A -s gpg_t -t gpg_agent_t -c process 2>/dev/null \
             || true)
  if [[ -z "${merged}" ]]; then
    printf '(no allow surface)\n'
    return
  fi
  printf '%s\n' "${merged}"
  printf 'noatsecure_present: '
  if printf '%s' "${merged}" | grep -qw 'noatsecure'; then
    printf 'yes\n'
  else
    printf 'no\n'
  fi
  printf 'rlimitinh_present: '
  if printf '%s' "${merged}" | grep -qw 'rlimitinh'; then
    printf 'yes\n'
  else
    printf 'no\n'
  fi
  printf 'siginh_present: '
  if printf '%s' "${merged}" | grep -qw 'siginh'; then
    printf 'yes\n'
  else
    printf 'no\n'
  fi
}

probe_avc_stream() {
  printf -- '--- AVC stream since boot (functional class only) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    printf 'ausearch: not available\n'
    return
  fi
  ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
    | grep -E 'gpg_pinentry_t.*session_dbusd_tmp_t' \
    | head -10 \
    || printf '(no functional-class denials since boot)\n'
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_pinentry_program
  probe_operator_mapping
  probe_module_slot
  probe_rule_a
  probe_rule_b
  probe_avc_stream
  printf -- '--- end of probe ---\n'
}

main "$@"
