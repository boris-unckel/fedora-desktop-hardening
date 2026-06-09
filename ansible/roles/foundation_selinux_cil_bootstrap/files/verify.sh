#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for foundation_selinux_cil_bootstrap.
#
# Compares observed state against the loader-contract end state declared
# in docs/reference/foundation/selinux-cil-bootstrap.md. Read-only.
# Reports SKIP for checks that need sysadm_t when the current shell is
# not in that domain; SKIP does not count as drift. Permissive runtime
# and runtime/config divergence are reported as WARN (loader is
# operational); disabled is reported as FAIL.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly SELINUX_CONFIG="/etc/selinux/config"
readonly CIL_DIR="/usr/local/share/selinux"
readonly EXPECTED_DIR_MODE="755"
readonly EXPECTED_DIR_OWNER="root:root"
readonly EXPECTED_CONFIG_TYPE="targeted"
readonly REQUIRED_PACKAGES=(
  "policycoreutils-python-utils"
  "selinux-policy-targeted"
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

report_warn() {
  printf 'WARN %-30s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-30s %s\n' "$1" "$2"
  fail_state=1
}

verify_runtime_mode() {
  if ! command -v getenforce >/dev/null 2>&1; then
    report_fail "selinux_runtime_mode" "getenforce not installed"
    return
  fi
  local mode
  mode=$(getenforce 2>/dev/null || true)
  case "${mode}" in
    Enforcing)
      report_ok "selinux_runtime_mode" "${mode}"
      ;;
    Permissive)
      report_warn "selinux_runtime_mode" \
        "${mode} (loader operational; enforcement off)"
      ;;
    Disabled)
      report_fail "selinux_runtime_mode" \
        "${mode} (recovery requires reboot; out of role scope)"
      ;;
    *)
      report_fail "selinux_runtime_mode" \
        "unexpected getenforce output: ${mode:-<empty>}"
      ;;
  esac
}

verify_selinux_config() {
  if [[ ! -r "${SELINUX_CONFIG}" ]]; then
    report_skip "selinux_config_mode" \
      "${SELINUX_CONFIG} unreadable from current domain"
    report_skip "selinux_config_type" \
      "${SELINUX_CONFIG} unreadable from current domain"
    return
  fi
  local config_mode config_type
  config_mode=$(awk -F= '/^[[:space:]]*SELINUX=/ {print $2; exit}' \
                  "${SELINUX_CONFIG}" | tr -d '[:space:]')
  config_type=$(awk -F= '/^[[:space:]]*SELINUXTYPE=/ {print $2; exit}' \
                  "${SELINUX_CONFIG}" | tr -d '[:space:]')
  case "${config_mode}" in
    enforcing)
      report_ok "selinux_config_mode" "${config_mode}"
      ;;
    permissive)
      report_warn "selinux_config_mode" \
        "${config_mode} (deliberate operator setting; loader operational)"
      ;;
    disabled)
      report_fail "selinux_config_mode" \
        "${config_mode} (recovery requires reboot; out of role scope)"
      ;;
    *)
      report_fail "selinux_config_mode" \
        "expected=enforcing actual=${config_mode:-<missing>}"
      ;;
  esac
  if [[ "${config_type}" == "${EXPECTED_CONFIG_TYPE}" ]]; then
    report_ok "selinux_config_type" "${config_type}"
  else
    report_fail "selinux_config_type" \
      "expected=${EXPECTED_CONFIG_TYPE} actual=${config_type:-<missing>}"
  fi
}

verify_cil_dir() {
  if [[ ! -d "${CIL_DIR}" ]]; then
    report_fail "selinux_dir_present" "${CIL_DIR} not present"
    report_skip "selinux_dir_label" "${CIL_DIR} not present"
    return
  fi
  local mode owner group
  mode=$(stat -c '%a' "${CIL_DIR}" 2>/dev/null || true)
  owner=$(stat -c '%U' "${CIL_DIR}" 2>/dev/null || true)
  group=$(stat -c '%G' "${CIL_DIR}" 2>/dev/null || true)
  if [[ "${mode}" == "${EXPECTED_DIR_MODE}" ]] \
     && [[ "${owner}:${group}" == "${EXPECTED_DIR_OWNER}" ]]; then
    report_ok "selinux_dir_present" \
      "${CIL_DIR} mode=0${mode} owner=${owner}:${group}"
  else
    report_fail "selinux_dir_present" \
      "${CIL_DIR} mode=0${mode} owner=${owner}:${group} (expected mode=0${EXPECTED_DIR_MODE} owner=${EXPECTED_DIR_OWNER})"
  fi
  local label
  label=$(stat -c '%C' "${CIL_DIR}" 2>/dev/null || true)
  if [[ "${label}" == *":usr_t:"* ]]; then
    report_ok "selinux_dir_label" "${label}"
  elif [[ -z "${label}" || "${label}" == "?" ]]; then
    report_skip "selinux_dir_label" "label unavailable in current domain"
  else
    report_warn "selinux_dir_label" \
      "${label} (expected *:usr_t:*; non-default label, loader still operational)"
  fi
}

verify_packages() {
  if ! command -v rpm >/dev/null 2>&1; then
    report_fail "pkg_check" "rpm not available"
    return
  fi
  local pkg label
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    label="pkg_$(printf '%s' "${pkg}" | tr -- '-' '_')"
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      report_ok "${label}" "installed"
    else
      report_fail "${label}" "not installed"
    fi
  done
}

verify_semodule_callable() {
  if ! command -v semodule >/dev/null 2>&1; then
    report_fail "semodule_callable" "semodule not installed"
    return
  fi
  if ! is_sysadm_t; then
    report_skip "semodule_callable" "needs sysadm_t"
    return
  fi
  if semodule -lfull >/dev/null 2>&1; then
    report_ok "semodule_callable" "semodule -lfull returned 0"
  else
    report_fail "semodule_callable" \
      "semodule -lfull returned non-zero from sysadm_t"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool stat
  verify_runtime_mode
  verify_selinux_config
  verify_cil_dir
  verify_packages
  verify_semodule_callable
  exit "${fail_state}"
}

main "$@"
