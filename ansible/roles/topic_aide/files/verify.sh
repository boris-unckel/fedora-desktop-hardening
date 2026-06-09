#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_aide.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/aide.md. The service is Type=oneshot and has
# no MainPID between runs, so there is no liveness check on the service;
# the verify script asserts the timer's active+enabled state instead.
# The CIL-module-presence, three-rule sesearch, and AVC-clean checks are
# gated behind a sysadm_t domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for sysadm_t-gated checks)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly TIMER_UNIT="aide-check.timer"
readonly SERVICE_UNIT="aide-check.service"
readonly UNIT_DIR="/etc/systemd/system"
readonly EXPECTED_TIMER_ACTIVE="active"
readonly EXPECTED_TIMER_ENABLED="enabled"
readonly REQUIRED_PACKAGE="aide"
readonly EXPECTED_CIL_MODULE="aide_extras"
readonly EXPECTED_DOMAIN="aide_t"
readonly DB_PATH="/var/lib/aide/aide.db.gz"
readonly EXPECTED_DB_MODE="600"
readonly EXPECTED_DB_OWNER="root"
readonly EXPECTED_DB_GROUP="root"
readonly EXPECTED_DB_SELTYPE="aide_db_t"
readonly CONF_PATH="/etc/aide.conf"
readonly EXPECTED_CONF_MODE="600"
readonly EXPECTED_CONF_OWNER="root"
readonly EXPECTED_CONF_GROUP="root"
readonly EXPECTED_CONF_SELTYPE="etc_t"
readonly EXPECTED_UNIT_MODE="644"
readonly EXPECTED_UNIT_OWNER="root"
readonly EXPECTED_UNIT_GROUP="root"
readonly EXPECTED_UNIT_SELTYPE="systemd_unit_file_t"
readonly EXPECTED_FCONTEXT="aide_exec_t"
readonly BINARY_CANONICAL="/usr/bin/aide"
readonly BINARY_PRE_MERGE="/usr/sbin/aide"
readonly SCOPE_MARKER="topic_aide scope tuning (managed)"
readonly BANNER_PATH="/etc/profile.d/aide-alert.sh"
readonly BANNER_ACK_MARKER="_aide_mono"

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

verify_timer_active() {
  local actual
  actual=$(systemctl is-active "${TIMER_UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "${EXPECTED_TIMER_ACTIVE}" ]]; then
    report_ok "timer_active" "${actual}"
  else
    report_fail "timer_active" \
      "expected=${EXPECTED_TIMER_ACTIVE} actual=${actual:-<empty>}"
  fi
}

verify_timer_enabled() {
  local actual
  actual=$(systemctl is-enabled "${TIMER_UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "${EXPECTED_TIMER_ENABLED}" ]]; then
    report_ok "timer_enabled" "${actual}"
  else
    report_fail "timer_enabled" \
      "expected=${EXPECTED_TIMER_ENABLED} actual=${actual:-<empty>}"
  fi
}

verify_file_triplet() {
  local label="$1"
  local path="$2"
  local expected_mode="$3"
  local expected_owner="$4"
  local expected_group="$5"
  local expected_seltype="$6"
  if [[ ! -e "${path}" ]]; then
    report_fail "${label}" "missing: ${path}"
    return
  fi
  local mode owner group label_str seltype
  mode=$(stat -c '%a' "${path}" 2>/dev/null || true)
  owner=$(stat -c '%U' "${path}" 2>/dev/null || true)
  group=$(stat -c '%G' "${path}" 2>/dev/null || true)
  label_str=$(stat -c '%C' "${path}" 2>/dev/null || true)
  seltype=$(printf '%s' "${label_str}" | awk -F: '{print $3}')
  local triplet_ok=1
  if [[ "${mode}" != "${expected_mode}" ]]; then
    report_fail "${label}_mode" \
      "expected=${expected_mode} actual=${mode}"
    triplet_ok=0
  fi
  if [[ "${owner}" != "${expected_owner}" \
        || "${group}" != "${expected_group}" ]]; then
    report_fail "${label}_owner" \
      "expected=${expected_owner}:${expected_group} actual=${owner}:${group}"
    triplet_ok=0
  fi
  if [[ "${seltype}" != "${expected_seltype}" ]]; then
    report_fail "${label}_seltype" \
      "expected=${expected_seltype} actual=${seltype}"
    triplet_ok=0
  fi
  if (( triplet_ok == 1 )); then
    report_ok "${label}" \
      "mode=${mode} owner=${owner}:${group} seltype=${seltype}"
  fi
}

verify_database_present() {
  if [[ -f "${DB_PATH}" ]]; then
    report_ok "db_present" "${DB_PATH}"
  else
    report_fail "db_present" "missing: ${DB_PATH}"
  fi
}

verify_fcontext() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_aide" "matchpathcon not available"
    return
  fi
  local out_canonical out_pre_merge
  out_canonical=$(matchpathcon "${BINARY_CANONICAL}" 2>/dev/null || true)
  out_pre_merge=$(matchpathcon "${BINARY_PRE_MERGE}" 2>/dev/null || true)
  if printf '%s\n%s\n' "${out_canonical}" "${out_pre_merge}" \
       | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_aide" \
      "${EXPECTED_FCONTEXT} (canonical='${out_canonical}' pre-merge='${out_pre_merge}')"
  else
    report_fail "fcontext_aide" \
      "neither path resolved to ${EXPECTED_FCONTEXT}; canonical='${out_canonical}' pre-merge='${out_pre_merge}'"
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
  hits=$(semodule -l 2>/dev/null | grep -cx "${EXPECTED_CIL_MODULE}" || true)
  if [[ "${hits}" == "1" ]]; then
    report_ok "cil_${EXPECTED_CIL_MODULE}" "loaded"
  else
    report_fail "cil_${EXPECTED_CIL_MODULE}" \
      "expected=1 line actual=${hits}"
  fi
}

verify_cil_rule() {
  local label="$1"
  local source_type="$2"
  local target_type="$3"
  local class="$4"
  local perm="$5"
  if ! is_sysadm_t; then
    report_skip "${label}" "needs sysadm_t"
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    report_fail "${label}" "sesearch not available"
    return
  fi
  local out
  out=$(sesearch -A -s "${source_type}" -t "${target_type}" \
                 -c "${class}" -p "${perm}" 2>/dev/null || true)
  if [[ -n "${out}" ]]; then
    report_ok "${label}" "allow rule present"
  else
    report_fail "${label}" \
      "no allow rule for ${source_type} -> ${target_type} : ${class} ${perm}"
  fi
}

verify_scope_block() {
  # /etc/aide.conf is mode 0600 root:root; reading it needs sysadm_t.
  if ! is_sysadm_t; then
    report_skip "scope_block_marker" "needs sysadm_t"
    return
  fi
  if [[ ! -r "${CONF_PATH}" ]]; then
    report_fail "scope_block_marker" "not readable: ${CONF_PATH}"
    return
  fi
  if grep -qF "${SCOPE_MARKER}" "${CONF_PATH}"; then
    report_ok "scope_block_marker" "present"
  else
    report_fail "scope_block_marker" "absent in ${CONF_PATH}"
  fi
}

verify_config_check() {
  # aide --config-check reads /etc/aide.conf (0600 root:root); needs sysadm_t.
  if ! is_sysadm_t; then
    report_skip "config_check" "needs sysadm_t"
    return
  fi
  if ! command -v aide >/dev/null 2>&1; then
    report_fail "config_check" "aide not available"
    return
  fi
  if aide --config-check >/dev/null 2>&1; then
    report_ok "config_check" "clean parse"
  else
    report_fail "config_check" "aide --config-check reported a parse error"
  fi
}

verify_banner_ack() {
  # The banner is 0644 bin_t and readable from staff_t. The artefact is
  # opt-in; SKIP when it is not installed (topic_aide_install_alert_banner
  # set to false), FAIL only when an installed banner lacks the ack block.
  if [[ ! -f "${BANNER_PATH}" ]]; then
    report_skip "banner_ack_block" "banner not installed (opt-out)"
    return
  fi
  if grep -qF "${BANNER_ACK_MARKER}" "${BANNER_PATH}"; then
    report_ok "banner_ack_block" "present"
  else
    report_fail "banner_ack_block" \
      "installed banner lacks ${BANNER_ACK_MARKER} (pre-ack banner)"
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
           | grep -cE '(aide_t|aide_exec_t|aide_db_t|aide_log_t|aide_conf_t)' \
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
  require_tool stat
  require_tool systemctl
  verify_package
  verify_timer_active
  verify_timer_enabled
  verify_file_triplet "service_unit" \
    "${UNIT_DIR}/${SERVICE_UNIT}" \
    "${EXPECTED_UNIT_MODE}" \
    "${EXPECTED_UNIT_OWNER}" \
    "${EXPECTED_UNIT_GROUP}" \
    "${EXPECTED_UNIT_SELTYPE}"
  verify_file_triplet "timer_unit" \
    "${UNIT_DIR}/${TIMER_UNIT}" \
    "${EXPECTED_UNIT_MODE}" \
    "${EXPECTED_UNIT_OWNER}" \
    "${EXPECTED_UNIT_GROUP}" \
    "${EXPECTED_UNIT_SELTYPE}"
  verify_database_present
  verify_file_triplet "db_file" \
    "${DB_PATH}" \
    "${EXPECTED_DB_MODE}" \
    "${EXPECTED_DB_OWNER}" \
    "${EXPECTED_DB_GROUP}" \
    "${EXPECTED_DB_SELTYPE}"
  verify_file_triplet "conf_file" \
    "${CONF_PATH}" \
    "${EXPECTED_CONF_MODE}" \
    "${EXPECTED_CONF_OWNER}" \
    "${EXPECTED_CONF_GROUP}" \
    "${EXPECTED_CONF_SELTYPE}"
  verify_fcontext
  verify_cil_module
  verify_cil_rule "cil_rule_dosfs" \
    "${EXPECTED_DOMAIN}" "dosfs_t" "filesystem" "getattr"
  verify_cil_rule "cil_rule_xdm_sock" \
    "${EXPECTED_DOMAIN}" "xdm_var_run_t" "sock_file" "write"
  verify_cil_rule "cil_rule_xdm_connectto" \
    "${EXPECTED_DOMAIN}" "xdm_t" "unix_stream_socket" "connectto"
  verify_scope_block
  verify_config_check
  verify_banner_ack
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
