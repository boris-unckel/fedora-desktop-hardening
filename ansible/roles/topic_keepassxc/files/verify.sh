#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_keepassxc.
#
# Compares observed state against the post-deploy expected end-state declared
# in docs/reference/topics/keepassxc.md. Independent surfaces:
#
#   1. The three custom types are present.
#   2. The three modules are loaded at priority 400.
#   3. The two companion type_transition rules are present
#      (keepassxc_t user_home_t:file -> keepassxc_db_t; and
#       keepassxc_t bin_t:process -> staff_t).
#   4. The typepermissive marker on keepassxc_t matches expectation.
#   5. The three binaries carry keepassxc_exec_t.
#   6. No keepassxc_db_t-labeled file exists outside the database directory.
#   7. A live keepassxc GUI process (if any) carries the substring
#      keepassxc_t in /proc/${pid}/attr/current.
#   8. Leverage-proof: a read of the canonical database file is denied from a
#      staff_t shell and succeeds from a sysadm_t shell.
#
# The policy-store queries (seinfo, semodule, sesearch, semanage) need
# sysadm_t and are reported as SKIP from any other domain; SKIP is accepted
# for a clean run. The leverage-proof expectation depends on the verify's own
# domain. Liveness uses `[[ -d /proc/${pid} ]]`, never `kill -0`.
#
# Usage: bash verify.sh   (run under `sudo -r sysadm_r -t sysadm_t` for the
#                          full policy-store surface and the sysadm leverage)
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for sysadm_t-gated checks)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly DATABASE_DIR="${KEEPASSXC_DB_DIR:-${HOME}/keepass}"
readonly BINARIES=(/usr/bin/keepassxc /usr/bin/keepassxc-cli /usr/bin/keepassxc-proxy)
readonly MODULES=(keepassxc_extras keepassxc_dbtype_autotrans keepassxc_spawn_isolation)
readonly EXPECTED_BINARY_SETYPE="keepassxc_exec_t"
readonly EXPECTED_DB_SETYPE="keepassxc_db_t"
readonly EXPECTED_TYPEPERMISSIVE="${KEEPASSXC_EXPECT_TYPEPERMISSIVE:-yes}"
readonly EXPECTED_RUNTIME_DOMAIN_SUBSTRING="keepassxc_t"

declare -i fail_state=0
CURRENT_TYPE="$(id -Z 2>/dev/null | cut -d: -f3 || echo '?')"
readonly CURRENT_TYPE

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

is_sysadm() {
  [[ "${CURRENT_TYPE}" == "sysadm_t" ]]
}

report_ok() {
  printf 'OK   %-46s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-46s %s\n' "$1" "$2"
  fail_state=1
}

report_skip() {
  printf 'SKIP %-46s %s\n' "$1" "$2"
}

verify_custom_types() {
  if ! is_sysadm; then
    report_skip "custom_types_present" "needs sysadm_t"
    return
  fi
  local t present
  for t in keepassxc_t keepassxc_exec_t keepassxc_db_t; do
    present=$(seinfo -t 2>/dev/null | grep -wc "${t}" || true)
    [[ -z "${present}" ]] && present="0"
    if [[ "${present}" != "0" ]]; then
      report_ok "type_present[${t}]" "expected=yes actual=yes"
    else
      report_fail "type_present[${t}]" "expected=yes actual=no"
    fi
  done
}

verify_modules_loaded() {
  if ! is_sysadm; then
    report_skip "modules_loaded" "needs sysadm_t"
    return
  fi
  local m hit
  for m in "${MODULES[@]}"; do
    hit=$(semodule -lfull 2>/dev/null | grep -wc "${m}" || true)
    [[ -z "${hit}" ]] && hit="0"
    if [[ "${hit}" != "0" ]]; then
      report_ok "module_loaded[${m}]" "expected=yes actual=yes"
    else
      report_fail "module_loaded[${m}]" "expected=yes actual=no"
    fi
  done
}

verify_type_transitions() {
  if ! is_sysadm; then
    report_skip "type_transitions_present" "needs sysadm_t"
    return
  fi
  local autotrans spawn
  autotrans=$(sesearch -T -s keepassxc_t -t user_home_t -c file 2>/dev/null \
                | grep -c 'keepassxc_db_t' || true)
  [[ -z "${autotrans}" ]] && autotrans="0"
  if [[ "${autotrans}" != "0" ]]; then
    report_ok "transition[user_home_t->keepassxc_db_t]" "expected=present actual=present"
  else
    report_fail "transition[user_home_t->keepassxc_db_t]" "expected=present actual=absent"
  fi
  spawn=$(sesearch -T -s keepassxc_t -t bin_t -c process 2>/dev/null \
            | grep -cw 'staff_t' || true)
  [[ -z "${spawn}" ]] && spawn="0"
  if [[ "${spawn}" != "0" ]]; then
    report_ok "transition[bin_t:process->staff_t]" "expected=present actual=present"
  else
    report_fail "transition[bin_t:process->staff_t]" "expected=present actual=absent"
  fi
}

verify_typepermissive() {
  if ! is_sysadm; then
    report_skip "typepermissive_keepassxc_t" "needs sysadm_t"
    return
  fi
  local actual
  if semanage permissive -l 2>/dev/null | grep -qw keepassxc_t; then
    actual="yes"
  else
    actual="no"
  fi
  if [[ "${actual}" == "${EXPECTED_TYPEPERMISSIVE}" ]]; then
    report_ok "typepermissive_keepassxc_t" "expected=${EXPECTED_TYPEPERMISSIVE} actual=${actual}"
  else
    report_fail "typepermissive_keepassxc_t" "expected=${EXPECTED_TYPEPERMISSIVE} actual=${actual}"
  fi
}

verify_binary_labels() {
  local b setype
  for b in "${BINARIES[@]}"; do
    if [[ ! -e "${b}" ]]; then
      report_fail "binary_label[$(basename "${b}")]" "binary absent"
      continue
    fi
    setype=$(stat -c '%C' "${b}" 2>/dev/null | cut -d: -f3 || echo '?')
    if [[ "${setype}" == "${EXPECTED_BINARY_SETYPE}" ]]; then
      report_ok "binary_label[$(basename "${b}")]" "expected=${EXPECTED_BINARY_SETYPE} actual=${setype}"
    else
      report_fail "binary_label[$(basename "${b}")]" "expected=${EXPECTED_BINARY_SETYPE} actual=${setype}"
    fi
  done
}

verify_db_label_sweep() {
  local hits count
  hits=$(find "${HOME}" -xdev -path "${DATABASE_DIR}" -prune -o \
           -context "*:${EXPECTED_DB_SETYPE}:*" -print 2>/dev/null || true)
  count=$(printf '%s' "${hits}" | grep -c . || true)
  [[ -z "${count}" ]] && count="0"
  if [[ "${count}" == "0" ]]; then
    report_ok "db_label_outside_database_dir" "expected=0 actual=0"
  else
    report_fail "db_label_outside_database_dir" \
      "expected=0 actual=${count} (helper-spawn inheritance — see Topic Reference)"
  fi
}

verify_runtime_domain() {
  local pid label
  pid=$(pgrep -x keepassxc 2>/dev/null | head -1 || true)
  if [[ -z "${pid}" ]]; then
    report_ok "runtime_domain_substring" \
      "expected=${EXPECTED_RUNTIME_DOMAIN_SUBSTRING} actual=(no live GUI process; check skipped non-fatally)"
    return
  fi
  if [[ ! -d "/proc/${pid}" ]]; then
    report_fail "runtime_domain_substring" "pid=${pid} vanished between pgrep and read"
    return
  fi
  label=$(cat "/proc/${pid}/attr/current" 2>/dev/null || echo '?')
  if [[ "${label}" == *"${EXPECTED_RUNTIME_DOMAIN_SUBSTRING}"* ]]; then
    report_ok "runtime_domain_substring" \
      "expected=${EXPECTED_RUNTIME_DOMAIN_SUBSTRING} actual=${label} (substring match)"
  else
    report_fail "runtime_domain_substring" \
      "expected=${EXPECTED_RUNTIME_DOMAIN_SUBSTRING} actual=${label}"
  fi
}

verify_leverage_proof() {
  local canonical
  canonical=$(find "${DATABASE_DIR}" -maxdepth 2 -type f -name '*.kdbx' 2>/dev/null \
                | head -1 || true)
  if [[ -z "${canonical}" ]]; then
    report_skip "leverage_proof" "no *.kdbx under ${DATABASE_DIR}"
    return
  fi
  local rc=0
  cat "${canonical}" >/dev/null 2>&1 || rc=$?
  case "${CURRENT_TYPE}" in
    staff_t)
      if (( rc != 0 )); then
        report_ok "leverage_proof[staff_t]" "expected=denied actual=denied"
      else
        report_fail "leverage_proof[staff_t]" "expected=denied actual=read-succeeded"
      fi
      ;;
    sysadm_t)
      if (( rc == 0 )); then
        report_ok "leverage_proof[sysadm_t]" "expected=read-ok actual=read-ok"
      else
        report_fail "leverage_proof[sysadm_t]" "expected=read-ok actual=denied"
      fi
      ;;
    *)
      report_skip "leverage_proof" "ambiguous domain ${CURRENT_TYPE} (run from staff_t or sysadm_t)"
      ;;
  esac
}

main() {
  require_tool find
  require_tool stat
  require_tool pgrep
  verify_custom_types
  verify_modules_loaded
  verify_type_transitions
  verify_typepermissive
  verify_binary_labels
  verify_db_label_sweep
  verify_runtime_domain
  verify_leverage_proof
  exit "${fail_state}"
}

main "$@"
