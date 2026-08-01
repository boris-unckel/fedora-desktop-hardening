#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_cron.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/cron.md. Liveness uses /proc, never `kill -0`,
# so the script reports correctly when run from a non-privileged context
# against the daemon's root-owned MainPID. The CIL-module-presence,
# AVC-clean, and SECCOMP-clean checks are gated behind a sysadm_t domain
# check and reported as SKIP from staff_t. The cronjob-spawn domain
# assertion writes a one-minute test cronjob and removes it at end-of-run.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP accepted for sysadm_t-gated checks)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="crond.service"
readonly EXPECTED_DOMAIN="crond_t"
readonly EXPECTED_CRONJOB_DOMAIN="system_cronjob_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_PROTECT_SYSTEM="full"
readonly EXPECTED_PROTECT_HOME="yes"
readonly EXPECTED_PROTECT_KERNEL_TUNABLES="yes"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="yes"
readonly EXPECTED_PRIVATE_TMP="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_HOSTNAME="yes"
readonly EXPECTED_LOCK_PERSONALITY="yes"
readonly EXPECTED_RESTRICT_REALTIME="yes"
readonly EXPECTED_RESTRICT_SUID_SGID="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_RAF_SOURCE_ORDER="AF_UNIX AF_INET AF_INET6 AF_NETLINK"
readonly EXPECTED_CAPS_SORTED="cap_dac_read_search cap_setgid cap_setuid"
readonly EXPECTED_FCONTEXT="crond_exec_t"
readonly REQUIRED_PACKAGE="cronie"
readonly EXPECTED_CIL_MODULE="nnp_crond"
readonly BINARY_CANONICAL="/usr/bin/crond"
readonly BINARY_PRE_MERGE="/usr/sbin/crond"
readonly TEST_CRONJOB_PATH="/etc/cron.d/diataxis-verify-test"
readonly TEST_CRONJOB_OUT="/run/diataxis-verify-cron.out"
declare -ri EXPECTED_SCF_LENGTH_MIN=200
# @class / ~@class tokens only survive in the raw merged unit; systemctl
# show -p SystemCallFilter --value expands them to a concrete syscall list.
# Class tokens are checked against `systemctl cat`; concrete anchors against
# the resolved value.
readonly -a EXPECTED_SCF_CLASS_TOKENS=(
  "@system-service"
  "~@privileged"
)
readonly -a EXPECTED_SCF_ANCHOR_TOKENS=(
  setresuid
  setgroups
)
declare -ri CRONJOB_WAIT_SECONDS=90

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/crond.service.d"
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

verify_unit_active() {
  local actual
  actual=$(systemctl is-active "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "active" ]]; then
    report_ok "unit_${UNIT%.service}" "${actual}"
  else
    report_fail "unit_${UNIT%.service}" \
      "expected=active actual=${actual:-<empty>}"
  fi
}

read_main_pid() {
  systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0
}

verify_liveness() {
  # /proc, not `kill -0`: kill -0 from a non-privileged context against a
  # foreign uid returns EPERM, not ESRCH, and would falsely report a live
  # daemon as dead.
  local pid
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_fail "liveness" "pid=${pid} not present"
    return
  fi
  report_ok "liveness" "pid=${pid}"
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

verify_capability_bounding_set() {
  local raw normalised
  raw=$(systemctl show -p CapabilityBoundingSet --value "${UNIT}" 2>/dev/null \
          || true)
  if [[ -z "${raw}" ]]; then
    report_fail "cap_bounding_set" "empty (no resolved bounding set read)"
    return
  fi
  normalised=$(printf '%s\n' "${raw}" \
                | tr '[:upper:]' '[:lower:]' \
                | tr -s '[:space:]' '\n' \
                | grep -v '^$' \
                | sort \
                | tr '\n' ' ' \
                | sed 's/ *$//')
  if [[ "${normalised}" == "${EXPECTED_CAPS_SORTED}" ]]; then
    report_ok "cap_bounding_set" "${normalised}"
  else
    report_fail "cap_bounding_set" \
      "expected='${EXPECTED_CAPS_SORTED}' actual='${normalised}'"
  fi
}

verify_restrict_address_families() {
  # systemctl renders the families alphabetically, which need not match the
  # source order written in the drop-in; compare as a case-insensitive set,
  # mirroring verify_capability_bounding_set. The security intent is set
  # membership, not token order.
  local raw observed expected
  raw=$(systemctl show -p RestrictAddressFamilies --value "${UNIT}" 2>/dev/null \
          || true)
  observed=$(printf '%s\n' "${raw}" \
               | tr '[:upper:]' '[:lower:]' \
               | tr -s '[:space:]' '\n' \
               | grep -v '^$' \
               | sort \
               | tr '\n' ' ' \
               | sed 's/ *$//')
  expected=$(printf '%s\n' "${EXPECTED_RAF_SOURCE_ORDER}" \
               | tr '[:upper:]' '[:lower:]' \
               | tr -s '[:space:]' '\n' \
               | grep -v '^$' \
               | sort \
               | tr '\n' ' ' \
               | sed 's/ *$//')
  if [[ "${observed}" == "${expected}" ]]; then
    report_ok "restrict_address_families" "${raw}"
  else
    report_fail "restrict_address_families" \
      "expected set='${EXPECTED_RAF_SOURCE_ORDER}' actual='${raw}'"
  fi
}

verify_system_call_filter() {
  local raw
  raw=$(systemctl show -p SystemCallFilter --value "${UNIT}" 2>/dev/null \
          || true)
  if [[ -z "${raw}" ]]; then
    report_fail "scf_length" "empty (no resolved filter read)"
    return
  fi
  local len
  len=${#raw}
  if (( len < EXPECTED_SCF_LENGTH_MIN )); then
    report_fail "scf_length" \
      "expected_min=${EXPECTED_SCF_LENGTH_MIN} actual=${len}"
  else
    report_ok "scf_length" "len=${len}"
  fi
  # Concrete syscall anchors are present in the resolved (expanded) value.
  local token
  for token in "${EXPECTED_SCF_ANCHOR_TOKENS[@]}"; do
    if printf '%s' "${raw}" | grep -qF -- "${token}"; then
      report_ok "scf_anchor_${token}" "present"
    else
      report_fail "scf_anchor_${token}" "missing from resolved filter"
    fi
  done
  # @class / ~@class tokens are expanded away in the resolved value; read the
  # raw merged unit to assert them.
  local cat_out
  cat_out=$(systemctl cat "${UNIT}" 2>/dev/null || true)
  for token in "${EXPECTED_SCF_CLASS_TOKENS[@]}"; do
    if grep -qF -- "${token}" <<<"${cat_out}"; then
      report_ok "scf_class_${token}" "present"
    else
      report_fail "scf_class_${token}" "missing from merged unit"
    fi
  done
}

verify_selinux_domain() {
  local pid domain
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "selinux_domain" "no MainPID"
    return
  fi
  domain=$(awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null \
           || echo "?")
  if [[ "${domain}" == "${EXPECTED_DOMAIN}" ]]; then
    report_ok "selinux_domain" "${domain}"
  else
    report_fail "selinux_domain" \
      "expected=${EXPECTED_DOMAIN} actual=${domain}"
  fi
}

verify_fcontext() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_crond" "matchpathcon not available"
    return
  fi
  local out_canonical out_pre_merge
  out_canonical=$(matchpathcon "${BINARY_CANONICAL}" 2>/dev/null || true)
  out_pre_merge=$(matchpathcon "${BINARY_PRE_MERGE}" 2>/dev/null || true)
  if printf '%s\n%s\n' "${out_canonical}" "${out_pre_merge}" \
       | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_crond" \
      "${EXPECTED_FCONTEXT} (canonical='${out_canonical}' pre-merge='${out_pre_merge}')"
  else
    report_fail "fcontext_crond" \
      "neither path resolved to ${EXPECTED_FCONTEXT}; canonical='${out_canonical}' pre-merge='${out_pre_merge}'"
  fi
}

cleanup_test_cronjob() {
  if [[ -f "${TEST_CRONJOB_PATH}" ]]; then
    rm -f "${TEST_CRONJOB_PATH}" 2>/dev/null || true
  fi
  if [[ -f "${TEST_CRONJOB_OUT}" ]]; then
    rm -f "${TEST_CRONJOB_OUT}" 2>/dev/null || true
  fi
}

verify_cronjob_spawn_domain() {
  if ! is_sysadm_t; then
    report_skip "cronjob_spawn_domain" "needs sysadm_t (write under /etc/cron.d/)"
    return
  fi
  cleanup_test_cronjob
  local content="* * * * * root /usr/bin/cat /proc/self/attr/current > ${TEST_CRONJOB_OUT} 2>/dev/null"
  if ! printf '%s\n' "${content}" >"${TEST_CRONJOB_PATH}" 2>/dev/null; then
    report_fail "cronjob_spawn_domain" "could not write ${TEST_CRONJOB_PATH}"
    return
  fi
  chmod 0644 "${TEST_CRONJOB_PATH}" 2>/dev/null || true
  chown root:root "${TEST_CRONJOB_PATH}" 2>/dev/null || true

  local -i waited=0
  while (( waited < CRONJOB_WAIT_SECONDS )); do
    if [[ -s "${TEST_CRONJOB_OUT}" ]]; then
      break
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done

  if [[ ! -s "${TEST_CRONJOB_OUT}" ]]; then
    report_fail "cronjob_spawn_domain" \
      "no output within ${CRONJOB_WAIT_SECONDS}s; cronjob did not run"
    cleanup_test_cronjob
    return
  fi

  local domain
  domain=$(awk -F: '{print $3}' "${TEST_CRONJOB_OUT}" 2>/dev/null || echo "?")
  if [[ "${domain}" == "${EXPECTED_CRONJOB_DOMAIN}" ]]; then
    report_ok "cronjob_spawn_domain" "${domain}"
  else
    report_fail "cronjob_spawn_domain" \
      "expected=${EXPECTED_CRONJOB_DOMAIN} actual=${domain} (CIL rule 2 not in effect)"
  fi
  cleanup_test_cronjob
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
  hits=$(semodule -l 2>/dev/null | grep -cw "${EXPECTED_CIL_MODULE}" || true)
  if [[ "${hits}" == "1" ]]; then
    report_ok "cil_${EXPECTED_CIL_MODULE}" "loaded"
  else
    report_fail "cil_${EXPECTED_CIL_MODULE}" \
      "expected=1 line actual=${hits}"
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
           | grep -cE '(crond_t|crond_exec_t|crond_log_t|cron_spool_t|system_cronjob_t|nnp_transition)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
  fi
}

verify_seccomp_clean() {
  if ! is_sysadm_t; then
    report_skip "seccomp_clean" "needs sysadm_t"
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    report_fail "seccomp_clean" "ausearch not available"
    return
  fi
  local hits
  hits=$(ausearch -m seccomp -ts boot 2>/dev/null \
           | grep -cE '(comm="crond"|exe="/usr/sbin/crond"|exe="/usr/bin/crond")' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "seccomp_clean" "0 hits"
  else
    report_fail "seccomp_clean" "${hits} hits since boot"
  fi
}

# Expected context for one path, honouring the file-type qualifier carried by
# file_contexts entries. A `--` entry matches regular files only, so a
# directory or a symlink at the same path resolves through a different rule;
# without the mode hint the comparison tests against the wrong expectation.
#
# The type comes from `stat`, not from `[[ -d ]]`/`[[ -L ]]`: those operators
# report false when the path cannot be stat'ed, which would silently fall
# through to the regular-file rule and produce a plausible wrong answer.
# LC_ALL=C because `%F` is localised.
expected_context() {
  local path="$1" mode ftype
  ftype=$(LC_ALL=C stat -c '%F' "${path}" 2>/dev/null) || return 1
  case "${ftype}" in
    *"symbolic link"*) mode="lnk_file" ;;
    "directory") mode="dir" ;;
    *) mode="file" ;;
  esac
  matchpathcon -m "${mode}" "${path}" 2>/dev/null | sed 's#.*\t##'
}

# Compares the full context, including the SELinux user field. `restorecon -n`
# compares the type alone, so a path differing only in the user field stays
# invisible to it and to any check built on it.
context_matches() {
  local path="$1" expected actual
  actual=$(stat -c '%C' "${path}" 2>/dev/null || true)
  expected=$(expected_context "${path}") || expected=""
  if [[ -z "${expected}" || -z "${actual}" ]]; then
    report_fail "selinux_context" "${path}: context not resolvable"
    return 1
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    report_fail "selinux_context" \
      "${path}: expected=${expected} actual=${actual}"
    return 1
  fi
  return 0
}

verify_selinux_context() {
  local path child drift=0 checked=0
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_skip "selinux_context" "matchpathcon not available"
    return
  fi
  for path in "${CONTEXT_PATHS[@]}"; do
    if [[ ! -e "${path}" ]]; then
      report_fail "selinux_context" "${path}: absent"
      drift=$((drift + 1))
      continue
    fi
    checked=$((checked + 1))
    context_matches "${path}" || drift=$((drift + 1))
    [[ -d "${path}" ]] || continue
    for child in "${path}"/*; do
      [[ -e "${child}" ]] || continue
      checked=$((checked + 1))
      context_matches "${child}" || drift=$((drift + 1))
    done
  done
  if [[ "${drift}" -eq 0 ]]; then
    report_ok "selinux_context" "${checked} paths match file_contexts"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool systemctl
  trap cleanup_test_cronjob EXIT
  verify_package
  verify_unit_active
  verify_liveness
  verify_property "NoNewPrivileges" "NoNewPrivileges" "${EXPECTED_NNP}"
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_property "ProtectSystem" "ProtectSystem" \
    "${EXPECTED_PROTECT_SYSTEM}"
  verify_property "ProtectHome" "ProtectHome" \
    "${EXPECTED_PROTECT_HOME}"
  verify_property "ProtectKernelTunables" "ProtectKernelTunables" \
    "${EXPECTED_PROTECT_KERNEL_TUNABLES}"
  verify_property "ProtectKernelModules" "ProtectKernelModules" \
    "${EXPECTED_PROTECT_KERNEL_MODULES}"
  verify_property "ProtectKernelLogs" "ProtectKernelLogs" \
    "${EXPECTED_PROTECT_KERNEL_LOGS}"
  verify_property "ProtectControlGroups" "ProtectControlGroups" \
    "${EXPECTED_PROTECT_CONTROL_GROUPS}"
  verify_property "PrivateTmp" "PrivateTmp" \
    "${EXPECTED_PRIVATE_TMP}"
  verify_property "ProtectClock" "ProtectClock" \
    "${EXPECTED_PROTECT_CLOCK}"
  verify_property "ProtectHostname" "ProtectHostname" \
    "${EXPECTED_PROTECT_HOSTNAME}"
  verify_property "LockPersonality" "LockPersonality" \
    "${EXPECTED_LOCK_PERSONALITY}"
  verify_property "RestrictRealtime" "RestrictRealtime" \
    "${EXPECTED_RESTRICT_REALTIME}"
  verify_property "RestrictSUIDSGID" "RestrictSUIDSGID" \
    "${EXPECTED_RESTRICT_SUID_SGID}"
  verify_property "SystemCallArchitectures" "SystemCallArchitectures" \
    "${EXPECTED_SYSCALL_ARCH}"
  verify_restrict_address_families
  verify_capability_bounding_set
  verify_system_call_filter
  verify_selinux_domain
  verify_fcontext
  verify_cronjob_spawn_domain
  verify_cil_module
  verify_avc_clean
  verify_seccomp_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
