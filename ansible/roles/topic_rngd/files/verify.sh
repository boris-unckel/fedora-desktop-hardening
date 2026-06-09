#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_rngd.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/rngd.md. Liveness uses /proc, never `kill -0`,
# so the script reports correctly when run from a non-privileged context
# against the daemon-uid-owned long-running process. The AVC-clean,
# SECCOMP-clean, and CIL-module-presence checks are gated behind a
# sysadm_t domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="rngd.service"
readonly EXPECTED_DOMAIN="rngd_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_PROTECT_SYSTEM="full"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_UID="2"
readonly EXPECTED_GID="2"
readonly REQUIRED_PACKAGE="rng-tools"
readonly EXPECTED_CIL_MODULE="nnp_rngd"
readonly BINARY_PATH="/usr/bin/rngd"
readonly ENTROPY_AVAIL_PATH="/proc/sys/kernel/random/entropy_avail"
readonly EXPECTED_FCONTEXT="rngd_exec_t"
readonly EXPECTED_CAPS_SORTED="cap_setgid cap_setuid cap_sys_admin"
readonly EXPECTED_RAF_SOURCE_ORDER="AF_UNIX AF_NETLINK"
declare -ri EXPECTED_SCF_LENGTH_MIN=1500
readonly -a EXPECTED_SCF_ANCHOR_TOKENS=(
  setgroups
  setuid
  capset
  epoll_wait
  recvfrom
)
readonly -a EXPECTED_INIT_SOURCE_TOKENS=(
  hwrng
  rdrand
  jitter
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
  local token
  for token in "${EXPECTED_SCF_ANCHOR_TOKENS[@]}"; do
    if printf '%s' "${raw}" | grep -qw "${token}"; then
      report_ok "scf_anchor_${token}" "present"
    else
      report_fail "scf_anchor_${token}" "missing from resolved filter"
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

verify_live_uid_gid() {
  local pid uid gid
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "live_uid_gid" "no MainPID"
    return
  fi
  uid=$(awk '/^Uid:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "?")
  gid=$(awk '/^Gid:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "?")
  if [[ "${uid}" == "${EXPECTED_UID}" ]]; then
    report_ok "live_uid" "${uid}"
  else
    report_fail "live_uid" \
      "expected=${EXPECTED_UID} actual=${uid} (privilege drop incomplete)"
  fi
  if [[ "${gid}" == "${EXPECTED_GID}" ]]; then
    report_ok "live_gid" "${gid}"
  else
    report_fail "live_gid" \
      "expected=${EXPECTED_GID} actual=${gid} (privilege drop incomplete)"
  fi
}

verify_fcontext() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_${BINARY_PATH##*/}" "matchpathcon not available"
    return
  fi
  local out
  out=$(matchpathcon "${BINARY_PATH}" 2>/dev/null || true)
  if printf '%s' "${out}" | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_${BINARY_PATH##*/}" "${EXPECTED_FCONTEXT}"
  else
    report_fail "fcontext_${BINARY_PATH##*/}" \
      "expected=${EXPECTED_FCONTEXT} actual='${out}'"
  fi
}

verify_entropy_pool() {
  if [[ ! -r "${ENTROPY_AVAIL_PATH}" ]]; then
    report_fail "entropy_avail" "not readable: ${ENTROPY_AVAIL_PATH}"
    return
  fi
  local raw
  raw=$(cat "${ENTROPY_AVAIL_PATH}" 2>/dev/null || true)
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    report_ok "entropy_avail" "${raw}"
  else
    report_fail "entropy_avail" "non-integer: '${raw}'"
  fi
}

verify_journal_privilege_drop() {
  if ! command -v journalctl >/dev/null 2>&1; then
    report_fail "journal_dropped_to" "journalctl not available"
    return
  fi
  local hits
  hits=$(journalctl -u "${UNIT}" -b --no-pager 2>/dev/null \
           | grep -cE 'dropped to' || true)
  if (( hits >= 1 )); then
    report_ok "journal_dropped_to" "${hits} match(es)"
  else
    report_fail "journal_dropped_to" \
      "no 'dropped to' line since boot (privilege drop did not log)"
  fi
}

verify_journal_source_initialized() {
  if ! command -v journalctl >/dev/null 2>&1; then
    report_fail "journal_init_source" "journalctl not available"
    return
  fi
  local hits=0
  local journal
  journal=$(journalctl -u "${UNIT}" -b --no-pager 2>/dev/null || true)
  local token
  for token in "${EXPECTED_INIT_SOURCE_TOKENS[@]}"; do
    if printf '%s\n' "${journal}" \
         | grep -E "(\[${token}\]:|${token}.*Initialized)" \
         | grep -q 'Initialized'; then
      hits=$((hits + 1))
    fi
  done
  if (( hits >= 1 )); then
    report_ok "journal_init_source" "${hits}/${#EXPECTED_INIT_SOURCE_TOKENS[@]} sources Initialized"
  else
    report_fail "journal_init_source" \
      "no entropy source reported Initialized since boot"
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
           | grep -cE '(rngd_t|nnp_transition|rngd)' \
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
  local records hit_lines fields
  records=$(ausearch -m seccomp -ts boot 2>/dev/null \
              | grep 'comm="rngd"' || true)
  if [[ -z "${records}" ]]; then
    report_ok "seccomp_clean" "0 hits"
    return
  fi
  hit_lines=$(printf '%s\n' "${records}" | wc -l | tr -d ' ')
  fields=$(printf '%s\n' "${records}" \
            | grep -oE '(syscall|uid|gid)=[^ ]+' \
            | sort -u \
            | tr '\n' ' ')
  report_fail "seccomp_clean" \
    "${hit_lines} hit(s) since boot; fields: ${fields}"
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool systemctl
  verify_package
  verify_unit_active
  verify_liveness
  verify_property "NoNewPrivileges" "NoNewPrivileges" "${EXPECTED_NNP}"
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_capability_bounding_set
  verify_restrict_address_families
  verify_system_call_filter
  verify_property "SystemCallArchitectures" "SystemCallArchitectures" \
    "${EXPECTED_SYSCALL_ARCH}"
  verify_property "ProtectSystem" "ProtectSystem" \
    "${EXPECTED_PROTECT_SYSTEM}"
  verify_selinux_domain
  verify_live_uid_gid
  verify_fcontext
  verify_entropy_pool
  verify_journal_privilege_drop
  verify_journal_source_initialized
  verify_cil_module
  verify_avc_clean
  verify_seccomp_clean
  exit "${fail_state}"
}

main "$@"
