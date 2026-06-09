#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_avahi_daemon.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/avahi-daemon.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against a foreign-uid PID. The AVC-clean check and
# the CIL-module-presence check are gated behind a sysadm_t domain check
# and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="avahi-daemon.service"
readonly EXPECTED_DOMAIN="avahi_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_PROTECT_SYSTEM="strict"
readonly EXPECTED_PROTECT_HOME="yes"
readonly EXPECTED_PROTECT_KERNEL_TUNABLES="yes"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_HOSTNAME="yes"
readonly EXPECTED_PROTECT_PROC="invisible"
readonly EXPECTED_PROCSUBSET="pid"
readonly EXPECTED_PRIVATE_TMP="yes"
readonly EXPECTED_PRIVATE_DEVICES="yes"
readonly EXPECTED_READ_WRITE_PATHS_SUBSTRING="/run/avahi-daemon"
readonly EXPECTED_RESTRICT_ADDRESS_FAMILIES="AF_INET AF_INET6 AF_UNIX AF_NETLINK"
readonly EXPECTED_RESTRICT_NAMESPACES="yes"
readonly EXPECTED_RESTRICT_REALTIME="yes"
readonly EXPECTED_RESTRICT_SUID_SGID="yes"
readonly EXPECTED_LOCK_PERSONALITY="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
# @class tokens (e.g. @system-service) only appear in the raw merged unit;
# systemctl show -p SystemCallFilter --value expands them into a concrete
# syscall list with no class name. Class tokens are checked against
# `systemctl cat`; the explicit carve-out syscalls against the resolved value.
readonly EXPECTED_SCF_CLASS_TOKENS="@system-service"
readonly EXPECTED_SCF_SYSCALL_SUBSTRINGS="chown fchown lchown chroot"
readonly EXPECTED_CAP_BOUNDING_SET="CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT"
readonly EXPECTED_UMASK="0027"
readonly REQUIRED_PACKAGE="avahi"
readonly EXPECTED_CIL_MODULE="nnp_avahi_daemon"
readonly MDNS_RESOLVE_TIMEOUT_SECONDS=5

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
  printf 'OK   %-32s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-32s %s\n' "$1" "$2"
}

report_warn() {
  printf 'WARN %-32s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-32s %s\n' "$1" "$2"
  fail_state=1
}

normalize_set() {
  # Case-fold, whitespace-normalise, sort, deduplicate, rejoin with single
  # spaces. systemctl renders CapabilityBoundingSet lower-case (cap_chown),
  # so the expected upper-case set must be folded too for an order- and
  # case-insensitive comparison.
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ *$//'
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

verify_liveness() {
  # /proc, not `kill -0`: kill -0 from a non-privileged context against a
  # foreign uid returns EPERM, not ESRCH, and would falsely report a live
  # daemon as dead.
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
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

verify_substring() {
  local label="$1"
  local prop="$2"
  local needle="$3"
  local actual
  actual=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == *"${needle}"* ]]; then
    report_ok "${label}" "contains '${needle}'"
  else
    report_fail "${label}" "missing '${needle}' in '${actual}'"
  fi
}

verify_set_exact() {
  local label="$1"
  local prop="$2"
  local expected_raw="$3"
  local actual_raw
  actual_raw=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  local actual_norm expected_norm
  actual_norm=$(normalize_set "${actual_raw}")
  expected_norm=$(normalize_set "${expected_raw}")
  if [[ "${actual_norm}" == "${expected_norm}" ]]; then
    report_ok "${label}" "${actual_norm}"
  else
    report_fail "${label}" \
      "expected='${expected_norm}' actual='${actual_norm}'"
  fi
}

verify_substring_set() {
  local label="$1"
  local prop="$2"
  local expected_raw="$3"
  local actual
  actual=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  local token missing=""
  for token in ${expected_raw}; do
    if [[ "${actual}" != *"${token}"* ]]; then
      missing="${missing}${token} "
    fi
  done
  if [[ -z "${missing}" ]]; then
    report_ok "${label}" "all tokens present"
  else
    report_fail "${label}" \
      "missing tokens: ${missing% } in '${actual}'"
  fi
}

verify_scf_class_tokens() {
  # @class / ~@class tokens are expanded away by `systemctl show --value`;
  # read the raw merged unit (`systemctl cat`) to assert their presence.
  local cat_out token missing=""
  cat_out=$(systemctl cat "${UNIT}" 2>/dev/null || true)
  for token in ${EXPECTED_SCF_CLASS_TOKENS}; do
    if ! grep -qF -- "${token}" <<<"${cat_out}"; then
      missing="${missing}${token} "
    fi
  done
  if [[ -z "${missing}" ]]; then
    report_ok "SystemCallFilter_class" "all class tokens present"
  else
    report_fail "SystemCallFilter_class" \
      "missing class tokens: ${missing% } from merged unit"
  fi
}

verify_umask() {
  local actual
  actual=$(systemctl show -p UMask --value "${UNIT}" 2>/dev/null || true)
  if [[ "${actual}" == "${EXPECTED_UMASK}" ]]; then
    report_ok "UMask" "${actual}"
    return
  fi
  # Some systemd versions return the decimal form (0027 octal == 23 dec).
  if [[ "${actual}" == "23" ]]; then
    report_ok "UMask" "23 (decimal form of 0027)"
    return
  fi
  report_fail "UMask" "expected='${EXPECTED_UMASK}' actual='${actual}'"
}

verify_selinux_domain() {
  local pid domain
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
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

verify_mdns_multicast_join() {
  if ! command -v journalctl >/dev/null 2>&1; then
    report_fail "mdns_multicast_join" "journalctl not available"
    return
  fi
  local count
  count=$(journalctl -u "${UNIT}" -b 0 --no-pager 2>/dev/null \
            | grep -cF "Joining mDNS multicast group" || true)
  if [[ "${count}" =~ ^[0-9]+$ ]] && (( count >= 1 )); then
    report_ok "mdns_multicast_join" "${count} line(s) since boot"
  else
    report_fail "mdns_multicast_join" \
      "expected>=1 actual=${count}; daemon failed to join any multicast group at boot"
  fi
}

verify_mdns_resolve_roundtrip() {
  if ! command -v avahi-resolve-host-name >/dev/null 2>&1; then
    report_warn "mdns_resolve_roundtrip" "avahi-resolve-host-name not available"
    return
  fi
  local hn
  hn=$(hostname 2>/dev/null || echo "")
  if [[ -z "${hn}" ]]; then
    report_warn "mdns_resolve_roundtrip" "hostname not resolvable"
    return
  fi
  local out rc=0
  if ! out=$(timeout "${MDNS_RESOLVE_TIMEOUT_SECONDS}" \
              avahi-resolve-host-name "${hn}.local" 2>/dev/null); then
    rc=$?
    report_warn "mdns_resolve_roundtrip" "exit=${rc} (warning, not drift)"
    return
  fi
  if [[ -n "${out}" ]]; then
    report_ok "mdns_resolve_roundtrip" "non-empty resolution"
  else
    report_warn "mdns_resolve_roundtrip" \
      "empty resolution (warning, not drift)"
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
  hits=$(ausearch -m AVC -ts boot 2>/dev/null \
           | grep -cE '(avahi_t|avahi_exec_t|nnp_transition|avahi)' \
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
  require_tool systemctl
  verify_package
  verify_unit_active
  verify_liveness
  verify_property "NoNewPrivileges" "NoNewPrivileges" "${EXPECTED_NNP}"
  verify_property "ProtectSystem" "ProtectSystem" "${EXPECTED_PROTECT_SYSTEM}"
  verify_property "ProtectHome" "ProtectHome" "${EXPECTED_PROTECT_HOME}"
  verify_property "ProtectKernelTunables" "ProtectKernelTunables" \
    "${EXPECTED_PROTECT_KERNEL_TUNABLES}"
  verify_property "ProtectKernelModules" "ProtectKernelModules" \
    "${EXPECTED_PROTECT_KERNEL_MODULES}"
  verify_property "ProtectKernelLogs" "ProtectKernelLogs" \
    "${EXPECTED_PROTECT_KERNEL_LOGS}"
  verify_property "ProtectControlGroups" "ProtectControlGroups" \
    "${EXPECTED_PROTECT_CONTROL_GROUPS}"
  verify_property "ProtectClock" "ProtectClock" "${EXPECTED_PROTECT_CLOCK}"
  verify_property "ProtectHostname" "ProtectHostname" \
    "${EXPECTED_PROTECT_HOSTNAME}"
  verify_property "ProtectProc" "ProtectProc" "${EXPECTED_PROTECT_PROC}"
  verify_property "ProcSubset" "ProcSubset" "${EXPECTED_PROCSUBSET}"
  verify_property "PrivateTmp" "PrivateTmp" "${EXPECTED_PRIVATE_TMP}"
  verify_property "PrivateDevices" "PrivateDevices" \
    "${EXPECTED_PRIVATE_DEVICES}"
  verify_substring "ReadWritePaths" "ReadWritePaths" \
    "${EXPECTED_READ_WRITE_PATHS_SUBSTRING}"
  verify_set_exact "RestrictAddressFamilies" "RestrictAddressFamilies" \
    "${EXPECTED_RESTRICT_ADDRESS_FAMILIES}"
  verify_property "RestrictNamespaces" "RestrictNamespaces" \
    "${EXPECTED_RESTRICT_NAMESPACES}"
  verify_property "RestrictRealtime" "RestrictRealtime" \
    "${EXPECTED_RESTRICT_REALTIME}"
  verify_property "RestrictSUIDSGID" "RestrictSUIDSGID" \
    "${EXPECTED_RESTRICT_SUID_SGID}"
  verify_property "LockPersonality" "LockPersonality" \
    "${EXPECTED_LOCK_PERSONALITY}"
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_property "SystemCallArchitectures" "SystemCallArchitectures" \
    "${EXPECTED_SYSCALL_ARCH}"
  verify_scf_class_tokens
  verify_substring_set "SystemCallFilter" "SystemCallFilter" \
    "${EXPECTED_SCF_SYSCALL_SUBSTRINGS}"
  verify_set_exact "CapabilityBoundingSet" "CapabilityBoundingSet" \
    "${EXPECTED_CAP_BOUNDING_SET}"
  verify_umask
  verify_selinux_domain
  verify_mdns_multicast_join
  verify_mdns_resolve_roundtrip
  verify_cil_module
  verify_avc_clean
  exit "${fail_state}"
}

main "$@"
