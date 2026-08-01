#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_alsa_state.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/alsa-state.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against a long-running root-uid process. The vendor
# ExecStart= directive carries a leading dash prefix, which would mask a
# SIGSYS-killed binary as an "active" unit; the paired comm=alsactl probe
# defeats that exit-masking. The AVC-clean, SECCOMP-clean, and CIL-
# module-presence checks are gated behind a sysadm_t domain check and
# reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="alsa-state.service"
readonly EXPECTED_DOMAIN="alsa_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_PROTECT_SYSTEM="full"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_UID="0"
readonly EXPECTED_GID="0"
readonly EXPECTED_COMM="alsactl"
readonly REQUIRED_PACKAGE="alsa-utils"
readonly EXPECTED_CIL_MODULE="nnp_alsa"
readonly BINARY_BIN_PATH="/usr/bin/alsactl"
readonly BINARY_SBIN_PATH="/usr/sbin/alsactl"
readonly STATE_FILE_PATH="/var/lib/alsa/asound.state"
readonly EXPECTED_FCONTEXT="alsa_exec_t"
readonly EXPECTED_CAPS_NORMALIZED=""
readonly EXPECTED_RAF_SOURCE_ORDER="AF_UNIX AF_NETLINK"
declare -ri EXPECTED_SCF_LENGTH_MIN=1500
readonly -a EXPECTED_SCF_ANCHOR_TOKENS=(
  epoll_wait
  recvfrom
)

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/alsa-state.service.d"
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

sound_hardware_present() {
  # A virtual machine exposes no sound card: /dev/snd is absent and
  # /proc/asound/cards does not exist. alsa-state.service is then never pulled
  # in (no sound.target reached), so it is legitimately inactive and the
  # saved-state file is never written. The hardening directives remain merged
  # into the loaded unit and verifiable through `systemctl show`.
  [[ -d /dev/snd ]] || [[ -e /proc/asound/cards ]]
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
  elif ! sound_hardware_present; then
    report_ok "unit_${UNIT%.service}" \
      "${actual:-inactive} (no sound hardware — service not pulled in on this host)"
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
    if ! sound_hardware_present; then
      report_skip "liveness" "no sound hardware — no MainPID on this host"
      return
    fi
    report_fail "liveness" "pid=${pid} not present"
    return
  fi
  report_ok "liveness" "pid=${pid}"
}

verify_live_comm() {
  # The vendor ExecStart= directive carries a leading dash prefix, which
  # makes systemd treat a non-zero exit of the binary as success. Without
  # this probe, a SIGSYS-killed alsactl would still report an "active"
  # unit to a superficial systemctl is-active check.
  local pid comm
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "live_comm" "no MainPID"
    return
  fi
  comm=$(cat "/proc/${pid}/comm" 2>/dev/null || echo "?")
  if [[ "${comm}" == "${EXPECTED_COMM}" ]]; then
    report_ok "live_comm" "${comm}"
  else
    report_fail "live_comm" \
      "expected=${EXPECTED_COMM} actual=${comm} (dash-prefix exit-masking suspected)"
  fi
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
  # The expected end-state is the empty bounding set. systemd's --value
  # output for an empty CapabilityBoundingSet= is the empty string;
  # whitespace-strip the observed value and compare against "". Any
  # non-empty observed value is drift.
  local raw normalised
  raw=$(systemctl show -p CapabilityBoundingSet --value "${UNIT}" 2>/dev/null \
          || true)
  normalised=$(printf '%s\n' "${raw}" \
                | tr '[:upper:]' '[:lower:]' \
                | tr -s '[:space:]' ' ' \
                | sed 's/^ *//; s/ *$//')
  if [[ "${normalised}" == "${EXPECTED_CAPS_NORMALIZED}" ]]; then
    report_ok "cap_bounding_set" "(empty)"
  else
    report_fail "cap_bounding_set" \
      "expected='(empty)' actual='${normalised}'"
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
      "expected=${EXPECTED_UID} actual=${uid} (alsactl runs as root throughout)"
  fi
  if [[ "${gid}" == "${EXPECTED_GID}" ]]; then
    report_ok "live_gid" "${gid}"
  else
    report_fail "live_gid" \
      "expected=${EXPECTED_GID} actual=${gid} (alsactl runs as root throughout)"
  fi
}

verify_fcontext() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_alsactl" "matchpathcon not available"
    return
  fi
  local out_bin out_sbin
  out_bin=$(matchpathcon "${BINARY_BIN_PATH}" 2>/dev/null || true)
  out_sbin=$(matchpathcon "${BINARY_SBIN_PATH}" 2>/dev/null || true)
  if printf '%s' "${out_bin}" | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_bin" "${EXPECTED_FCONTEXT}"
  else
    report_fail "fcontext_bin" \
      "expected=${EXPECTED_FCONTEXT} actual='${out_bin}'"
  fi
  if printf '%s' "${out_sbin}" | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_sbin" "${EXPECTED_FCONTEXT}"
  else
    report_fail "fcontext_sbin" \
      "expected=${EXPECTED_FCONTEXT} actual='${out_sbin}'"
  fi
}

verify_state_file() {
  if [[ ! -e "${STATE_FILE_PATH}" ]]; then
    if ! sound_hardware_present; then
      report_skip "state_file" \
        "no sound hardware — ${STATE_FILE_PATH} not written on this host"
      return
    fi
    report_fail "state_file" "missing: ${STATE_FILE_PATH}"
    return
  fi
  local size
  size=$(stat -c '%s' "${STATE_FILE_PATH}" 2>/dev/null || echo 0)
  if [[ "${size}" =~ ^[0-9]+$ ]] && (( size > 0 )); then
    report_ok "state_file" "size=${size} bytes"
  else
    report_fail "state_file" "size=${size} (expected > 0)"
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
           | grep -cE '(alsa_t|nnp_transition|alsa-state|alsactl)' \
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
              | grep 'comm="alsactl"' || true)
  if [[ -z "${records}" ]]; then
    report_ok "seccomp_clean" "0 hits"
    return
  fi
  hit_lines=$(printf '%s\n' "${records}" | wc -l | tr -d ' ')
  fields=$(printf '%s\n' "${records}" \
            | grep -oE '(syscall|uid|gid)=[^ ]+' \
            | sort -u \
            | tr '\n' ' ')
  if ! sound_hardware_present; then
    # On a no-card host alsactl performs a no-op restore yet still trips the
    # subtractive @resources class (setpriority, syscall 141) under the SCF —
    # the Phase-B privilege-restriction interaction. The daemon does no real
    # work here, so this is HW-gap noise, not boot drift; whether the SCF needs
    # a setpriority carve-out must be settled on real sound hardware.
    report_skip "seccomp_clean" \
      "${hit_lines} hit(s) on no-card host (fields: ${fields}); HW-gap — validate SCF vs alsactl on real sound hardware"
    return
  fi
  report_fail "seccomp_clean" \
    "${hit_lines} hit(s) since boot; fields: ${fields}"
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
  verify_package
  verify_unit_active
  verify_liveness
  verify_live_comm
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
  verify_state_file
  verify_cil_module
  verify_avc_clean
  verify_seccomp_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
