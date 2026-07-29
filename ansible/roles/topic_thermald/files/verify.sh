#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_thermald.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/thermald.md. Liveness uses /proc, never
# `kill -0`, so the script reports correctly when run from a non-
# privileged context against a long-running root-uid process. The verify
# branches on MainPID to accept either of the two well-defined Soll states:
#
#   - DPTF-bearing host: ActiveState=active, SubState=running,
#                        Result=success, MainPID > 0, live domain init_t,
#                        live UID/GID 0/0.
#   - DPTF-less host:    ActiveState=inactive, SubState=dead,
#                        Result=success, MainPID == 0, and the current boot's
#                        journal carries the not-applicable anchor — either
#                        "Unsupported cpu model|Unsupported platform" on bare
#                        metal without a DPTF table, or the stock unit's
#                        "unmet condition check ConditionVirtualization" on a
#                        virtual machine, where ConditionVirtualization=no gates
#                        the service off.
#
# The AVC-clean and SECCOMP-clean checks are gated behind a sysadm_t
# domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="thermald.service"
readonly EXPECTED_TYPE="dbus"
readonly EXPECTED_RESULT="success"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_PROTECT_SYSTEM="full"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_RUNTIME_DOMAIN="init_t"
readonly EXPECTED_UID="0"
readonly EXPECTED_GID="0"
readonly EXPECTED_FCONTEXT="bin_t"
readonly REQUIRED_PACKAGE="thermald"
readonly BINARY_PATH="/usr/bin/thermald"
readonly EXPECTED_CAPS_NORMALIZED=""
readonly EXPECTED_RAF_SOURCE_ORDER="AF_UNIX AF_NETLINK"
# The DPTF-less branch is reached on bare metal without a DPTF table
# ("Unsupported cpu model|Unsupported platform") and, equivalently, on a
# virtual machine where the stock unit's ConditionVirtualization=no gates the
# service off entirely ("unmet condition check ConditionVirtualization"). Both
# are legitimate "thermald not running on this hardware" end-states.
readonly DPTF_LESS_JOURNAL_ANCHOR='Unsupported cpu model|Unsupported platform|unmet condition check ConditionVirtualization'
declare -ri EXPECTED_SCF_LENGTH_MIN=1500
readonly -a EXPECTED_SCF_ANCHOR_TOKENS=(
  epoll_wait
  recvfrom
)
readonly -a FORBIDDEN_POLICY_TYPES=(
  thermald_t
  thermald_exec_t
)

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/thermald.service.d"
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

read_main_pid() {
  systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0
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

verify_fcontext_bin_t() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_thermald" "matchpathcon not available"
    return
  fi
  local out
  out=$(matchpathcon "${BINARY_PATH}" 2>/dev/null || true)
  if printf '%s' "${out}" | grep -qw "${EXPECTED_FCONTEXT}"; then
    report_ok "fcontext_thermald" "${EXPECTED_FCONTEXT}"
  else
    report_fail "fcontext_thermald" \
      "expected=${EXPECTED_FCONTEXT} actual='${out}' (stock policy may have gained a service-specific subtype; manifest revision required)"
  fi
}

verify_stock_policy_absence() {
  if ! command -v seinfo >/dev/null 2>&1; then
    report_skip "stock_policy_absence" "seinfo not available"
    return
  fi
  local pattern hits
  pattern=$(IFS='|'; printf '%s' "${FORBIDDEN_POLICY_TYPES[*]}")
  hits=$(seinfo --type 2>/dev/null | grep -wcE "${pattern}" || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "stock_policy_absence" "no thermald_t/thermald_exec_t in policy"
  else
    report_fail "stock_policy_absence" \
      "${hits} forbidden type(s) present (manifest revision required)"
  fi
}

verify_active_substate_result() {
  # Platform-symmetric branching on MainPID:
  #   MainPID > 0 → DPTF-bearing branch (active/running/success).
  #   MainPID == 0 → DPTF-less branch (inactive/dead/success + journal anchor).
  # Any other state combination is drift.
  local pid active sub result
  pid=$(read_main_pid)
  active=$(systemctl show -p ActiveState --value "${UNIT}" 2>/dev/null || true)
  sub=$(systemctl show -p SubState --value "${UNIT}" 2>/dev/null || true)
  result=$(systemctl show -p Result --value "${UNIT}" 2>/dev/null || true)

  if [[ "${pid}" != "0" && -d "/proc/${pid}" ]]; then
    if [[ "${active}" == "active" \
          && "${sub}" == "running" \
          && "${result}" == "${EXPECTED_RESULT}" ]]; then
      report_ok "soll_state_dptf_bearing" \
        "ActiveState=${active} SubState=${sub} Result=${result} pid=${pid}"
    else
      report_fail "soll_state_dptf_bearing" \
        "pid=${pid} but ActiveState='${active}' SubState='${sub}' Result='${result}'"
    fi
  elif [[ "${pid}" == "0" ]]; then
    if [[ "${active}" == "inactive" \
          && "${sub}" == "dead" \
          && "${result}" == "${EXPECTED_RESULT}" ]]; then
      report_ok "soll_state_dptf_less" \
        "ActiveState=${active} SubState=${sub} Result=${result} pid=0"
    else
      report_fail "soll_state_dptf_less" \
        "pid=0 but ActiveState='${active}' SubState='${sub}' Result='${result}'"
    fi
  else
    report_fail "soll_state_unknown" \
      "pid=${pid} not present and not 0"
  fi
}

verify_dptf_less_journal_anchor() {
  # Only meaningful on the DPTF-less branch (MainPID == 0). On the
  # DPTF-bearing branch the anchor is irrelevant; report SKIP.
  local pid
  pid=$(read_main_pid)
  if [[ "${pid}" != "0" ]]; then
    report_skip "dptf_less_journal_anchor" "DPTF-bearing branch"
    return
  fi
  if ! command -v journalctl >/dev/null 2>&1; then
    report_fail "dptf_less_journal_anchor" "journalctl not available"
    return
  fi
  local hits
  hits=$(journalctl -u "${UNIT}" -b --no-pager 2>/dev/null \
          | grep -cE "${DPTF_LESS_JOURNAL_ANCHOR}" \
          || true)
  if (( hits > 0 )); then
    report_ok "dptf_less_journal_anchor" "${hits} match(es) since boot"
  else
    report_fail "dptf_less_journal_anchor" \
      "expected at least one match for '${DPTF_LESS_JOURNAL_ANCHOR}' since boot"
  fi
}

verify_selinux_domain() {
  # DPTF-bearing branch only. The DPTF-less branch has no live process to
  # read /proc/<pid>/attr/current from.
  local pid domain
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "selinux_domain" "DPTF-less branch — no MainPID"
    return
  fi
  domain=$(awk -F: '{print $3}' "/proc/${pid}/attr/current" 2>/dev/null \
           || echo "?")
  if [[ "${domain}" == "${EXPECTED_RUNTIME_DOMAIN}" ]]; then
    report_ok "selinux_domain" "${domain}"
  else
    report_fail "selinux_domain" \
      "expected=${EXPECTED_RUNTIME_DOMAIN} actual=${domain}"
  fi
}

verify_live_uid_gid() {
  # DPTF-bearing branch only.
  local pid uid gid
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    report_skip "live_uid_gid" "DPTF-less branch — no MainPID"
    return
  fi
  uid=$(awk '/^Uid:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "?")
  gid=$(awk '/^Gid:/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "?")
  if [[ "${uid}" == "${EXPECTED_UID}" ]]; then
    report_ok "live_uid" "${uid}"
  else
    report_fail "live_uid" \
      "expected=${EXPECTED_UID} actual=${uid} (thermald runs as root throughout)"
  fi
  if [[ "${gid}" == "${EXPECTED_GID}" ]]; then
    report_ok "live_gid" "${gid}"
  else
    report_fail "live_gid" \
      "expected=${EXPECTED_GID} actual=${gid} (thermald runs as root throughout)"
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
           | grep -cE '(thermald|nnp_transition)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
  fi
}

verify_seccomp_clean() {
  # On the DPTF-less branch the assertion is trivially satisfied because
  # the binary exits before any SCF-evaluated syscall after the seed-
  # allowed execve(2). On the DPTF-bearing branch a non-empty record set
  # is drift requiring an SCF carve-out.
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
              | grep 'comm="thermald"' || true)
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
    *"symbolic link"*) mode="link" ;;
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
  verify_property "Type" "Type" "${EXPECTED_TYPE}"
  verify_active_substate_result
  verify_dptf_less_journal_anchor
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
  verify_fcontext_bin_t
  verify_stock_policy_absence
  verify_selinux_domain
  verify_live_uid_gid
  verify_avc_clean
  verify_seccomp_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
