#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_tuned.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/tuned.md. Liveness uses [ -d /proc/${main_pid} ],
# never `kill -0`, so the script reports correctly when run from a non-
# privileged context against a long-running root-uid process.
#
# Deliberate omission: tuned-adm verify is NOT invoked. The command would
# report platform-side mismatches (for example, AHCI ALPM EOPNOTSUPP on
# SATA host ports whose driver does not expose ALPM) that are not topic-
# owned drift signals. The smoketest is tuned-adm active.
#
# The two opt-outs ProtectKernelTunables=no and ProtectControlGroups=no
# are deliberate concessions to the daemon's profile execution path
# (sysctl writes via /proc/sys/, cgroup writes via /sys/fs/cgroup/);
# tightening either to `yes` is drift against this end-state.
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

readonly UNIT="tuned.service"
readonly EXPECTED_PROTECT_SYSTEM="full"
readonly EXPECTED_PROTECT_HOME="yes"
readonly EXPECTED_PROTECT_KERNEL_TUNABLES="no"
readonly EXPECTED_PROTECT_KERNEL_MODULES="yes"
readonly EXPECTED_PROTECT_KERNEL_LOGS="yes"
readonly EXPECTED_PROTECT_CONTROL_GROUPS="no"
readonly EXPECTED_PRIVATE_TMP="yes"
readonly EXPECTED_PROTECT_CLOCK="yes"
readonly EXPECTED_PROTECT_HOSTNAME="yes"
readonly EXPECTED_LOCK_PERSONALITY="yes"
readonly EXPECTED_RESTRICT_REALTIME="yes"
readonly EXPECTED_RESTRICT_SUID_SGID="yes"
readonly EXPECTED_SYSCALL_ARCH="native"
readonly EXPECTED_RUNTIME_DOMAIN="tuned_t"
readonly EXPECTED_FCONTEXT_CANONICAL="tuned_exec_t"
readonly EXPECTED_FCONTEXT_PREMERGE="bin_t"
readonly REQUIRED_PACKAGE="tuned"
readonly BINARY_PATH_CANONICAL="/usr/bin/tuned"
readonly BINARY_PATH_PREMERGE="/usr/sbin/tuned"
readonly ACTIVE_PROFILE_MARKER="Current active profile:"
readonly AVC_FILTER='(tuned_t|tuned_exec_t|tuned_log_t|tuned_etc_t|tuned_rw_etc_t)'
readonly SECCOMP_FILTER='tuned'

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/tuned.service.d"
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
  printf 'OK   %-32s %s\n' "$1" "$2"
}

report_skip() {
  printf 'SKIP %-32s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-32s %s\n' "$1" "$2"
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

verify_unit_alive() {
  # Liveness via [ -d /proc/${main_pid} ] — ownership-independent. From a
  # staff_t shell, kill -0 against a foreign-uid PID returns EPERM rather
  # than ESRCH; the /proc form avoids that ambiguity. The class trap is
  # the kill-0-cross-user-eperm Pattern (slug only; not a written article
  # in this tree this session).
  local pid
  pid=$(read_main_pid)
  if [[ "${pid}" == "0" ]]; then
    report_fail "unit_alive" "MainPID=0 (service inactive)"
    return
  fi
  if [[ -d "/proc/${pid}" ]]; then
    report_ok "unit_alive" "MainPID=${pid}"
  else
    report_fail "unit_alive" "MainPID=${pid} but /proc/${pid} absent"
  fi
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
  if [[ "${domain}" == "${EXPECTED_RUNTIME_DOMAIN}" ]]; then
    report_ok "selinux_domain" "${domain}"
  else
    report_fail "selinux_domain" \
      "expected=${EXPECTED_RUNTIME_DOMAIN} actual=${domain}"
  fi
}

verify_tuned_adm_active() {
  if ! command -v tuned-adm >/dev/null 2>&1; then
    report_fail "tuned_adm_active" "tuned-adm not available"
    return
  fi
  local out rc
  out=$(tuned-adm active 2>&1) && rc=0 || rc=$?
  if (( rc != 0 )); then
    report_fail "tuned_adm_active" "exit=${rc} stdout='${out}'"
    return
  fi
  if ! printf '%s' "${out}" | grep -q "${ACTIVE_PROFILE_MARKER}"; then
    report_fail "tuned_adm_active" \
      "marker '${ACTIVE_PROFILE_MARKER}' missing from stdout='${out}'"
    return
  fi
  local profile_name
  profile_name=$(printf '%s' "${out}" \
                  | sed -n "s/^${ACTIVE_PROFILE_MARKER} *//p" \
                  | head -1 \
                  | tr -d '\r' \
                  | sed 's/^ *//; s/ *$//')
  if [[ -z "${profile_name}" ]]; then
    report_fail "tuned_adm_active" \
      "marker present but profile name empty (stdout='${out}')"
    return
  fi
  # The profile name is reported as informational output; this Topic
  # asserts only that the command returns exit 0 and a non-empty profile
  # name, not that any specific profile is selected.
  report_ok "tuned_adm_active" "profile=${profile_name}"
}

verify_fcontext_canonical_or_premerge() {
  if ! command -v matchpathcon >/dev/null 2>&1; then
    report_fail "fcontext_tuned" "matchpathcon not available"
    return
  fi
  local out_canonical out_premerge
  out_canonical=$(matchpathcon "${BINARY_PATH_CANONICAL}" 2>/dev/null || true)
  out_premerge=$(matchpathcon "${BINARY_PATH_PREMERGE}" 2>/dev/null || true)
  # Either-or fail-fast: if NEITHER path resolves to tuned_exec_t the
  # init_t -> tuned_t type-transition will not fire at execve time.
  if printf '%s' "${out_canonical}" | grep -qw "${EXPECTED_FCONTEXT_CANONICAL}"; then
    report_ok "fcontext_canonical" "${EXPECTED_FCONTEXT_CANONICAL}"
  elif printf '%s' "${out_premerge}" | grep -qw "${EXPECTED_FCONTEXT_CANONICAL}"; then
    report_ok "fcontext_premerge_fallback" \
      "${EXPECTED_FCONTEXT_CANONICAL} (pre-merge path; canonical-path mapping missing)"
  else
    report_fail "fcontext_tuned" \
      "neither '${BINARY_PATH_CANONICAL}' nor '${BINARY_PATH_PREMERGE}' resolves to ${EXPECTED_FCONTEXT_CANONICAL}; canonical='${out_canonical}' pre-merge='${out_premerge}'"
  fi
  # Informational: the pre-merge path normally resolves to bin_t (the
  # generic label) because the F44 sbin/bin equivalency rewrites the
  # lookup target before the file_contexts table is consulted.
  if printf '%s' "${out_premerge}" | grep -qw "${EXPECTED_FCONTEXT_PREMERGE}"; then
    report_ok "fcontext_premerge_info" "${EXPECTED_FCONTEXT_PREMERGE} (expected on F44)"
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
           | grep -cE "${AVC_FILTER}" \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
  fi
}

verify_seccomp_clean() {
  # This Topic ships no SystemCallFilter= directive; any seccomp record
  # naming tuned would itself be unexpected and surfaces as drift either
  # way (the record would imply a stock-systemd-side seccomp filter
  # inherited from a higher-level unit).
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
              | grep "${SECCOMP_FILTER}" || true)
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
  verify_unit_alive
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
  verify_selinux_domain
  verify_tuned_adm_active
  verify_fcontext_canonical_or_premerge
  verify_avc_clean
  verify_seccomp_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
