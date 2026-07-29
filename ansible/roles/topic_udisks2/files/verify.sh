#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_udisks2.
#
# Compares observed runtime state against the expected end state declared
# in docs/reference/topics/udisks2.md. Liveness uses /proc, never `kill -0`,
# so the script reports correctly when run from a non-privileged context
# against the root-owned daemon. The AVC-clean check is gated behind a
# sysadm_t domain check and reported as SKIP from staff_t.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (SKIP and WARN accepted)
#   1  drift detected
#   2  invocation error (missing required tool)

set -euo pipefail

readonly UNIT="udisks2.service"
readonly EXPECTED_DOMAIN="devicekit_disk_t"
readonly EXPECTED_NNP="yes"
readonly EXPECTED_MDWE="yes"
readonly EXPECTED_PRIVATE_MOUNTS="no"
# CapabilityBoundingSet from `systemctl show --value` is alphabetical and
# lower-case; the expected string mirrors that normalisation.
readonly EXPECTED_CAPS="cap_sys_admin cap_sys_rawio"
# RestrictAddressFamilies from `systemctl show --value` preserves the
# source order written in the drop-in.
readonly EXPECTED_RAF="AF_UNIX AF_NETLINK"
readonly EXPECTED_SCF_MIN_BYTES=200
readonly -a EXPECTED_SCF_ANCHORS=(
  "mount"
  "umount2"
  "read"
  "write"
  "openat"
  "close"
)
readonly REQUIRED_PACKAGE="udisks2"

# Paths whose SELinux context is asserted against file_contexts. A directory
# entry also covers every path inside it. Files written into a drop-in
# directory take that directory's type at creation time; only a restorecon
# pass assigns the type that file_contexts maps for the path, which for most
# units is a service-specific *_unit_file_t rather than the generic
# systemd_unit_file_t. Nothing in the unit's runtime behaviour reveals the
# difference, so the comparison has to be explicit.
readonly -a CONTEXT_PATHS=(
  "/etc/systemd/system/udisks2.service.d"
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

udisks2_dbus_activatable() {
  # udisks2 is D-Bus-activated on Fedora 44: it ships a system D-Bus service
  # file with SystemdService=udisks2.service and is not enabled at boot, so an
  # inactive udisks2.service is the steady state on a headless node, not a
  # fault. The daemon starts on the first UDisks2 D-Bus call (a desktop session
  # or `udisksctl`) and idles back out. This is also the post-reboot state in
  # the system tier, where nothing has yet issued a UDisks2 call.
  [[ -f /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service ]]
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
  elif udisks2_dbus_activatable; then
    report_ok "unit_${UNIT%.service}" \
      "${actual:-inactive} (D-Bus-activated; udisksd starts on first UDisks2 call)"
  else
    report_fail "unit_${UNIT%.service}" \
      "expected=active actual=${actual:-<empty>} and not D-Bus-activatable"
  fi
}

verify_liveness() {
  # /proc, not `kill -0`: kill -0 from a non-privileged context against a
  # foreign uid returns EPERM, not ESRCH, and would falsely report a live
  # daemon as dead.
  local pid
  pid=$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null || echo 0)
  if [[ "${pid}" == "0" || ! -d "/proc/${pid}" ]]; then
    if udisks2_dbus_activatable; then
      report_skip "liveness" \
        "D-Bus-activated; udisksd idle (no MainPID until first UDisks2 call)"
      return
    fi
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

# verify_set_property compares a space-separated property as an unordered,
# case-insensitive set. systemctl renders CapabilityBoundingSet in kernel
# cap-bit order (cap_sys_rawio before cap_sys_admin) and RestrictAddressFamilies
# alphabetically, neither of which matches a hand-written order; the security
# intent is the set membership, not the token order.
verify_set_property() {
  local label="$1" prop="$2" expected="$3" actual
  actual=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
  local actual_sorted expected_sorted
  # Intentional word-splitting of the space-separated token lists.
  # shellcheck disable=SC2086
  actual_sorted=$(printf '%s\n' ${actual,,} | sort | tr '\n' ' ')
  # shellcheck disable=SC2086
  expected_sorted=$(printf '%s\n' ${expected,,} | sort | tr '\n' ' ')
  if [[ "${actual_sorted}" == "${expected_sorted}" ]]; then
    report_ok "${label}" "${actual}"
  else
    report_fail "${label}" "expected set='${expected}' actual='${actual}'"
  fi
}

verify_systemcallfilter() {
  # SystemCallFilter --value returns the expanded syscall list, not the
  # @class names. Length plus anchor presence is the robust shape; a
  # literal-string compare against `@system-service @mount` would fail on
  # every correctly configured host.
  local actual length missing anchor
  actual=$(systemctl show -p SystemCallFilter --value "${UNIT}" 2>/dev/null \
           || true)
  length=${#actual}
  missing=()
  for anchor in "${EXPECTED_SCF_ANCHORS[@]}"; do
    if ! grep -qw "${anchor}" <<<"${actual}"; then
      missing+=("${anchor}")
    fi
  done
  if (( length < EXPECTED_SCF_MIN_BYTES )); then
    report_fail "SystemCallFilter" \
      "length=${length} below threshold=${EXPECTED_SCF_MIN_BYTES}"
    return
  fi
  if (( ${#missing[@]} > 0 )); then
    report_fail "SystemCallFilter" \
      "length=${length} missing anchors: ${missing[*]}"
    return
  fi
  report_ok "SystemCallFilter" \
    "length=${length} anchors=$(IFS=,; printf '%s' "${EXPECTED_SCF_ANCHORS[*]}")"
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
           | grep -cE '(devicekit_disk_t|nnp_transition|udisksd)' \
           || true)
  if [[ "${hits}" == "0" ]]; then
    report_ok "avc_clean" "0 hits"
  else
    report_fail "avc_clean" "${hits} hits since boot"
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
  verify_unit_active
  verify_liveness
  verify_property "NoNewPrivileges" "NoNewPrivileges" "${EXPECTED_NNP}"
  verify_property "MemoryDenyWriteExecute" "MemoryDenyWriteExecute" \
    "${EXPECTED_MDWE}"
  verify_property "PrivateMounts" "PrivateMounts" "${EXPECTED_PRIVATE_MOUNTS}"
  verify_set_property "CapabilityBoundingSet" "CapabilityBoundingSet" \
    "${EXPECTED_CAPS}"
  verify_set_property "RestrictAddressFamilies" "RestrictAddressFamilies" \
    "${EXPECTED_RAF}"
  verify_systemcallfilter
  verify_selinux_domain
  verify_avc_clean
  verify_selinux_context
  exit "${fail_state}"
}

main "$@"
