#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only state probe for topic_keepassxc.
#
# Reports observed state without judging it. Runs from a staff_t-confined
# shell for the staff-side checks (package, binary labels, database-tree
# labels, the live runtime domain of a running GUI process). The SELinux
# policy-store queries (seinfo, semodule, semanage, sesearch) and the
# ausearch AVC read need sysadm_t and are reported as `SKIP needs sysadm_t`
# when the probe runs from any other domain; re-run under
# `sudo -r sysadm_r -t sysadm_t bash probe.sh` for the full picture.
#
# Liveness uses `[[ -d /proc/${pid} ]]`, never `kill -0` (which returns
# EPERM cross-user from a non-privileged context and would misreport a live
# process as dead).
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  completed (regardless of observed state)
#   2  a required base tool is missing

set -euo pipefail

readonly DATABASE_DIR="${KEEPASSXC_DB_DIR:-${HOME}/keepass}"
readonly BINARIES=(/usr/bin/keepassxc /usr/bin/keepassxc-cli /usr/bin/keepassxc-proxy)
readonly MODULES=(keepassxc_extras keepassxc_dbtype_autotrans keepassxc_spawn_isolation)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

is_sysadm() {
  [[ "$(id -Z 2>/dev/null | cut -d: -f3)" == "sysadm_t" ]]
}

section() {
  printf '\n== %s ==\n' "$1"
}

probe_package() {
  section "package"
  rpm -q keepassxc 2>&1 || true
}

probe_binary_labels() {
  section "binary SELinux labels"
  local b
  for b in "${BINARIES[@]}"; do
    if [[ -e "${b}" ]]; then
      # shellcheck disable=SC2012 # ls -Z is the SELinux context display path
      ls -laZ "${b}" 2>/dev/null || true
    else
      printf '%s: (absent)\n' "${b}"
    fi
  done
}

probe_database_labels() {
  section "database directory and *.kdbx SELinux labels"
  if [[ -d "${DATABASE_DIR}" ]]; then
    # shellcheck disable=SC2012 # ls -Z is the SELinux context display path
    ls -ldZ "${DATABASE_DIR}" 2>/dev/null || true
    local f found=0
    for f in "${DATABASE_DIR}"/*.kdbx "${DATABASE_DIR}"/*.kdbx.backup; do
      [[ -e "${f}" ]] || continue
      found=1
      # shellcheck disable=SC2012 # ls -Z is the SELinux context display path
      ls -laZ "${f}" 2>/dev/null || true
    done
    (( found == 0 )) && printf '(no *.kdbx entries directly under %s)\n' "${DATABASE_DIR}"
  else
    printf '%s: (absent)\n' "${DATABASE_DIR}"
  fi
}

probe_live_domain() {
  section "live runtime domain of running keepassxc GUI"
  local pid
  pid=$(pgrep -x keepassxc 2>/dev/null | head -1 || true)
  if [[ -z "${pid}" ]]; then
    printf '(no live keepassxc GUI process)\n'
    return
  fi
  if [[ -d "/proc/${pid}" ]]; then
    printf 'pid=%s attr/current=%s\n' \
      "${pid}" "$(cat "/proc/${pid}/attr/current" 2>/dev/null || echo '?')"
  else
    printf 'pid=%s vanished between pgrep and read\n' "${pid}"
  fi
}

probe_db_label_sweep() {
  section "keepassxc_db_t files outside the database directory (expected: none)"
  local hits
  hits=$(find "${HOME}" -xdev -path "${DATABASE_DIR}" -prune -o \
           -context '*:keepassxc_db_t:*' -print 2>/dev/null || true)
  if [[ -z "${hits}" ]]; then
    printf '(none)\n'
  else
    printf '%s\n' "${hits}"
    printf '(non-empty: a helper spawn may have inherited keepassxc_t — see Topic Reference)\n'
  fi
}

probe_selinux_policy() {
  section "SELinux policy state"
  if ! is_sysadm; then
    printf 'SKIP needs sysadm_t (seinfo, semodule, semanage, sesearch)\n'
    return
  fi
  printf '-- custom types present:\n'
  seinfo -t 2>/dev/null | grep -wE 'keepassxc_t|keepassxc_exec_t|keepassxc_db_t' || true
  printf '-- modules loaded at priority 400:\n'
  local m
  for m in "${MODULES[@]}"; do
    semodule -lfull 2>/dev/null | grep -wE "${m}" || printf '%s: (not loaded)\n' "${m}"
  done
  printf '-- typepermissive marker:\n'
  semanage permissive -l 2>/dev/null | grep -w keepassxc_t || printf '(keepassxc_t not permissive)\n'
  printf '-- companion type_transition rules:\n'
  sesearch -T -s keepassxc_t -t user_home_t -c file 2>/dev/null || true
  sesearch -T -s keepassxc_t -t bin_t -c process 2>/dev/null || true
  printf '-- fcontext entries:\n'
  semanage fcontext -l 2>/dev/null | grep -E 'keepassxc' || true
}

probe_avc() {
  section "AVC posture since boot"
  if ! is_sysadm; then
    printf 'SKIP needs sysadm_t (ausearch)\n'
    return
  fi
  ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
    | grep -E '(keepassxc|keepassxc_t|keepassxc_exec_t|keepassxc_db_t)' \
    || printf '(no matching AVC records)\n'
}

main() {
  require_tool rpm
  require_tool pgrep
  require_tool find
  probe_package
  probe_binary_labels
  probe_database_labels
  probe_live_domain
  probe_db_label_sweep
  probe_selinux_policy
  probe_avc
  exit 0
}

main "$@"
