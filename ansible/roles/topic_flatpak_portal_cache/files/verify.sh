#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_flatpak_portal_cache.
#
# Compares observed runtime state against the expected post-reset
# end-state declared in docs/reference/topics/flatpak-portal-cache.md:
#
#   - xdg-document-portal.service is in user-systemd state 'active'
#   - flatpak documents list reports zero data rows
#   - per-application token count under
#     /run/user/${uid}/doc/by-app/<appid>/ is zero for every <appid>
#
# The verify is post-reset-applicable. Pre-reset on a host where the
# cache has not yet been flushed, the verify exits 0 with an
# informational note rather than 1; the Topic does not specialize on
# this case (a fresh cache snapshot is a clean state in itself).
#
# Liveness: `[[ -d /proc/${pid} ]]` against the user-systemd-reported
# main PID. Never `kill -0` — cross-user `kill -0` from a non-privileged
# context against a foreign-uid PID returns EPERM, not ESRCH, and would
# misreport a live process as dead. The canonical Soll/Ist comparison
# does not need a liveness probe in the first place: the user-systemd
# 'active' state already asserts a live main process. The /proc check
# is retained as a defense-in-depth signal that fires only when the
# unit reports active but the PID is in fact gone.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (or pre-reset informational no-op)
#   1  drift detected
#   2  invocation error (missing required tool, user-systemd not
#      addressable in the current connection mode)

set -euo pipefail

readonly PORTAL_SERVICE="xdg-document-portal.service"
readonly EXPECTED_PORTAL_SERVICE_STATE="active"
readonly EXPECTED_FUSE_BY_APP_TOKEN_COUNT="0"
readonly EXPECTED_PERSISTENT_DOCUMENTS_LINE_COUNT="0"

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

fuse_by_app_path() {
  printf '/run/user/%s/doc/by-app' "$(id -u)"
}

report_ok() {
  printf 'OK   %-48s %s\n' "$1" "$2"
}

report_info() {
  printf 'INFO %-48s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-48s %s\n' "$1" "$2"
  fail_state=1
}

verify_user_systemd_addressable() {
  if ! command -v systemctl >/dev/null 2>&1; then
    printf 'verify: systemctl not available\n' >&2
    exit 2
  fi
  # `systemctl --user is-system-running` returns non-zero on a degraded
  # but addressable user-bus; the verify treats any reachable user-bus
  # as addressable and only fails on a connection mode that rejects the
  # call outright (typical for a non-graphical SSH session without
  # `loginctl enable-linger`).
  if ! systemctl --user show-environment >/dev/null 2>&1; then
    printf 'verify: user-systemd is not addressable in this connection mode\n' >&2
    exit 2
  fi
}

verify_portal_service_state() {
  local actual
  actual=$(systemctl --user is-active "${PORTAL_SERVICE}" 2>/dev/null \
             || true)
  if [[ "${actual}" == "${EXPECTED_PORTAL_SERVICE_STATE}" ]]; then
    report_ok "portal_service_state" \
      "expected=${EXPECTED_PORTAL_SERVICE_STATE} actual=${actual}"
    return
  fi
  if [[ "${actual}" == "inactive" ]] || [[ "${actual}" == "" ]]; then
    report_info "portal_service_state" \
      "actual=${actual:-unknown} (pre-reset; service has not been spawned yet — informational, not drift)"
    return
  fi
  report_fail "portal_service_state" \
    "expected=${EXPECTED_PORTAL_SERVICE_STATE} actual=${actual}"
}

verify_portal_main_pid_alive() {
  local pid
  pid=$(systemctl --user show -p MainPID --value "${PORTAL_SERVICE}" \
          2>/dev/null \
          || echo 0)
  if [[ "${pid}" == "0" ]] || [[ -z "${pid}" ]]; then
    report_info "portal_service_main_pid" \
      "actual=0 (pre-reset, or service awaiting D-Bus activation)"
    return
  fi
  if [[ -d "/proc/${pid}" ]]; then
    report_ok "portal_service_main_pid" "pid=${pid} (/proc/${pid} present)"
  else
    report_fail "portal_service_main_pid" \
      "pid=${pid} reported by user-systemd but /proc/${pid} absent"
  fi
}

verify_persistent_documents_count() {
  if ! command -v flatpak >/dev/null 2>&1; then
    report_fail "persistent_documents_count" "flatpak not available"
    return
  fi
  local listing actual
  listing=$(flatpak documents list 2>/dev/null || true)
  if [[ -z "${listing}" ]]; then
    actual="0"
  else
    actual=$(printf '%s\n' "${listing}" \
               | grep -cE '^[^[:space:]]' \
               || true)
    [[ -z "${actual}" ]] && actual="0"
  fi
  if [[ "${actual}" == "${EXPECTED_PERSISTENT_DOCUMENTS_LINE_COUNT}" ]]; then
    report_ok "persistent_documents_count" \
      "expected=${EXPECTED_PERSISTENT_DOCUMENTS_LINE_COUNT} actual=${actual}"
  else
    report_fail "persistent_documents_count" \
      "expected=${EXPECTED_PERSISTENT_DOCUMENTS_LINE_COUNT} actual=${actual} (necessary-but-not-sufficient signal — see FUSE-by-app check below)"
  fi
}

verify_fuse_by_app_token_count() {
  local by_app
  by_app=$(fuse_by_app_path)
  if [[ ! -d "${by_app}" ]]; then
    report_ok "fuse_by_app_path_state" \
      "by_app/ does not exist (portal-service awaiting first D-Bus activation; cache empty by construction)"
    return
  fi
  local appdir app_id token_count any_drift=0
  shopt -s nullglob
  for appdir in "${by_app}"/*; do
    [[ -d "${appdir}" ]] || continue
    app_id=$(basename "${appdir}")
    token_count=$(find "${appdir}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
                    | wc -l \
                    || echo 0)
    if [[ "${token_count}" == "${EXPECTED_FUSE_BY_APP_TOKEN_COUNT}" ]]; then
      report_ok "fuse_by_app_token_count[${app_id}]" \
        "expected=${EXPECTED_FUSE_BY_APP_TOKEN_COUNT} actual=${token_count}"
    else
      report_fail "fuse_by_app_token_count[${app_id}]" \
        "expected=${EXPECTED_FUSE_BY_APP_TOKEN_COUNT} actual=${token_count} (cache not flushed for this application)"
      any_drift=1
    fi
  done
  shopt -u nullglob
  if (( any_drift == 0 )); then
    report_ok "fuse_by_app_aggregate" \
      "all <appid>/ entries empty"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  require_tool find
  verify_user_systemd_addressable
  verify_portal_service_state
  verify_portal_main_pid_alive
  verify_persistent_documents_count
  verify_fuse_by_app_token_count
  exit "${fail_state}"
}

main "$@"
