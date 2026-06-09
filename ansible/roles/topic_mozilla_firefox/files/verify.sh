#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_mozilla_firefox.
#
# Compares observed state against the post-deploy expected end-state declared
# in docs/reference/topics/mozilla-firefox.md across nine independent
# surfaces:
#
#   1. RPM Firefox tree absent.
#   2. Flatpak ref org.mozilla.firefox installed system-wide from flathub
#      on branch stable.
#   3. Sandbox-override `filesystems=` line is the byte-exact string
#      `xdg-download;!host;!home;`.
#   4. Sandbox-override `sockets=` line is the byte-exact string
#      `wayland;!x11;`.
#   5. Portal-permission row count for the application is zero (default
#      ask posture).
#   6. Per-profile user.js carries exactly two VAAPI user_pref(...) lines.
#   7. xdg-settings get default-web-browser returns
#      `org.mozilla.firefox.desktop`.
#   8. Live firefox-bin process (if any) carries the substring `staff_t`
#      in /proc/${pid}/attr/current.
#   9. AVC backlog from boot filtered against the application's process
#      tree returns zero matches.
#
# Liveness: `[[ -d /proc/${pid} ]]` is the canonical pattern this tree
# uses (never `kill -0`, which returns EPERM cross-user from a
# non-privileged context and would misreport a live process as dead).
#
# Override-file content read and AVC backlog read are gated behind a
# `sudo -r sysadm_r -t sysadm_t` role-switch.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation
#   1  drift detected
#   2  invocation error (missing required tool, sudo not available)

set -euo pipefail

readonly APPLICATION_ID="org.mozilla.firefox"
readonly REMOTE_NAME="flathub"
readonly EXPECTED_BRANCH="stable"
readonly OVERRIDE_PATH="/var/lib/flatpak/overrides/org.mozilla.firefox"
readonly EXPECTED_OVERRIDE_FILESYSTEMS="xdg-download;!host;!home;"
readonly EXPECTED_OVERRIDE_SOCKETS="wayland;!x11;"
readonly EXPECTED_PORTAL_ROW_COUNT="0"
readonly EXPECTED_USER_JS_VAAPI_LINE_COUNT="2"
readonly EXPECTED_DEFAULT_BROWSER="org.mozilla.firefox.desktop"
readonly EXPECTED_RUNTIME_DOMAIN_SUBSTRING="staff_t"
readonly EXPECTED_AVC_MATCH_COUNT="0"
readonly USER_DATA_PATH_TEMPLATE="/home/__USER__/.var/app/org.mozilla.firefox/.mozilla/firefox"

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

verify_sudo_present() {
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'verify: /usr/bin/sudo not available\n' >&2
    exit 2
  fi
}

report_ok() {
  printf 'OK   %-48s %s\n' "$1" "$2"
}

report_fail() {
  printf 'FAIL %-48s %s\n' "$1" "$2"
  fail_state=1
}

verify_rpm_firefox_absent() {
  local listing
  listing=$(rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)' || true)
  if [[ -z "${listing}" ]]; then
    report_ok "rpm_firefox_absent" "expected=yes actual=yes"
  else
    report_fail "rpm_firefox_absent" \
      "expected=yes actual=no (packages present: $(printf '%s' "${listing}" | tr '\n' ' '))"
  fi
}

verify_flatpak_ref_present() {
  local row
  row=$(flatpak list \
          --columns=application,branch,origin,installation \
          2>/dev/null \
          | awk -v app="${APPLICATION_ID}" -v rem="${REMOTE_NAME}" \
                -v br="${EXPECTED_BRANCH}" '
              $1 == app && $2 == br && $3 == rem && $4 == "system" {
                print $0; exit
              }' \
          || true)
  if [[ -n "${row}" ]]; then
    report_ok "flatpak_ref_present" \
      "expected=${APPLICATION_ID} actual=${APPLICATION_ID} (branch=${EXPECTED_BRANCH} origin=${REMOTE_NAME} installation=system)"
  else
    report_fail "flatpak_ref_present" \
      "expected=${APPLICATION_ID} actual=(absent or unexpected branch/origin/installation)"
  fi
}

verify_override_lines() {
  local override_content fs_line sock_line
  override_content=$(sudo -r sysadm_r -t sysadm_t -- \
                       cat "${OVERRIDE_PATH}" 2>/dev/null \
                       || true)
  fs_line=$(printf '%s\n' "${override_content}" \
              | awk -F= '/^filesystems=/ { sub(/^filesystems=/, ""); print; exit }' \
              || true)
  sock_line=$(printf '%s\n' "${override_content}" \
                | awk -F= '/^sockets=/ { sub(/^sockets=/, ""); print; exit }' \
                || true)
  if [[ "${fs_line}" == "${EXPECTED_OVERRIDE_FILESYSTEMS}" ]]; then
    report_ok "override_filesystems" \
      "expected=${EXPECTED_OVERRIDE_FILESYSTEMS} actual=${fs_line}"
  else
    report_fail "override_filesystems" \
      "expected=${EXPECTED_OVERRIDE_FILESYSTEMS} actual=${fs_line:-(absent)}"
  fi
  if [[ "${sock_line}" == "${EXPECTED_OVERRIDE_SOCKETS}" ]]; then
    report_ok "override_sockets" \
      "expected=${EXPECTED_OVERRIDE_SOCKETS} actual=${sock_line}"
  else
    report_fail "override_sockets" \
      "expected=${EXPECTED_OVERRIDE_SOCKETS} actual=${sock_line:-(absent)}"
  fi
}

verify_portal_permission_row_count() {
  local count
  count=$(flatpak permission-list org.freedesktop.impl.portal.access \
            2>/dev/null \
            | grep -cE "^org\.freedesktop\.impl\.portal\.access[[:space:]]+(camera|microphone|location)[[:space:]]+${APPLICATION_ID}" \
            || true)
  [[ -z "${count}" ]] && count="0"
  if [[ "${count}" == "${EXPECTED_PORTAL_ROW_COUNT}" ]]; then
    report_ok "portal_permission_row_count" \
      "expected=${EXPECTED_PORTAL_ROW_COUNT} actual=${count}"
  else
    report_fail "portal_permission_row_count" \
      "expected=${EXPECTED_PORTAL_ROW_COUNT} actual=${count} (operator-side hard-deny entry present; review intended posture)"
  fi
}

verify_user_js_vaapi_line_count() {
  local user_data_path profile_dir user_js count seen=0
  user_data_path="${USER_DATA_PATH_TEMPLATE//__USER__/${USER}}"
  if [[ ! -d "${user_data_path}" ]]; then
    report_fail "user_js_vaapi_line_count" \
      "per-user data path not present: ${user_data_path}"
    return
  fi
  for profile_dir in "${user_data_path}"/*/; do
    [[ -d "${profile_dir}" ]] || continue
    user_js="${profile_dir}user.js"
    if [[ ! -f "${user_js}" ]]; then
      continue
    fi
    seen=1
    count=$(grep -cE '^user_pref\("media\.(ffmpeg\.vaapi\.enabled|hardware-video-decoding\.force-enabled)"' \
              "${user_js}" \
              || true)
    [[ -z "${count}" ]] && count="0"
    if [[ "${count}" == "${EXPECTED_USER_JS_VAAPI_LINE_COUNT}" ]]; then
      report_ok "user_js_vaapi_line_count[$(basename "${profile_dir}")]" \
        "expected=${EXPECTED_USER_JS_VAAPI_LINE_COUNT} actual=${count}"
    else
      report_fail "user_js_vaapi_line_count[$(basename "${profile_dir}")]" \
        "expected=${EXPECTED_USER_JS_VAAPI_LINE_COUNT} actual=${count}"
    fi
  done
  if (( seen == 0 )); then
    report_fail "user_js_vaapi_line_count" \
      "no profile-directory under ${user_data_path} carried a user.js"
  fi
}

verify_default_web_browser() {
  local actual
  actual=$(xdg-settings get default-web-browser 2>/dev/null || true)
  if [[ "${actual}" == "${EXPECTED_DEFAULT_BROWSER}" ]]; then
    report_ok "default_web_browser" \
      "expected=${EXPECTED_DEFAULT_BROWSER} actual=${actual}"
  else
    report_fail "default_web_browser" \
      "expected=${EXPECTED_DEFAULT_BROWSER} actual=${actual:-(unset)}"
  fi
}

verify_runtime_domain_substring() {
  local pid label
  pid=$(pgrep -x firefox-bin 2>/dev/null | head -1 || true)
  if [[ -z "${pid}" ]]; then
    report_ok "runtime_domain_substring" \
      "expected=${EXPECTED_RUNTIME_DOMAIN_SUBSTRING} actual=(no live firefox-bin process; check skipped non-fatally)"
    return
  fi
  if [[ ! -d "/proc/${pid}" ]]; then
    report_fail "runtime_domain_substring" \
      "pid=${pid} vanished between pgrep and read"
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

verify_avc_backlog() {
  local count
  count=$(sudo -r sysadm_r -t sysadm_t -- \
            ausearch -m AVC,USER_AVC -ts boot 2>&1 \
            | grep -cE "(firefox|bwrap|flatpak.*org\.mozilla\.firefox)" \
            || true)
  [[ -z "${count}" ]] && count="0"
  if [[ "${count}" == "${EXPECTED_AVC_MATCH_COUNT}" ]]; then
    report_ok "avc_backlog_for_firefox_from_boot" \
      "expected=${EXPECTED_AVC_MATCH_COUNT} actual=${count}"
  else
    report_fail "avc_backlog_for_firefox_from_boot" \
      "expected=${EXPECTED_AVC_MATCH_COUNT} actual=${count} (drift; investigate per Topic Reference §AVC posture)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool rpm
  require_tool flatpak
  verify_sudo_present
  verify_rpm_firefox_absent
  verify_flatpak_ref_present
  verify_override_lines
  verify_portal_permission_row_count
  verify_user_js_vaapi_line_count
  verify_default_web_browser
  verify_runtime_domain_substring
  verify_avc_backlog
  exit "${fail_state}"
}

main "$@"
