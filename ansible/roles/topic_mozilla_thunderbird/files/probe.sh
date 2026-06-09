#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_mozilla_thunderbird.
#
# Reports current state of the Mozilla Thunderbird Flatpak end-state: RPM
# Thunderbird tree absence, the system-installed Flatpak ref inventory and
# permission table, the sandbox-override file content (read under
# role-switched sysadm_t), the per-application portal-permission row
# inventory, the MIME default-mailto resolution, the live runtime-domain
# context of any active thunderbird process, and the AVC backlog from boot
# filtered against the application's process tree (read under role-switched
# sysadm_t).
#
# The probe never gates on observed state. The host may be in pre-deploy,
# post-deploy, or partial-deploy shape; the probe inventories what is there.
#
# Liveness signal: `[[ -d /proc/${pid} ]]` is the canonical pattern this
# tree uses where a liveness check is needed (never `kill -0`, which
# returns EPERM cross-user from a non-privileged context and would
# misreport a live process as dead). The override-file read and the AVC
# stream read are gated behind a `sudo -r sysadm_r -t sysadm_t` role-switch.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool: flatpak or rpm not present)

set -euo pipefail

readonly APPLICATION_ID="net.thunderbird.Thunderbird"
readonly OVERRIDE_PATH="/var/lib/flatpak/overrides/net.thunderbird.Thunderbird"
readonly EXPECTED_RUNTIME_DOMAIN_SUBSTRING="staff_t"

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

print_header() {
  printf '=== probe: mozilla-thunderbird ===\n'
}

probe_rpm_thunderbird_tree() {
  printf -- '--- RPM Thunderbird tree ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf 'rpm: not available\n'
    return
  fi
  local listing
  listing=$(rpm -qa | grep -iE '^(firefox|thunderbird|mozilla)' || true)
  if [[ -z "${listing}" ]]; then
    printf 'rpm_thunderbird_absent: yes (no firefox/thunderbird/mozilla packages installed)\n'
  else
    printf 'rpm_thunderbird_absent: no (packages present)\n%s\n' "${listing}"
  fi
}

probe_flatpak_ref_inventory() {
  printf -- '--- Flatpak ref inventory ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak list \
              --columns=application,branch,origin,installation,version \
              2>/dev/null \
              | grep -E '^net\.thunderbird\.Thunderbird' \
              || true)
  if [[ -z "${listing}" ]]; then
    printf 'flatpak_ref_present: no (net.thunderbird.Thunderbird not installed)\n'
  else
    printf 'flatpak_ref_present: yes\n%s\n' "${listing}"
  fi
}

probe_flatpak_permissions() {
  printf -- '--- post-override permission table ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  flatpak info --show-permissions "${APPLICATION_ID}" 2>&1 \
    || printf '(flatpak info --show-permissions returned non-zero)\n'
}

probe_override_file_content() {
  printf -- '--- sandbox-override file content (sysadm_t) ---\n'
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'sudo: not available; skipping override-file read\n'
    return
  fi
  local content
  content=$(sudo -r sysadm_r -t sysadm_t -- \
              cat "${OVERRIDE_PATH}" 2>&1 || true)
  if [[ -z "${content}" ]]; then
    printf '(empty or unreadable; override may be absent or the role-switched read returned empty)\n'
  else
    printf '%s\n' "${content}"
  fi
}

probe_portal_permission_rows() {
  printf -- '--- portal-permission rows for the application ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local rows
  rows=$(flatpak permission-list org.freedesktop.impl.portal.access 2>/dev/null \
           | grep -E "^org\.freedesktop\.impl\.portal\.access[[:space:]]+(camera|microphone|location)[[:space:]]+${APPLICATION_ID}" \
           || true)
  if [[ -z "${rows}" ]]; then
    printf '(no portal-permission rows for %s — pre-deploy or partial-deploy state)\n' \
      "${APPLICATION_ID}"
  else
    printf '%s\n' "${rows}"
  fi
}

probe_mime_defaults() {
  printf -- '--- MIME-default resolution ---\n'
  if command -v xdg-mime >/dev/null 2>&1; then
    printf 'x-scheme-handler/mailto -> %s\n' \
      "$(xdg-mime query default x-scheme-handler/mailto 2>/dev/null || echo '?')"
  else
    printf 'xdg-mime: not available\n'
  fi
}

probe_runtime_domain() {
  printf -- '--- live thunderbird runtime domain ---\n'
  local pid
  pid=$(pgrep -x thunderbird 2>/dev/null | head -1 || true)
  if [[ -z "${pid}" ]]; then
    printf '(no live thunderbird process)\n'
    return
  fi
  if [[ ! -d "/proc/${pid}" ]]; then
    printf '(pid=%s vanished between pgrep and read)\n' "${pid}"
    return
  fi
  local label
  label=$(cat "/proc/${pid}/attr/current" 2>/dev/null || echo '?')
  printf 'pid=%s context=%s\n' "${pid}" "${label}"
  if [[ "${label}" == *"${EXPECTED_RUNTIME_DOMAIN_SUBSTRING}"* ]]; then
    printf 'runtime_domain_substring: matches anchor %s\n' \
      "${EXPECTED_RUNTIME_DOMAIN_SUBSTRING}"
  else
    printf 'runtime_domain_substring: does not match anchor %s\n' \
      "${EXPECTED_RUNTIME_DOMAIN_SUBSTRING}"
  fi
}

probe_avc_backlog() {
  printf -- '--- AVC backlog from boot (sysadm_t) ---\n'
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'sudo: not available; skipping AVC backlog read\n'
    return
  fi
  local hits
  hits=$(sudo -r sysadm_r -t sysadm_t -- \
           ausearch -m AVC,USER_AVC -ts boot 2>&1 \
           | grep -E "(thunderbird|bwrap|flatpak.*net\.thunderbird\.Thunderbird)" \
           || true)
  if [[ -z "${hits}" ]]; then
    printf 'CLEAN\n'
  else
    printf '%s\n' "${hits}"
  fi
}

main() {
  require_tool grep
  print_header
  probe_rpm_thunderbird_tree
  probe_flatpak_ref_inventory
  probe_flatpak_permissions
  probe_override_file_content
  probe_portal_permission_rows
  probe_mime_defaults
  probe_runtime_domain
  probe_avc_backlog
  printf -- '--- end of probe ---\n'
}

main "$@"
