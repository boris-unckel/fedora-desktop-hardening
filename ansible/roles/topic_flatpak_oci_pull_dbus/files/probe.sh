#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_flatpak_oci_pull_dbus.
#
# Reports current state of the flatpak-oci-pull D-Bus session-bus
# surface: package presence, the operator-configured Flatpak remote
# inventory (with OCI-vs-ostree discrimination), the operator's
# runtime SELinux mapping, the priority-400 module slot, the single
# allow surface of the topic-owned CIL module, and the AVC stream
# filtered for the functional-class records since boot.
#
# The probe never gates on observed state; the end-state of an applied
# host is the priority-400 module installed and the single allow
# surface present in the loaded policy.
#
# Stages that need policy-store reads (semodule, sesearch, ausearch)
# are gated behind a sysadm_t domain check and reported as SKIP from a
# staff_t shell.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MODULE_NAME="flatpak_oci_pull_dbus"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly OCI_REMOTE_URL_PREFIX="oci+"
readonly -a CORE_PACKAGES=(
  "flatpak"
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

current_type() {
  id -Z 2>/dev/null | awk -F: '{print $3}'
}

is_sysadm_t() {
  [[ "$(current_type)" == "sysadm_t" ]]
}

print_header() {
  printf '=== probe: flatpak-oci-pull-dbus ===\n'
}

probe_packages() {
  printf -- '--- packages ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf 'rpm: not available\n'
    return
  fi
  local pkg
  for pkg in "${CORE_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      printf 'core      %s: installed (%s)\n' "${pkg}" "$(rpm -q "${pkg}")"
    else
      printf 'core      %s: missing\n' "${pkg}"
    fi
  done
}

probe_remote_inventory() {
  printf -- '--- flatpak remote inventory (OCI / ostree discrimination) ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak remotes --columns=name,url,collection 2>/dev/null || true)
  if [[ -z "${listing}" ]]; then
    printf '(no remotes configured)\n'
    return
  fi
  printf '%s\n' "${listing}"
  local oci_count=0
  local ostree_count=0
  local line url
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    url=$(printf '%s' "${line}" | awk '{print $2}')
    [[ -z "${url}" || "${url}" == "Url" ]] && continue
    if [[ "${url}" == "${OCI_REMOTE_URL_PREFIX}"* ]]; then
      oci_count=$(( oci_count + 1 ))
    else
      ostree_count=$(( ostree_count + 1 ))
    fi
  done <<< "${listing}"
  printf 'oci_remote_count: %d\n' "${oci_count}"
  printf 'ostree_remote_count: %d\n' "${ostree_count}"
  if (( oci_count == 0 )); then
    printf 'applicability: no OCI-typed remote configured; gap currently unreachable\n'
    printf '               (the policy patch still applies pre-emptively for future remote additions)\n'
  fi
}

probe_operator_mapping() {
  printf -- '--- operator runtime SELinux mapping ---\n'
  local id_z
  id_z=$(id -Z 2>/dev/null || true)
  printf 'id -Z: %s\n' "${id_z}"
  if [[ "${id_z}" == *"${EXPECTED_SEUSER_SUBSTRING}"* ]]; then
    printf 'applicability: matches anchor %s\n' "${EXPECTED_SEUSER_SUBSTRING}"
  else
    printf 'applicability: does NOT match anchor %s; topic does not apply\n' \
      "${EXPECTED_SEUSER_SUBSTRING}"
  fi
}

probe_module_slot() {
  printf -- '--- priority-%s module slot ---\n' "${MODULE_PRIORITY}"
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t (run via `sudo -r sysadm_r -t sysadm_t bash probe.sh`)\n'
    return
  fi
  if ! command -v semodule >/dev/null 2>&1; then
    printf 'semodule: not available\n'
    return
  fi
  semodule -lfull \
    | grep -wE "^[ ]*${MODULE_PRIORITY}.*${MODULE_NAME}" \
    || printf '(module not installed at priority %s)\n' "${MODULE_PRIORITY}"
}

probe_rule() {
  printf -- '--- functional rule (sysadm_t × unconfined_dbusd_t : unix_stream_socket connectto) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A \
    -s sysadm_t \
    -t unconfined_dbusd_t \
    -c unix_stream_socket \
    -p connectto \
    || printf '(no allow surface)\n'
}

probe_avc_stream() {
  printf -- '--- AVC stream since boot (functional class only) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v ausearch >/dev/null 2>&1; then
    printf 'ausearch: not available\n'
    return
  fi
  ausearch -m AVC,USER_AVC -ts boot 2>/dev/null \
    | grep -E '(sysadm_t.*unconfined_dbusd_t.*unix_stream_socket|/run/user/0/bus)' \
    | head -10 \
    || printf '(no functional-class denials since boot)\n'
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_remote_inventory
  probe_operator_mapping
  probe_module_slot
  probe_rule
  probe_avc_stream
  printf -- '--- end of probe ---\n'
}

main "$@"
