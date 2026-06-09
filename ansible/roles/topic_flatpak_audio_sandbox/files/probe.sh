#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_flatpak_audio_sandbox.
#
# Reports current state of the bwrap audio bind-mount surface: package
# presence, the operator-installed Flatpak inventory (with audio-vs-
# audio-silent discrimination on the per-application permissions
# column), the operator's runtime SELinux mapping, the priority-400
# module slot, the single allow surface of the topic-owned CIL module,
# and the AVC stream filtered for the functional-class records since
# boot.
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

readonly MODULE_NAME="flatpak_audio_sandbox"
readonly MODULE_PRIORITY="400"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly AUDIO_PERMISSION_SUBSTRING="pulseaudio"
readonly -a CORE_PACKAGES=(
  "flatpak"
  "bubblewrap"
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
  printf '=== probe: flatpak-audio-sandbox ===\n'
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

probe_application_inventory() {
  printf -- '--- flatpak application inventory (audio / audio-silent discrimination) ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak list --columns=application,permissions 2>/dev/null || true)
  if [[ -z "${listing}" ]]; then
    printf '(no flatpak applications installed)\n'
    return
  fi
  printf '%s\n' "${listing}"
  local audio_count=0
  local total_count=0
  local line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    total_count=$(( total_count + 1 ))
    if [[ "${line}" == *"${AUDIO_PERMISSION_SUBSTRING}"* ]]; then
      audio_count=$(( audio_count + 1 ))
    fi
  done <<< "${listing}"
  printf 'application_total_count: %d\n' "${total_count}"
  printf 'audio_permission_application_count: %d\n' "${audio_count}"
  if (( audio_count == 0 )); then
    printf 'applicability: no application declares the %s permission; gap currently unreachable\n' \
      "${AUDIO_PERMISSION_SUBSTRING}"
    printf '               (the policy patch still applies pre-emptively for future application installs)\n'
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
  printf -- '--- functional rule (staff_t × device_t : dir mounton) ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP: needs sysadm_t\n'
    return
  fi
  if ! command -v sesearch >/dev/null 2>&1; then
    printf 'sesearch: not available\n'
    return
  fi
  sesearch -A \
    -s staff_t \
    -t device_t \
    -c dir \
    -p mounton \
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
    | grep -E '(staff_t.*device_t.*dir|/newroot/dev/snd)' \
    | head -10 \
    || printf '(no functional-class denials since boot)\n'
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_application_inventory
  probe_operator_mapping
  probe_module_slot
  probe_rule
  probe_avc_stream
  printf -- '--- end of probe ---\n'
}

main "$@"
