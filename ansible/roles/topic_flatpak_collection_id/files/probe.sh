#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_flatpak_collection_id.
#
# Reports current state of the system-wide Flatpak ostree store's
# per-remote collection-id binding: package presence, the operator's
# runtime SELinux mapping, the operator-configured remote inventory with
# OCI-vs-ostree discrimination, the ostree-side authoritative read of the
# per-remote configuration blocks, the diagnostic non-fatal-fetch-warning
# line-count from a dry-run `flatpak update --noninteractive --no-deploy`,
# and the operator-installed ref inventory by remote-of-origin.
#
# The probe never gates on observed state. The host may be Pre-1.13-
# initialized (collection-id missing on one or more ostree-typed remotes),
# already repaired (collection-id present on every targeted remote), or
# in a partial-repair shape. The probe inventories what is there.
#
# Liveness signal: `[[ -d /proc/${pid} ]]` is the canonical pattern this
# tree uses where a liveness check is needed (never `kill -0`, which
# returns EPERM cross-user from a non-privileged context and would
# misreport a live process as dead). The probe does not in fact need a
# liveness check, because the config-file read and the dry-run
# line-count read are sufficient end-state signals.
#
# Config-file reads and dry-run flatpak invocations are gated behind a
# `sudo -r sysadm_r -t sysadm_t` role-switch; from a staff_t or
# unconfined_u shell the probe attempts the role-switched call and
# records the outcome without judging it.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool: flatpak or ostree
#      package not installed)

set -euo pipefail

readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly REPO_CONFIG_PATH="/var/lib/flatpak/repo/config"
readonly OCI_URL_PREFIX="oci+"
readonly NONFATAL_WARNING_TEXT="Treating remote fetch error as non-fatal"
readonly -a CORE_PACKAGES=(
  "flatpak"
  "ostree"
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

print_header() {
  printf '=== probe: flatpak-collection-id ===\n'
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
      printf 'core      %s: missing (Topic out of scope)\n' "${pkg}"
    fi
  done
}

probe_operator_mapping() {
  printf -- '--- operator runtime SELinux mapping ---\n'
  local id_z
  id_z=$(id -Z 2>/dev/null || true)
  printf 'id -Z: %s\n' "${id_z}"
  if [[ "${id_z}" == *"${EXPECTED_SEUSER_SUBSTRING}"* ]]; then
    printf 'applicability: matches anchor %s\n' "${EXPECTED_SEUSER_SUBSTRING}"
  else
    printf 'applicability: does not match anchor %s; this Topic'\''s framing assumes a staff_u-mapped login\n' \
      "${EXPECTED_SEUSER_SUBSTRING}"
  fi
}

probe_remote_inventory() {
  printf -- '--- flatpak remote inventory ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak remotes --columns=name,url,collection 2>&1 || true)
  printf '%s\n' "${listing}"
  printf -- '--- remote-type discrimination ---\n'
  local name url collection_value
  while IFS=$'\t' read -r name url collection_value; do
    [[ -z "${name}" ]] && continue
    [[ "${name}" =~ ^Name ]] && continue
    if [[ "${url}" == "${OCI_URL_PREFIX}"* ]]; then
      printf 'remote=%-30s type=oci    collection=%s (collection-id not meaningful on OCI; repair does not apply)\n' \
        "${name}" "${collection_value:-(empty)}"
    else
      if [[ -z "${collection_value}" ]]; then
        printf 'remote=%-30s type=ostree collection=(empty) (candidate for repair)\n' \
          "${name}"
      else
        printf 'remote=%-30s type=ostree collection=%s (binding present)\n' \
          "${name}" "${collection_value}"
      fi
    fi
  done < <(flatpak remotes --columns=name,url,collection 2>/dev/null || true)
}

probe_config_file() {
  printf -- '--- ostree-side authoritative read of %s (sysadm_t) ---\n' \
    "${REPO_CONFIG_PATH}"
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'sudo: not available; skipping config-file read\n'
    return
  fi
  local content
  content=$(sudo -r sysadm_r -t sysadm_t -- \
              grep -E '^\[remote |^collection-id=' \
              "${REPO_CONFIG_PATH}" 2>&1 \
              || true)
  if [[ -z "${content}" ]]; then
    printf '(no [remote ...] sections or collection-id= lines found, or the role-switched read returned empty)\n'
    return
  fi
  printf '%s\n' "${content}"
}

probe_diagnostic_line_count() {
  printf -- '--- dry-run flatpak update non-fatal-fetch-warning line-count (sysadm_t) ---\n'
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'sudo: not available; skipping dry-run\n'
    return
  fi
  local full_output line_count
  full_output=$(sudo -r sysadm_r -t sysadm_t -- \
                  flatpak update --noninteractive --no-deploy 2>&1 \
                  || true)
  line_count=$(printf '%s\n' "${full_output}" \
                 | grep -c "${NONFATAL_WARNING_TEXT}" \
                 || true)
  [[ -z "${line_count}" ]] && line_count="0"
  printf 'nonfatal_fetch_warning_count: %s\n' "${line_count}"
  printf 'note: a high value (typically ten or more on a hardened desktop) combined with a zero applied-update count is the load-bearing fingerprint of the collection-id binding gap.\n'
  printf -- '--- dry-run full output (informational) ---\n'
  printf '%s\n' "${full_output}"
}

probe_ref_inventory() {
  printf -- '--- operator-installed ref inventory by remote-of-origin ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  printf '\n[applications]\n'
  flatpak list --app --columns=application,origin 2>&1 \
    || printf '(flatpak list --app returned non-zero)\n'
  printf '\n[runtimes]\n'
  flatpak list --runtime --columns=ref,origin 2>&1 \
    || printf '(flatpak list --runtime returned non-zero)\n'
}

main() {
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_operator_mapping
  probe_remote_inventory
  probe_config_file
  probe_diagnostic_line_count
  probe_ref_inventory
  printf -- '--- end of probe ---\n'
}

main "$@"
