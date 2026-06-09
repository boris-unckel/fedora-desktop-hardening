#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_flatpak_portal_cache.
#
# Reports current state of the per-user xdg-document-portal cache: package
# presence, the operator's runtime SELinux mapping, the user-systemd state
# and main PID of xdg-document-portal.service, the persistent-class store
# count via `flatpak documents list`, the FUSE-anchored full-cache view
# under /run/user/${uid}/doc/by-app/, the operator-installed Flatpak
# inventory and per-application permission summary, and the per-<appid>
# system-wide override-store content (read under role-switched sysadm_t).
#
# The probe never gates on observed state. The cache may be empty, may
# carry pre-reset persistent or transient tokens, or may be in a
# transitional shape. The probe inventories what is there.
#
# Liveness signal: `[[ -d /proc/${pid} ]]` against the user-systemd-
# reported main PID (never `kill -0`, which returns EPERM cross-user from
# a non-privileged context and would misreport a live process as dead).
#
# Override-store reads are gated behind a sysadm_t domain check and run
# under `sudo -r sysadm_r -t sysadm_t`; from a staff_t or unconfined_u
# shell the probe attempts the role-switched call and records the outcome
# without judging it.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing required tool, user-systemd not
#      addressable in the current connection mode)

set -euo pipefail

readonly PORTAL_SERVICE="xdg-document-portal.service"
readonly EXPECTED_SEUSER_SUBSTRING="staff_u"
readonly OVERRIDE_STORE_DIR="/var/lib/flatpak/overrides"
readonly -a CORE_PACKAGES=(
  "flatpak"
  "xdg-desktop-portal"
)
readonly -a BACKEND_PACKAGES=(
  "xdg-desktop-portal-gtk"
  "xdg-desktop-portal-gnome"
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

fuse_by_app_path() {
  printf '/run/user/%s/doc/by-app' "$(id -u)"
}

print_header() {
  printf '=== probe: flatpak-portal-cache ===\n'
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
  local backend_present=0
  for pkg in "${BACKEND_PACKAGES[@]}"; do
    if rpm -q "${pkg}" >/dev/null 2>&1; then
      printf 'backend   %s: installed (%s)\n' "${pkg}" "$(rpm -q "${pkg}")"
      backend_present=1
    else
      printf 'backend   %s: absent\n' "${pkg}"
    fi
  done
  if (( backend_present == 0 )); then
    printf 'backend slot: neither GTK nor GNOME backend present (informational)\n'
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
    printf 'applicability: does not match anchor %s; this Topic'\''s framing assumes a staff_u-mapped login\n' \
      "${EXPECTED_SEUSER_SUBSTRING}"
  fi
}

probe_portal_service() {
  printf -- '--- user-systemd state of %s ---\n' "${PORTAL_SERVICE}"
  if ! command -v systemctl >/dev/null 2>&1; then
    printf 'systemctl: not available\n'
    return
  fi
  systemctl --user status "${PORTAL_SERVICE}" --no-pager 2>&1 \
    || printf '(systemctl --user status returned non-zero)\n'
  local pid
  pid=$(systemctl --user show -p MainPID --value "${PORTAL_SERVICE}" \
          2>/dev/null \
          || echo 0)
  printf 'main_pid: %s\n' "${pid}"
  if [[ "${pid}" != "0" ]] && [[ -d "/proc/${pid}" ]]; then
    printf 'liveness: /proc/%s present\n' "${pid}"
  else
    printf 'liveness: pid not running (service is inactive or has not yet been re-spawned)\n'
  fi
}

probe_persistent_store() {
  printf -- '--- persistent-class store (flatpak documents list) ---\n'
  printf 'note: this is a partial cache view — transient tokens are not listed here\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  local listing
  listing=$(flatpak documents list 2>&1 || true)
  if [[ -z "${listing}" ]]; then
    printf '(flatpak documents list returned empty)\n'
    return
  fi
  printf '%s\n' "${listing}"
  local data_lines
  data_lines=$(printf '%s\n' "${listing}" \
                 | grep -cE '^[^[:space:]]' \
                 || true)
  printf 'persistent_store_line_count: %s\n' "${data_lines}"
}

probe_fuse_by_app() {
  local by_app
  by_app=$(fuse_by_app_path)
  printf -- '--- FUSE-by-app full-cache view at %s ---\n' "${by_app}"
  if [[ ! -d "${by_app}" ]]; then
    printf '(by-app/ does not exist — portal-service has not been re-spawned, '
    printf 'or no Flatpak application has requested a token since the last service start)\n'
    return
  fi
  ls -la "${by_app}" 2>/dev/null \
    || printf '(by-app/ exists but is not listable from the current context)\n'
  local appdir token_count app_id
  for appdir in "${by_app}"/*; do
    [[ -d "${appdir}" ]] || continue
    app_id=$(basename "${appdir}")
    token_count=$(find "${appdir}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
                    | wc -l \
                    || echo 0)
    printf 'app=%-50s token_count=%s\n' "${app_id}" "${token_count}"
  done
}

probe_app_inventory() {
  printf -- '--- flatpak application inventory ---\n'
  if ! command -v flatpak >/dev/null 2>&1; then
    printf 'flatpak: not available\n'
    return
  fi
  flatpak list --app --columns=application,permissions 2>&1 \
    || printf '(flatpak list returned non-zero)\n'
}

probe_override_store() {
  printf -- '--- system-wide override store at %s (sysadm_t-only read) ---\n' \
    "${OVERRIDE_STORE_DIR}"
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'sudo: not available; skipping override-store read\n'
    return
  fi
  local listing
  listing=$(sudo -r sysadm_r -t sysadm_t -- ls "${OVERRIDE_STORE_DIR}" 2>&1 \
              || true)
  if [[ -z "${listing}" ]]; then
    printf '(no system-wide overrides, or the role-switched read returned empty)\n'
    return
  fi
  printf '%s\n' "${listing}"
  local appid
  while IFS= read -r appid; do
    [[ -z "${appid}" ]] && continue
    [[ "${appid}" == *":"* ]] && continue
    printf -- '--- override content: %s ---\n' "${appid}"
    sudo -r sysadm_r -t sysadm_t -- \
      cat "${OVERRIDE_STORE_DIR}/${appid}" 2>&1 \
      || printf '(cat returned non-zero)\n'
  done <<< "${listing}"
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_packages
  probe_operator_mapping
  probe_portal_service
  probe_persistent_store
  probe_fuse_by_app
  probe_app_inventory
  probe_override_store
  printf -- '--- end of probe ---\n'
}

main "$@"
