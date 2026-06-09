#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_switcheroo_control.
#
# Reports current state of switcheroo-control.service, the
# WantedBy=graphical.target symlink, the hybrid-GPU detection signal,
# and the recent journal tail for the unit. The probe is read-only and
# runnable from a staff_t-confined shell.
#
# The probe never gates on observed state; the end-state of an applied
# host is the unit disabled, inactive(dead), and the symlink absent.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling)
#   2  invocation error (missing systemctl, etc.)

set -euo pipefail

readonly UNIT="switcheroo-control.service"
readonly DROPIN_DIR="/etc/systemd/system/switcheroo-control.service.d"
readonly GRAPHICAL_WANTS_SYMLINK="/etc/systemd/system/graphical.target.wants/switcheroo-control.service"
readonly BINARY_PATH="/usr/libexec/switcheroo-control"
readonly STOCK_UNIT_PATH="/usr/lib/systemd/system/switcheroo-control.service"
readonly -a CORE_PACKAGES=(
  "switcheroo-control"
)
readonly -a TRACKED_DIRECTIVES=(
  Type
  ActiveState
  SubState
  Result
  MainPID
  LoadState
  UnitFileState
)

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

print_header() {
  printf '=== probe: %s ===\n' "${UNIT}"
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

probe_hybrid_gpu_detection() {
  printf -- '--- hybrid-GPU detection (PCI display+3D enumeration) ---\n'
  if ! command -v lspci >/dev/null 2>&1; then
    printf 'lspci: not available\n'
    return
  fi
  local display_lines threed_lines display_count threed_count gpu_count
  display_lines=$(lspci -d ::0300 -mm 2>/dev/null || true)
  threed_lines=$(lspci -d ::0302 -mm 2>/dev/null || true)
  display_count=$(printf '%s' "${display_lines}" | grep -c '.' || true)
  threed_count=$(printf '%s' "${threed_lines}" | grep -c '.' || true)
  gpu_count=$(( display_count + threed_count ))
  printf 'display controllers (class 0300, count=%s):\n' "${display_count}"
  if [[ -n "${display_lines}" ]]; then
    printf '%s\n' "${display_lines}"
  else
    printf '(none)\n'
  fi
  printf '3D controllers (class 0302, count=%s):\n' "${threed_count}"
  if [[ -n "${threed_lines}" ]]; then
    printf '%s\n' "${threed_lines}"
  else
    printf '(none)\n'
  fi
  printf 'gpu_count=%s\n' "${gpu_count}"
  if (( gpu_count >= 2 )); then
    printf 'hybrid-GPU detected; topic does not apply on this host\n'
  fi
}

probe_unit_state() {
  printf -- '--- unit state ---\n'
  systemctl is-active "${UNIT}" || true
  systemctl is-enabled "${UNIT}" || true
}

probe_stock_unit() {
  printf -- '--- stock unit recon ---\n'
  if [[ ! -f "${STOCK_UNIT_PATH}" ]]; then
    printf 'stock unit missing: %s\n' "${STOCK_UNIT_PATH}"
    return
  fi
  grep -E '^(Type|ExecStart|BusName|WantedBy|User|Group)=' \
    "${STOCK_UNIT_PATH}" \
    || printf '(no matching directive in stock unit)\n'
}

probe_dropin_directory() {
  printf -- '--- drop-in directory (expected absent) ---\n'
  if [[ -d "${DROPIN_DIR}" ]]; then
    # ls -ldZ surfaces SELinux label and mode for operator inspection.
    # shellcheck disable=SC2012
    ls -ldZ "${DROPIN_DIR}" || true
  else
    printf 'absent: %s\n' "${DROPIN_DIR}"
  fi
}

probe_graphical_wants_symlink() {
  printf -- '--- graphical.target.wants symlink (expected absent) ---\n'
  if [[ -L "${GRAPHICAL_WANTS_SYMLINK}" ]]; then
    # ls -lZ surfaces the SELinux label for the operator.
    # shellcheck disable=SC2012
    ls -lZ "${GRAPHICAL_WANTS_SYMLINK}" || true
    printf 'symlink_state: present\n'
  elif [[ -e "${GRAPHICAL_WANTS_SYMLINK}" ]]; then
    printf 'unexpected non-symlink at %s\n' "${GRAPHICAL_WANTS_SYMLINK}"
  else
    printf 'symlink_state: absent\n'
  fi
}

probe_binary_fcontext() {
  printf -- '--- fcontext mapping for daemon binary ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  matchpathcon "${BINARY_PATH}" 2>/dev/null || true
}

probe_directives() {
  printf -- '--- effective directive values ---\n'
  local prop value
  for prop in "${TRACKED_DIRECTIVES[@]}"; do
    value=$(systemctl show -p "${prop}" --value "${UNIT}" 2>/dev/null || true)
    printf '%-26s : %s\n' "${prop}" "${value}"
  done
}

probe_journal_tail() {
  printf -- '--- journal tail for unit since boot ---\n'
  if ! command -v journalctl >/dev/null 2>&1; then
    printf 'journalctl: not available\n'
    return
  fi
  # On a correctly applied host the journal carries no entries since
  # boot for the unit (the unit never started this boot); the tail is
  # empty in that case.
  journalctl -u "${UNIT}" -b --no-pager 2>/dev/null \
    | tail -20 \
    || printf '(no journal entries)\n'
}

main() {
  require_tool systemctl
  print_header
  probe_packages
  probe_hybrid_gpu_detection
  probe_unit_state
  probe_stock_unit
  probe_dropin_directory
  probe_graphical_wants_symlink
  probe_binary_fcontext
  probe_directives
  probe_journal_tail
  printf -- '--- end of probe ---\n'
}

main "$@"
