#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_python_pip_user_tree.
#
# Reports the active interpreter identity, the active stdlib path (load-
# bearing for the marker-path resolution), the marker presence across all
# installed Python minors, the RPM-non-ownership invariant for the active-
# minor marker, the active pip identity, the user-tree presence per Python
# minor, and the sudo-pip-layer detection. The probe is read-only and
# runnable from a staff_t-confined shell. The probe never gates on
# observed state.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly MARKER_FILENAME="EXTERNALLY-MANAGED"
readonly STDLIB_PARENT="/usr/lib64"
readonly USERLOCAL_LIB="/usr/local/lib"
readonly USERLOCAL_BIN="/usr/local/bin"
readonly USERLOCAL_SBIN="/usr/local/sbin"

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'probe: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
}

resolve_user_home() {
  printf '%s' "${HOME:-/home/$(id -un)}"
}

print_header() {
  printf '=== probe: python pip user-tree discipline ===\n'
}

probe_interpreter_identity() {
  printf -- '--- interpreter identity ---\n'
  python3 --version 2>&1 || true
  python3 -c 'import sys; print(sys.executable)' 2>&1 || true
}

probe_stdlib_path() {
  printf -- '--- active stdlib path ---\n'
  python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>&1 \
    || true
}

probe_marker_presence() {
  printf -- '--- marker presence across all installed Python minors ---\n'
  local pattern="${STDLIB_PARENT}/python3.*/${MARKER_FILENAME}"
  # shellcheck disable=SC2086
  # The glob is intentional: ls expands the pattern across all stdlib dirs.
  ls -la ${pattern} 2>/dev/null || printf '(no markers found)\n'
}

probe_active_marker_rpm_owner() {
  printf -- '--- active-minor marker RPM ownership ---\n'
  if ! command -v rpm >/dev/null 2>&1; then
    printf 'rpm: not available\n'
    return
  fi
  local stdlib marker_path
  stdlib=$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' \
             2>/dev/null || printf '')
  if [[ -z "${stdlib}" ]]; then
    printf '(stdlib path could not be resolved)\n'
    return
  fi
  marker_path="${stdlib}/${MARKER_FILENAME}"
  if [[ ! -f "${marker_path}" ]]; then
    printf 'marker not present at %s\n' "${marker_path}"
    return
  fi
  rpm -qf "${marker_path}" 2>&1 || true
}

probe_pip_identity() {
  printf -- '--- pip identity ---\n'
  if command -v pip3 >/dev/null 2>&1; then
    pip3 --version 2>&1 || true
  else
    printf 'pip3: not available\n'
  fi
}

probe_user_trees() {
  printf -- '--- user-tree presence per Python minor ---\n'
  local home pattern
  home=$(resolve_user_home)
  pattern="${home}/.local/lib/python3.*"
  # shellcheck disable=SC2086
  # The glob is intentional: ls expands the pattern across all user-tree
  # python3.X subdirectories.
  ls -d ${pattern} 2>/dev/null || printf '(no user-trees found)\n'
}

probe_sudo_pip_layer() {
  printf -- '--- sudo-pip layer detection (expected: empty) ---\n'
  local lib_pattern="${USERLOCAL_LIB}/python3.*"
  local bin_pattern="${USERLOCAL_BIN}/pip*"
  local sbin_pattern="${USERLOCAL_SBIN}/pip*"
  # shellcheck disable=SC2086
  ls -d ${lib_pattern} 2>/dev/null || printf '(no /usr/local/lib/python3.*)\n'
  # shellcheck disable=SC2086
  ls ${bin_pattern} ${sbin_pattern} 2>/dev/null \
    || printf '(no /usr/local/{bin,sbin}/pip*)\n'
}

probe_pip_path_resolution() {
  printf -- '--- PATH resolution for pip3 ---\n'
  type -a pip3 2>/dev/null || printf '(pip3 not found on PATH)\n'
}

main() {
  require_tool python3
  print_header
  probe_interpreter_identity
  probe_stdlib_path
  probe_marker_presence
  probe_active_marker_rpm_owner
  probe_pip_identity
  probe_user_trees
  probe_sudo_pip_layer
  probe_pip_path_resolution
  printf -- '--- end of probe ---\n'
}

main "$@"
