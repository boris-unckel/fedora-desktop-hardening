#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh — read-only diagnostics for topic_kernel_hardening.
#
# Reports current state of the four shipping configuration files, the
# running-kernel cmdline, the per-key sysctl readback, the loaded-module
# list, the merged systemd-coredump config, the PAM-limits effect on the
# current login session, and the file mode/owner/label triplets per
# shipping artefact. The probe is read-only and runnable from a staff_t-
# confined shell. SELinux-restricted-on-read sysctl keys and grubby
# --info=ALL are reported as SKIP from staff_t.
#
# Usage: bash probe.sh
#
# Exit codes:
#   0  always (probe never fails on observed state, only on tooling errors)
#   2  invocation error (missing required tool)

set -euo pipefail

readonly SYSCTL_PATH="/etc/sysctl.d/99-hardening.conf"
readonly MODPROBE_PATH="/etc/modprobe.d/hardening.conf"
readonly LIMITS_PATH="/etc/security/limits.d/90-nocore.conf"
readonly COREDUMP_PATH="/etc/systemd/coredump.conf.d/disable.conf"
readonly -a SHIPPING_PATHS=(
  "${SYSCTL_PATH}"
  "${MODPROBE_PATH}"
  "${LIMITS_PATH}"
  "${COREDUMP_PATH}"
)
readonly -a SYSCTL_KEYS=(
  "kernel.kptr_restrict"
  "kernel.dmesg_restrict"
  "kernel.yama.ptrace_scope"
  "kernel.kexec_load_disabled"
  "kernel.sysrq"
  "net.ipv4.conf.all.rp_filter"
  "net.ipv4.conf.default.rp_filter"
  "net.ipv4.conf.all.accept_redirects"
  "net.ipv4.conf.default.accept_redirects"
  "net.ipv6.conf.all.accept_redirects"
  "net.ipv6.conf.default.accept_redirects"
  "net.ipv4.conf.all.send_redirects"
  "net.ipv4.conf.default.send_redirects"
  "net.ipv4.conf.all.log_martians"
  "net.ipv4.conf.default.log_martians"
  "fs.suid_dumpable"
  "fs.protected_fifos"
  "fs.protected_regular"
  "dev.tty.ldisc_autoload"
  "net.core.bpf_jit_harden"
)
readonly -a SYSCTL_RESTRICTED_KEYS=(
  "kernel.kptr_restrict"
  "net.core.bpf_jit_harden"
  "fs.protected_fifos"
  "fs.protected_regular"
  "dev.tty.ldisc_autoload"
)
readonly -a BLACKLISTED_MODULES=(
  "cramfs"
  "freevxfs"
  "jffs2"
  "hfs"
  "hfsplus"
  "udf"
  "dccp"
  "sctp"
  "rds"
  "tipc"
  "firewire-core"
  "firewire-ohci"
  "firewire-sbp2"
)
readonly -a CMDLINE_SUBSTRINGS=(
  "slab_nomerge"
  "init_on_alloc=1"
  "init_on_free=1"
  "page_alloc.shuffle=1"
  "randomize_kstack_offset=on"
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

is_restricted_key() {
  local k="$1"
  local r
  for r in "${SYSCTL_RESTRICTED_KEYS[@]}"; do
    [[ "${k}" == "${r}" ]] && return 0
  done
  return 1
}

print_header() {
  printf '=== probe: kernel-hardening ===\n'
}

probe_shipping_files() {
  printf -- '--- shipping configuration files (cat) ---\n'
  local p
  for p in "${SHIPPING_PATHS[@]}"; do
    printf -- '\n>>> %s\n' "${p}"
    if [[ -r "${p}" ]]; then
      cat "${p}"
    else
      printf 'missing or unreadable: %s\n' "${p}"
    fi
  done
}

probe_cmdline() {
  printf -- '--- /proc/cmdline ---\n'
  if [[ -r "/proc/cmdline" ]]; then
    cat /proc/cmdline
  else
    printf 'missing or unreadable: /proc/cmdline\n'
    return
  fi
  printf -- '--- expected substrings ---\n'
  local s
  for s in "${CMDLINE_SUBSTRINGS[@]}"; do
    if grep -qwF -- "${s}" /proc/cmdline; then
      printf '  PRESENT  %s\n' "${s}"
    else
      printf '  ABSENT   %s\n' "${s}"
    fi
  done
}

probe_grubby() {
  printf -- '--- grubby --info=ALL ---\n'
  if ! is_sysadm_t; then
    printf 'SKIP needs sysadm_t\n'
    return
  fi
  if ! command -v grubby >/dev/null 2>&1; then
    printf 'grubby: not available\n'
    return
  fi
  grubby --info=ALL 2>/dev/null || true
}

probe_sysctl_keys() {
  printf -- '--- per-key sysctl readback ---\n'
  if ! command -v sysctl >/dev/null 2>&1; then
    printf 'sysctl: not available\n'
    return
  fi
  local k value
  for k in "${SYSCTL_KEYS[@]}"; do
    if is_restricted_key "${k}" && ! is_sysadm_t; then
      printf '  %-44s SKIP needs sysadm_t\n' "${k}"
      continue
    fi
    value=$(sysctl -n "${k}" 2>/dev/null || echo "?")
    printf '  %-44s %s\n' "${k}" "${value}"
  done
}

probe_lsmod() {
  printf -- '--- lsmod blacklisted-module presence ---\n'
  if ! command -v lsmod >/dev/null 2>&1; then
    printf 'lsmod: not available\n'
    return
  fi
  local m hits
  for m in "${BLACKLISTED_MODULES[@]}"; do
    hits=$(lsmod 2>/dev/null | grep -cw "^${m}" || true)
    if [[ "${hits}" == "0" ]]; then
      printf '  %-20s ABSENT\n' "${m}"
    else
      printf '  %-20s LOADED (presence is drift)\n' "${m}"
    fi
  done
}

probe_coredump() {
  printf -- '--- systemd-analyze cat-config systemd/coredump.conf ---\n'
  if ! command -v systemd-analyze >/dev/null 2>&1; then
    printf 'systemd-analyze: not available\n'
    return
  fi
  systemd-analyze cat-config systemd/coredump.conf 2>/dev/null || true
}

probe_ulimit_core() {
  printf -- '--- ulimit -c (current shell) ---\n'
  ulimit -c 2>/dev/null || printf '?\n'
}

probe_file_modes() {
  printf -- '--- shipping file modes / owners / labels ---\n'
  local p
  for p in "${SHIPPING_PATHS[@]}"; do
    if [[ -e "${p}" ]]; then
      stat -c '%n %a %U %G %C' "${p}" 2>/dev/null \
        || printf 'stat failed: %s\n' "${p}"
    else
      printf 'missing: %s\n' "${p}"
    fi
  done
}

probe_matchpathcon() {
  printf -- '--- matchpathcon shipping paths ---\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf 'matchpathcon: not available\n'
    return
  fi
  local p
  for p in "${SHIPPING_PATHS[@]}"; do
    matchpathcon "${p}" 2>/dev/null || printf 'matchpathcon failed: %s\n' "${p}"
  done
}

main() {
  require_tool awk
  require_tool grep
  require_tool id
  print_header
  probe_shipping_files
  probe_cmdline
  probe_grubby
  probe_sysctl_keys
  probe_lsmod
  probe_coredump
  probe_ulimit_core
  probe_file_modes
  probe_matchpathcon
  printf -- '--- end of probe ---\n'
}

main "$@"
