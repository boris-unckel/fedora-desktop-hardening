#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh — Soll/Ist comparison for topic_flatpak_collection_id.
#
# Compares observed runtime state against the expected post-repair
# end-state declared in docs/reference/topics/flatpak-collection-id.md:
#
#   - Per-remote `collection-id=<binding>` line is present under the
#     `[remote "<name>"]` section heading in /var/lib/flatpak/repo/config
#     for every <remote> in the role's binding mapping that is currently
#     configured on the host. The configured <binding> matches the
#     mapping value.
#   - The dry-run `flatpak update --noninteractive --no-deploy` produces
#     zero `Treating remote fetch error as non-fatal` warnings.
#
# A remote named in the role's mapping but not currently configured on
# the host (the operator removed it after the role's last apply) is
# reported as absent and does not produce a fail; the Topic is
# per-remote-applicable, not all-or-nothing.
#
# Liveness: `[[ -d /proc/${pid} ]]` is the canonical pattern this tree
# uses where a liveness check is needed (never `kill -0`, which returns
# EPERM cross-user from a non-privileged context and would misreport a
# live process as dead). The verify does not in fact need a liveness
# check, because the config-file read and the dry-run line-count read
# are sufficient end-state signals.
#
# Config-file reads and dry-run flatpak invocations are gated behind a
# `sudo -r sysadm_r -t sysadm_t` role-switch.
#
# Hardcoded expected values: the verify embeds the role's defaults
# binding mapping; an operator who has extended the mapping in
# group_vars or a playbook should re-generate this file or override
# EXPECTED_BINDINGS before invoking the verify.
#
# Usage: bash verify.sh
#
# Exit codes:
#   0  state matches expectation (or per-remote informational absence)
#   1  drift detected
#   2  invocation error (missing required tool, sudo not available)

set -euo pipefail

readonly REPO_CONFIG_PATH="/var/lib/flatpak/repo/config"
readonly OCI_URL_PREFIX="oci+"
readonly NONFATAL_WARNING_TEXT="Treating remote fetch error as non-fatal"
readonly EXPECTED_NONFATAL_FETCH_WARNING_COUNT="0"

# Per-remote binding mapping. Keep aligned with
# defaults/main.yml::topic_flatpak_collection_id_remote_bindings.
readonly -A EXPECTED_BINDINGS=(
  ["flathub"]="org.flathub.Stable"
  ["gnome-nightly"]="org.gnome.Nightly"
)

declare -i fail_state=0

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'verify: required tool not found: %s\n' "${tool}" >&2
    exit 2
  fi
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

verify_sudo_present() {
  if [[ ! -x /usr/bin/sudo ]]; then
    printf 'verify: /usr/bin/sudo not available\n' >&2
    exit 2
  fi
}

remote_is_configured() {
  local remote="$1"
  flatpak remotes --columns=name 2>/dev/null \
    | awk 'NR>1 {print $1}' \
    | grep -Fxq "${remote}"
}

remote_url_prefix() {
  local remote="$1"
  flatpak remotes --columns=name,url 2>/dev/null \
    | awk -v r="${remote}" 'NR>1 && $1 == r {print $2}'
}

read_collection_id() {
  local remote="$1"
  sudo -r sysadm_r -t sysadm_t -- \
    awk -v r="${remote}" '
      /^\[remote "/ {
        in_section = 0
        if ($0 == "[remote \"" r "\"]") { in_section = 1 }
        next
      }
      /^\[/ { in_section = 0; next }
      in_section && /^collection-id=/ {
        sub(/^collection-id=/, "")
        print
        exit
      }
    ' "${REPO_CONFIG_PATH}" 2>/dev/null \
    || true
}

verify_per_remote_bindings() {
  local remote expected actual url_prefix
  for remote in "${!EXPECTED_BINDINGS[@]}"; do
    expected="${EXPECTED_BINDINGS[${remote}]}"
    if ! remote_is_configured "${remote}"; then
      report_info "collection_id[${remote}]" \
        "remote not configured on this host (per-remote-applicable; not drift)"
      continue
    fi
    url_prefix=$(remote_url_prefix "${remote}")
    if [[ "${url_prefix}" == "${OCI_URL_PREFIX}"* ]]; then
      report_info "collection_id[${remote}]" \
        "remote is OCI-typed (url=${url_prefix}); collection-id not meaningful, repair does not apply"
      continue
    fi
    actual=$(read_collection_id "${remote}")
    if [[ "${actual}" == "${expected}" ]]; then
      report_ok "collection_id[${remote}]" \
        "expected=${expected} actual=${actual}"
    elif [[ -z "${actual}" ]]; then
      report_fail "collection_id[${remote}]" \
        "expected=${expected} actual=(absent) (binding missing — Pre-1.13-initialized state, or rolled back to empty-string)"
    else
      report_fail "collection_id[${remote}]" \
        "expected=${expected} actual=${actual} (binding present but does not match the configured value — operator override or upstream binding rotation)"
    fi
  done
}

verify_nonfatal_fetch_warning_count() {
  local full_output line_count
  full_output=$(sudo -r sysadm_r -t sysadm_t -- \
                  flatpak update --noninteractive --no-deploy 2>&1 \
                  || true)
  line_count=$(printf '%s\n' "${full_output}" \
                 | grep -c "${NONFATAL_WARNING_TEXT}" \
                 || true)
  [[ -z "${line_count}" ]] && line_count="0"
  if [[ "${line_count}" == "${EXPECTED_NONFATAL_FETCH_WARNING_COUNT}" ]]; then
    report_ok "nonfatal_fetch_warning_count" \
      "expected=${EXPECTED_NONFATAL_FETCH_WARNING_COUNT} actual=${line_count}"
  else
    report_fail "nonfatal_fetch_warning_count" \
      "expected=${EXPECTED_NONFATAL_FETCH_WARNING_COUNT} actual=${line_count} (silent-skip class still firing — see per-remote check above for binding state, or investigate upstream condition for an unrelated remote)"
  fi
}

main() {
  require_tool awk
  require_tool grep
  require_tool flatpak
  verify_sudo_present
  verify_per_remote_bindings
  verify_nonfatal_fetch_warning_count
  exit "${fail_state}"
}

main "$@"
