#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# teardown.sh -- remove all livetest infrastructure to stop provider costs.
#
# Run from the operator workstation, and only on an explicit operator request:
# under the keep-reusable-infrastructure policy the base snapshot, network, key,
# and control node are normally kept between runs because re-creating them costs
# far more (in time and tokens) than the idle server. This script is the manual
# "stop everything" switch.
#
# Order matters: detach-by-deleting servers first (a network with attached
# servers cannot be removed, and a firewall applied to a server cannot be
# deleted), then snapshots, then the network, firewalls, and key.

SCRIPT_NAME="teardown"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${HERE}/lib.sh"

delete_servers() {
  local names
  names="$(hcloud server list -o noheader -o columns=name 2>/dev/null \
    | grep -E '^livetest-|^managed-' || true)"
  local n
  for n in ${names}; do
    log "deleting server ${n}"
    hcloud server delete "${n}" >/dev/null 2>&1 || true
  done
}

delete_snapshots() {
  local ids
  ids="$(hcloud image list --type snapshot --selector "livetest" \
    -o noheader -o columns=id 2>/dev/null || true)"
  local id
  for id in ${ids}; do
    log "deleting snapshot ${id}"
    hcloud image delete "${id}" >/dev/null 2>&1 || true
  done
}

delete_network() {
  if hcloud_exists "network" "${NETWORK_NAME}"; then
    log "deleting network ${NETWORK_NAME}"
    hcloud network delete "${NETWORK_NAME}" >/dev/null 2>&1 || true
  fi
}

delete_firewalls() {
  local fw
  for fw in "${FW_CONTROL}" "${FW_MANAGED}"; do
    if hcloud_exists "firewall" "${fw}"; then
      log "deleting firewall ${fw}"
      hcloud firewall delete "${fw}" >/dev/null 2>&1 || true
    fi
  done
}

delete_key() {
  if hcloud_exists "ssh-key" "${SSH_KEY_NAME}"; then
    log "deleting ssh-key ${SSH_KEY_NAME}"
    hcloud ssh-key delete "${SSH_KEY_NAME}" >/dev/null 2>&1 || true
  fi
}

report_remaining() {
  log "remaining resources (expect none):"
  hcloud server list -o noheader 2>/dev/null | grep -E 'livetest|managed' || true
  hcloud image list --type snapshot --selector "livetest" -o noheader 2>/dev/null || true
  hcloud network list -o noheader 2>/dev/null | grep livetest || true
}

main() {
  require_token
  command -v hcloud >/dev/null || die "hcloud CLI not found"
  delete_servers
  delete_snapshots
  delete_network
  delete_firewalls
  delete_key
  report_remaining
  log "teardown complete"
}

main "$@"
