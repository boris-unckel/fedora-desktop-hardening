#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# lib.sh -- shared constants and helpers for the livetest cloud harness.
#
# Sourced by bootstrap_infra.sh, bake_base_snapshot.sh, run_suite.sh, and
# teardown.sh. Holds the single source of truth for resource names so the
# provider primitives the Molecule create play expects (the SSH key, private
# network, and managed firewall) are named identically here and in
# ../../ansible/molecule/shared/create.yml.
#
# Authentication: every helper shells out to the hcloud CLI, which reads the
# project-scoped token from the HCLOUD_TOKEN environment variable. The token
# value is never printed.

# Constants below are consumed by the scripts that source this library, and the
# ssh helpers intentionally expand their argument on the remote side.
# shellcheck disable=SC2034,SC2029

set -euo pipefail

# --- Provider resource names (must match ansible/molecule/shared/create.yml) --
readonly SSH_KEY_NAME="livetest-harness"
readonly NETWORK_NAME="livetest-net"
readonly FW_MANAGED="livetest-fw-managed"
readonly FW_CONTROL="livetest-fw-control"
readonly CONTROL_NAME="livetest-control"

# --- Network topology --------------------------------------------------------
readonly NETWORK_IP_RANGE="10.10.0.0/16"
readonly SUBNET_IP_RANGE="10.10.1.0/24"
readonly NETWORK_ZONE="us-east"

# --- Placement and sizing ----------------------------------------------------
readonly LOCATION="ash"
readonly SERVER_TYPE="cpx21"
readonly OS_IMAGE="fedora-44"

# --- Identities and paths ----------------------------------------------------
readonly IDENTITY_LOCAL="${HOME}/.ssh/livetest_harness"
readonly IDENTITY_REMOTE="/root/.ssh/livetest_harness"
readonly MANAGED_USER="fedora"
readonly VENV_DIR="/opt/harness"
readonly REMOTE_ANSIBLE="/root/ansible"
readonly REMOTE_ENV_FILE="/root/.hcloud_env"

# --- Labels (housekeeping; see livetest/reports for the policy) ---------------
# The base snapshot is reusable infrastructure and is kept across runs; only
# transient managed nodes are recycled per scenario.
readonly LABEL_BASE="livetest=base"
readonly LABEL_BUILDER="livetest=builder"

# --- SSH options for non-interactive control-node access ---------------------
# A single persistent ControlMaster connection is load-bearing, not an
# optimisation: OpenSSH 10.x ships PerSourcePenalties enabled, which drops a
# source address after a burst of new connections. Multiplexing every command
# over one already-open connection means there is no reconnect burst to
# penalise. ControlPersist keeps the master alive across the discrete steps of
# a script run. The long ServerAlive budget tolerates slow remote steps (a
# filesystem relabel) without the established connection being torn down.
readonly SSH_OPTS=(
  -i "${IDENTITY_LOCAL}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=15
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=20
  -o ControlMaster=auto
  -o ControlPath="${HOME}/.ssh/cm-livetest-%h"
  -o ControlPersist=600
)
# Host keys are not tracked: provider IPs are recycled across ephemeral test
# nodes, so a known_hosts entry from a prior node turns a reused IP into a
# host-key-mismatch refusal. /dev/null plus StrictHostKeyChecking=no matches the
# molecule scenario's host_key_checking:false and is appropriate for short-lived
# nodes on a dedicated project. The multiplex socket is still dropped per host so
# a reused IP opens a fresh master rather than reusing a dead one.

# drop_control_socket HOST -- remove any stale multiplex socket for a host whose
# server was just (re)created, so a fresh master is opened instead of a dead one.
drop_control_socket() {
  rm -f "${HOME}/.ssh/cm-livetest-$1" 2>/dev/null || true
}

log() {
  printf '[%s] %s\n' "${SCRIPT_NAME:-harness}" "$*" >&2
}

die() {
  log "FATAL: $*"
  exit 1
}

require_token() {
  [[ -n "${HCLOUD_TOKEN:-}" ]] || die "HCLOUD_TOKEN is not set in the environment."
}

require_local_key() {
  [[ -f "${IDENTITY_LOCAL}" ]] \
    || die "harness private key not found at ${IDENTITY_LOCAL}"
  [[ -f "${IDENTITY_LOCAL}.pub" ]] \
    || die "harness public key not found at ${IDENTITY_LOCAL}.pub"
}

# hcloud_exists KIND NAME -- true when the named resource is present.
hcloud_exists() {
  local kind="$1" name="$2"
  hcloud "${kind}" describe "${name}" >/dev/null 2>&1
}

# control_ipv4 -- print the control node's public IPv4, or empty when absent.
control_ipv4() {
  hcloud server ip "${CONTROL_NAME}" 2>/dev/null || true
}

# ssh_control CMD... -- run a command on the control node as root.
ssh_control() {
  local ip
  ip="$(control_ipv4)"
  [[ -n "${ip}" ]] || die "control node ${CONTROL_NAME} has no public IPv4"
  ssh "${SSH_OPTS[@]}" "root@${ip}" "$@"
}
