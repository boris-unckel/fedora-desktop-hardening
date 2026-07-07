#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# bake_base_snapshot.sh -- build the enforcing, desktop-like base snapshot.
#
# Run from the operator workstation. Provisions a short-lived builder with a
# public IPv4, brings it to the substrate every topic role assumes, snapshots
# it, and deletes the builder. The snapshot is labelled so the suite driver
# finds it; under the keep-reusable-infrastructure policy the snapshot is kept
# across runs and only re-baked when the role set's package needs change.
#
# What the base bakes, and why each clears a first-run failure class:
#   - The unprivileged connection account and the sshd drop-in (no
#     PerSourcePenalties): managed nodes that boot from the base reach SSH
#     immediately instead of racing a long first-boot cloud-init -- the cause
#     of the earlier "node unreachable" timeouts.
#   - The union of every topic role's required packages (a desktop-like
#     target): topic preflights that assert the daemon package and vendor unit
#     no longer fail on a minimal image.
#   - SELinux set to enforcing in the persistent config, with the filesystem
#     relabelled while permissive: managed nodes boot already-enforcing, so the
#     audit-cleanliness checks see no permissive->enforcing transition noise.

SCRIPT_NAME="bake"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${HERE}/lib.sh"

readonly BUILDER_NAME="livetest-builder"
readonly SNAPSHOT_DESC="livetest-base-${OS_IMAGE}"

# The union of every topic role's required packages plus the SELinux management
# tooling the foundation roles call. Presence-only desktop packages
# (gnome-shell, mutter, keepassxc) are included so the session-tier topics and
# the cumulative system tier never fail a package assertion.
readonly BASE_PACKAGES=(
  # SELinux management tooling (foundation substrate)
  policycoreutils policycoreutils-python-utils selinux-policy-targeted
  setools-console
  # daemon topics
  audit cups dbus-broker chrony cronie rng-tools tuned udisks2 udisks2-iscsi
  smartmontools thermald plymouth NetworkManager avahi switcheroo-control
  alsa-utils aide
  # session / flatpak / python topics (presence-oriented)
  flatpak bubblewrap ostree xdg-desktop-portal python3 python3-pip
)
# The full GNOME desktop stack (gnome-shell, mutter, gdm) is deliberately NOT
# baked in. It pulls gdm and the graphical target, which thrashes a headless VM
# and stretches the clone boot past five minutes. The component tier needs none
# of it; the few session-tier topics that assert a desktop package are handled
# in their own scenario, not by burdening every node's boot.

builder_ipv4() {
  hcloud server ip "${BUILDER_NAME}" 2>/dev/null || true
}

ssh_builder() {
  local ip
  ip="$(builder_ipv4)"
  [[ -n "${ip}" ]] || die "builder has no public IPv4"
  # The argument intentionally expands and runs on the builder.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" "root@${ip}" "$@"
}

cleanup_builder() {
  if hcloud_exists "server" "${BUILDER_NAME}"; then
    log "removing builder ${BUILDER_NAME}"
    hcloud server delete "${BUILDER_NAME}" >/dev/null 2>&1 || true
  fi
}

create_builder() {
  if hcloud_exists "server" "${BUILDER_NAME}"; then
    log "stale builder present; removing it first"
    hcloud server delete "${BUILDER_NAME}" >/dev/null
  fi
  log "creating builder ${BUILDER_NAME}"
  local user_data
  user_data="$(cat <<EOF
#cloud-config
users:
  - name: ${MANAGED_USER}
    groups: [wheel]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - "$(cat "${IDENTITY_LOCAL}.pub")"
write_files:
  - path: /etc/ssh/sshd_config.d/99-livetest.conf
    content: |
      PerSourcePenalties no
      MaxStartups 100:30:200
runcmd:
  - [bash, -c, "systemctl disable --now firewalld sshguard fail2ban 2>/dev/null || true"]
  - [systemctl, restart, sshd]
EOF
)"
  hcloud server create \
    --name "${BUILDER_NAME}" \
    --type "${SERVER_TYPE}" \
    --image "${OS_IMAGE}" \
    --location "${LOCATION}" \
    --ssh-key "${SSH_KEY_NAME}" \
    --firewall "${FW_CONTROL}" \
    --user-data-from-file <(printf '%s' "${user_data}") \
    --label "${LABEL_BUILDER}" >/dev/null
  log "builder created (ipv4 $(builder_ipv4))"
}

wait_for_builder_ssh() {
  local ip
  ip="$(builder_ipv4)"
  drop_control_socket "${ip}"
  log "waiting for SSH on builder ${ip}"
  for _ in $(seq 1 40); do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 "root@${ip}" true 2>/dev/null; then
      log "builder reachable"
      return
    fi
    sleep 10
  done
  die "builder ${ip} did not accept SSH within timeout"
}

configure_builder() {
  # cloud-init's runcmd restarts sshd, which can drop the multiplex master once.
  # Retry so the master is re-established after sshd settles, before the heavy
  # steps run over it.
  log "waiting for cloud-init on builder"
  local _
  for _ in $(seq 1 10); do
    if ssh_builder "cloud-init status --wait" >/dev/null 2>&1; then
      break
    fi
    sleep 10
  done

  log "installing the base package union (this is the slow step)"
  # --skip-unavailable: a single optional package missing from the repo must
  # not abort the whole bake; a genuinely-needed package that is absent surfaces
  # later as a topic preflight failure in the fan-out, which is the better place
  # to catch it.
  ssh_builder "set -e; dnf install -y --skip-unavailable ${BASE_PACKAGES[*]} >/dev/null"

  # The staff_u login mapping is deliberately NOT baked. foundation_prepare must
  # establish it from the initial unconfined_u session, because that mapping is
  # what later makes plain sudo land in staff_sudo_t -- which cannot write
  # /etc/selinux. If the base pre-mapped staff_u, the prepare session would start
  # confined and the SELinux setup (enforcing config) would fail with EACCES. The
  # base stays an unconfined-default image; foundation_prepare owns the substrate.

  log "relabelling the filesystem so a later enforcing boot is clean"
  ssh_builder "restorecon -R -F / >/dev/null 2>&1 || true"

  log "leaving SELinux permissive in the base (enforcing is applied per node)"
  # The base stays permissive on purpose. A clone re-runs cloud-init on its first
  # boot (Hetzner assigns a fresh instance-id), and cloud-init under enforcing
  # stalls -- and since sshd is ordered after cloud-init.target, sshd never comes
  # up. Booting permissive lets that first cloud-init run finish; foundation_prepare
  # then sets enforcing and reboots, so the node ends up enforcing with cloud-init
  # already done (a clean enforcing boot, no mid-run permissive->enforcing noise).
  ssh_builder "sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config"

  log "flushing buffers before snapshot"
  # No machine-id reset and no cloud-init clean. An empty /etc/machine-id sets
  # ConditionFirstBoot, which makes systemd-firstboot block the boot waiting for
  # console input that a headless clone never supplies -- sshd then never comes
  # up. Cloud-init re-runs its per-instance modules on a clone anyway, because
  # Hetzner assigns a fresh instance-id, so the private NIC is configured
  # without a manual clean. The builder's machine-id and SSH host keys are kept;
  # a shared machine-id and host key are harmless for serial, ephemeral test
  # nodes and the shared host key keeps the fixed private address stable across
  # scenarios.
  ssh_builder "sync"
}

snapshot_builder() {
  log "shutting down builder for a consistent snapshot"
  hcloud server shutdown "${BUILDER_NAME}" >/dev/null 2>&1 || true
  local status
  for _ in $(seq 1 30); do
    status="$(hcloud server describe "${BUILDER_NAME}" -o 'format={{.Status}}' 2>/dev/null || true)"
    [[ "${status}" == "off" ]] && break
    sleep 5
  done
  if [[ "${status}" != "off" ]]; then
    log "ACPI shutdown did not complete; forcing power off"
    hcloud server poweroff "${BUILDER_NAME}" >/dev/null 2>&1 || true
    sleep 5
  fi
  log "creating snapshot (labelled ${LABEL_BASE})"
  hcloud server create-image \
    --type snapshot \
    --description "${SNAPSHOT_DESC}" \
    --label "${LABEL_BASE}" \
    "${BUILDER_NAME}" >/dev/null
  local image_id
  image_id="$(hcloud image list --type snapshot --selector "${LABEL_BASE}" \
    -o noheader -o columns=id | head -n1)"
  log "snapshot created: image id ${image_id}"
  printf '%s\n' "${image_id}"
}

main() {
  require_token
  require_local_key
  command -v hcloud >/dev/null || die "hcloud CLI not found"

  # Replace any prior base snapshot: the suite resolves the base by label, so a
  # single labelled snapshot must remain.
  local prior
  prior="$(hcloud image list --type snapshot --selector "${LABEL_BASE}" \
    -o noheader -o columns=id || true)"
  if [[ -n "${prior}" ]]; then
    log "deleting prior base snapshot(s): ${prior}"
    local id
    for id in ${prior}; do
      hcloud image delete "${id}" >/dev/null 2>&1 || true
    done
  fi

  trap cleanup_builder EXIT
  create_builder
  wait_for_builder_ssh
  configure_builder
  local image_id
  image_id="$(snapshot_builder)"
  cleanup_builder
  trap - EXIT
  log "bake complete; base image id ${image_id}"
}

main "$@"
