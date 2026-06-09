#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# bootstrap_infra.sh -- stand up the reusable livetest infrastructure.
#
# Run from the operator workstation. Idempotently ensures the provider
# primitives exist and the control node is provisioned and configured to run
# the Molecule harness against managed nodes over the private network:
#
#   1. SSH key            (uploaded from the local harness public key)
#   2. private network    (with a subnet in the chosen network zone)
#   3. managed firewall    (empty inbound: managed nodes take no public ingress)
#   4. control firewall    (inbound SSH from the operator's current public IPv4)
#   5. control node        (public IPv4, attached to the private network)
#   6. control provisioning (Python venv, Molecule, collections, the harness
#                            private key, the token, and the synced role tree)
#
# Under the keep-reusable-infrastructure policy these are created once and kept;
# re-running this script reconciles drift (for example a changed operator IPv4)
# and re-syncs the role tree, so it is safe to run before every suite.

SCRIPT_NAME="bootstrap"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${HERE}/lib.sh"

ANSIBLE_TREE="$(cd "${HERE}/../../ansible" && pwd)"
readonly ANSIBLE_TREE

ensure_ssh_key() {
  if hcloud_exists "ssh-key" "${SSH_KEY_NAME}"; then
    log "ssh-key ${SSH_KEY_NAME} present"
    return
  fi
  log "creating ssh-key ${SSH_KEY_NAME}"
  hcloud ssh-key create \
    --name "${SSH_KEY_NAME}" \
    --public-key-from-file "${IDENTITY_LOCAL}.pub" >/dev/null
}

ensure_network() {
  if hcloud_exists "network" "${NETWORK_NAME}"; then
    log "network ${NETWORK_NAME} present"
  else
    log "creating network ${NETWORK_NAME} (${NETWORK_IP_RANGE})"
    hcloud network create \
      --name "${NETWORK_NAME}" \
      --ip-range "${NETWORK_IP_RANGE}" >/dev/null
  fi
  if hcloud network describe "${NETWORK_NAME}" -o json \
      | grep -q "\"ip_range\": \"${SUBNET_IP_RANGE}\""; then
    log "subnet ${SUBNET_IP_RANGE} present"
  else
    log "adding subnet ${SUBNET_IP_RANGE} (zone ${NETWORK_ZONE})"
    hcloud network add-subnet "${NETWORK_NAME}" \
      --network-zone "${NETWORK_ZONE}" \
      --type cloud \
      --ip-range "${SUBNET_IP_RANGE}" >/dev/null
  fi
}

ensure_managed_firewall() {
  if hcloud_exists "firewall" "${FW_MANAGED}"; then
    log "firewall ${FW_MANAGED} present"
    return
  fi
  # Empty rule set: deny all public inbound, allow all outbound (the default).
  # Managed nodes have no public IPv4; SSH reaches them over the private
  # network, which provider firewalls do not filter. Outbound IPv6 carries
  # package egress.
  log "creating firewall ${FW_MANAGED} (deny public inbound)"
  hcloud firewall create --name "${FW_MANAGED}" >/dev/null
}

ensure_control_firewall() {
  local my_ip
  my_ip="$(curl -fsS -4 https://api.ipify.org)" \
    || die "could not determine operator public IPv4"
  local cidr="${my_ip}/32"
  if ! hcloud_exists "firewall" "${FW_CONTROL}"; then
    log "creating firewall ${FW_CONTROL}"
    hcloud firewall create --name "${FW_CONTROL}" >/dev/null
  fi
  # Reconcile the single inbound SSH rule to the operator's current address.
  log "setting ${FW_CONTROL} inbound SSH source to ${cidr}"
  hcloud firewall replace-rules "${FW_CONTROL}" \
    --rules-file - >/dev/null <<EOF
[
  {
    "direction": "in",
    "protocol": "tcp",
    "port": "22",
    "source_ips": ["${cidr}"],
    "description": "operator ssh to control node"
  }
]
EOF
}

ensure_control_node() {
  if hcloud_exists "server" "${CONTROL_NAME}"; then
    log "control node ${CONTROL_NAME} present (ipv4 $(control_ipv4))"
    return
  fi
  log "creating control node ${CONTROL_NAME}"
  # The control node is reached as root (Hetzner injects the key); it needs no
  # extra account. It does need PerSourcePenalties disabled like every other
  # node so a reconnect (should the multiplex master ever drop) is not refused.
  local control_user_data
  control_user_data="$(cat <<'EOF'
#cloud-config
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
    --name "${CONTROL_NAME}" \
    --type "${SERVER_TYPE}" \
    --image "${OS_IMAGE}" \
    --location "${LOCATION}" \
    --ssh-key "${SSH_KEY_NAME}" \
    --network "${NETWORK_NAME}" \
    --firewall "${FW_CONTROL}" \
    --user-data-from-file <(printf '%s' "${control_user_data}") \
    --label "livetest=control" >/dev/null
  log "control node created (ipv4 $(control_ipv4))"
}

wait_for_control_ssh() {
  local ip
  ip="$(control_ipv4)"
  drop_control_socket "${ip}"
  log "waiting for SSH on control node ${ip}"
  for _ in $(seq 1 40); do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 "root@${ip}" true 2>/dev/null; then
      log "control node reachable"
      return
    fi
    sleep 10
  done
  die "control node ${ip} did not accept SSH within timeout"
}

provision_control_node() {
  # cloud-init's runcmd restarts sshd, which can drop the multiplex master once.
  # Retry the wait so the master is re-established after sshd settles; from then
  # on PerSourcePenalties is off and the master is stable for the heavy steps.
  log "waiting for cloud-init on control node"
  local _
  for _ in $(seq 1 10); do
    if ssh_control "cloud-init status --wait" >/dev/null 2>&1; then
      break
    fi
    sleep 10
  done

  log "installing base tooling on control node"
  ssh_control "set -e
    dnf install -y --setopt=install_weak_deps=False \
      python3 python3-pip git rsync openssh-clients >/dev/null"

  log "creating the harness venv and installing Molecule"
  ssh_control "set -e
    test -d ${VENV_DIR} || python3 -m venv ${VENV_DIR}
    ${VENV_DIR}/bin/pip install --quiet --upgrade pip
    ${VENV_DIR}/bin/pip install --quiet molecule ansible-core hcloud netaddr"

  log "pushing the harness private key to the control node"
  ssh_control "install -d -m 0700 /root/.ssh"
  # Pipe the key over stdin so its bytes never appear in a command line.
  ssh_control "umask 077; cat > ${IDENTITY_REMOTE}" < "${IDENTITY_LOCAL}"
  ssh_control "cat > ${IDENTITY_REMOTE}.pub" < "${IDENTITY_LOCAL}.pub"
  ssh_control "chmod 0600 ${IDENTITY_REMOTE}; chmod 0644 ${IDENTITY_REMOTE}.pub"

  log "writing the project token to the control node env file"
  # The token reaches the file via stdin expansion; it is not echoed.
  printf 'export HCLOUD_TOKEN=%s\n' "${HCLOUD_TOKEN}" \
    | ssh_control "umask 077; cat > ${REMOTE_ENV_FILE}"

  log "syncing the role tree to the control node"
  local ip
  ip="$(control_ipv4)"
  rsync -az --delete \
    -e "ssh ${SSH_OPTS[*]}" \
    "${ANSIBLE_TREE}/" "root@${ip}:${REMOTE_ANSIBLE}/"

  log "installing Ansible collections on the control node"
  ssh_control "set -e
    source ${VENV_DIR}/bin/activate
    ansible-galaxy collection install -r ${REMOTE_ANSIBLE}/requirements.yml >/dev/null"

  log "control node provisioned"
}

main() {
  require_token
  require_local_key
  command -v hcloud >/dev/null || die "hcloud CLI not found"
  ensure_ssh_key
  ensure_network
  ensure_managed_firewall
  ensure_control_firewall
  ensure_control_node
  wait_for_control_ssh
  provision_control_node
  log "bootstrap complete; control node ipv4 $(control_ipv4)"
}

main "$@"
