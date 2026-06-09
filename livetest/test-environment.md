<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Test environment

This document gives the concrete provisioning environment for the live-test suite.
[The test concept](test-concept.md) describes the topology, the harness, and the
run-state model provider-neutrally; this document makes them concrete against one
KVM-based cloud provider, Hetzner Cloud, used here as the worked example. A different
provider that offers the same primitives — hourly or per-second billing, a private
network, an out-of-band console, and pre-reboot snapshots — substitutes cleanly; the
section `## Provider neutrality` lists exactly which choices are Hetzner-specific.

The per-topic cloud-testability classification that decides which topics run on this
environment lives in [the topic test matrix](topic-test-matrix.md). Exact metric
computation lives in `metrics.md`. The suite overview and how the five documents fit
together live in `README.md`.

## Topology

The suite uses three node roles. The operator workstation stays outside the blast
radius; the control node runs the harness and acts as the bastion; two managed nodes
are the hardened targets and carry all boot-failure risk.

```text
  operator workstation                  Hetzner Cloud project (isolated)
  (laptop, SSH terminal)        ┌──────────────────────────────────────────────┐
        │                       │                                              │
        │  ssh (public IPv4)    │   control node (bastion + ansible-playbook)   │
        └──────────────────────►│   not hardened · public IPv4 · holds keys     │
                                │              │                                │
                                │              │  private network 10.x          │
                                │     ┌────────┴────────┐                       │
                                │     ▼                 ▼                       │
                                │  managed-a         managed-b                  │
                                │  hardened target   hardened target            │
                                │  no public IPv4    no public IPv4             │
                                │  VNC console       VNC console                │
                                └──────────────────────────────────────────────┘
```

### Operator workstation

A plain SSH terminal. It is neither a control node nor a managed node and holds no
provider credential beyond the SSH private key that authenticates to the control node.
It reaches a managed node only by jumping through the control node, so a managed node
that loses its network is unreachable from here until the console is used. Keeping the
harness off this machine means a local interruption — a closed laptop, a dropped
link — never aborts a run mid-flight; the run continues on the control node.

### Control node

A single cloud virtual machine that runs `ansible-playbook` and Molecule, holds the
inventory and the SSH keys, and serves as the bastion and jump host for the operator.
It is deliberately left unhardened so that it stays a stable platform while the targets
change underneath it: applying the role tree to the host that is also running the role
tree would couple the harness to the system under test. The control node sits on the
private network with the managed nodes, so the harness reaches them directly over their
private addresses; it is the only host in the project with a public address.

### Managed nodes

Two hardened targets, `managed-a` and `managed-b`. They have no public IPv4 address and
are reachable only across the private network through the control node. Two nodes let
the cumulative system-tier host run on one node while a second is provisioned in
parallel for an isolated component scenario or held as a spare when a risky reboot is
under test, without serialising the whole suite onto a single host. Both carry the
out-of-band console required below, because both can be made unreachable by a
misconfiguration of `sshd` or by a runtime-path race.

## Network and reachability

The two managed nodes attach to a private Hetzner Cloud network and run without a
public IPv4 address. A firewall on the project denies inbound traffic to the managed
nodes from the public internet; the only inbound public surface is SSH to the control
node. This keeps the hardened targets off the public internet entirely, which is
consistent with the host-local, defensive-only test boundary in
[the test concept](test-concept.md), and it removes any need to involve the provider
penetration-test approval regime.

The operator reaches a managed node through the control node with an SSH `ProxyJump`:

```text
ssh -J operator@<control-node-public-ip> fedora@<managed-node-private-ip>
```

The control node itself needs no jump, because it shares the private network with the
targets. When `sshd` on a managed node breaks, neither the direct path from the control
node nor the jump path from the workstation can reach it, and the out-of-band console
becomes the only channel left. That failure mode is why the console below is mandatory
rather than convenient.

## The Molecule delegated driver

The harness is Molecule driving the `hetzner.hcloud` collection through the delegated
driver. Containers are not an option: the system under test depends on SELinux running
in enforcing mode, on PID 1 applying the hardened drop-ins, and on a real reboot, none
of which a container reproduces. The delegated driver hands provisioning to two
playbooks the suite owns, `create.yml` and `destroy.yml`, so the lifecycle is explicit
and the same two playbooks back both scenario tiers.

A scenario's `molecule.yml` selects the delegated driver and points at the shared
provisioning playbooks:

```yaml
driver:
  name: default          # Molecule's delegated driver
platforms:
  - name: managed-a
    groups:
      - hardened_targets
provisioner:
  name: ansible
  playbooks:
    create: ../shared/create.yml
    destroy: ../shared/destroy.yml
    prepare: prepare.yml
    converge: converge.yml
    verify: verify.yml
verifier:
  name: ansible
```

`create.yml` provisions one server per platform with the `hetzner.hcloud` modules,
injects the harness SSH key, attaches the private network, and applies the firewall:

```yaml
- name: Provision managed nodes
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Create the test server
      hetzner.hcloud.hcloud_server:
        name: "{{ item.name }}"
        server_type: cx22
        image: fedora-44          # catalogue image, or a custom snapshot
        location: nbg1
        ssh_keys:
          - "{{ harness_ssh_key_name }}"
        firewalls:
          - "{{ harness_firewall_name }}"
        enable_ipv4: false
        state: present
      loop: "{{ molecule_yml.platforms }}"
      register: created

    - name: Attach the private network
      hetzner.hcloud.hcloud_server_network:
        server: "{{ item.hcloud_server.name }}"
        network: "{{ harness_private_network }}"
        state: present
      loop: "{{ created.results }}"
```

`destroy.yml` is the symmetric teardown — it sets `state: absent` on the same servers —
and it runs both on normal completion and on abort, so a failed run leaves no billable
host behind. The collection also ships `hcloud_ssh_key`, `hcloud_network`, and
`hcloud_firewall` modules for the one-time project scaffolding that the create playbook
assumes is present.

The two scenario tiers reuse this driver at their Molecule-standard locations. The
component tier lives in each role at `ansible/roles/<role>/molecule/default/`, and the
system tier lives at `ansible/molecule/system/`. The `create.yml` and `destroy.yml`
shared by both sit outside any single role so a change to provisioning is made once.

## Connection model and the staff_u transition

Molecule and `ansible-playbook` connect to each managed node as the cloud image's
default sudo-capable account. On the Fedora cloud image that account is `fedora`, and
the suite sets `foundation_sudo_roles_user` to it, so the account the harness logs in as
is exactly the account that Layer 1 maps to `staff_u`. Escalation is plain `sudo`
(`become: true`); the role tasks that touch the policy store, the audit store, or the
system journal additionally carry `become_flags: "-r sysadm_r -t sysadm_t"`, because
plain `sudo` from a `staff_u` login lands in `staff_sudo_t`, where the policy store is
unreadable.

The transition has a connection-lifecycle consequence the harness must handle.
`foundation_sudo_roles` runs `semanage login -m -s staff_u` against the connection
account, but `pam_selinux` only reads the new mapping when a session is established.
Ansible holds one persistent SSH connection for the whole play, so without intervention
every later task would keep running in the pre-mapping context. The harness therefore
resets the connection immediately after Layer 1:

```yaml
- name: Apply Foundation Layer 1
  ansible.builtin.include_role:
    name: foundation_sudo_roles

- name: Re-establish the session so pam_selinux picks up staff_u
  ansible.builtin.meta: reset_connection
```

The next task opens a fresh SSH session that authenticates as `staff_u:staff_r:staff_t`,
mirroring the manual re-login the bootstrap path requires. This is the same step,
expressed for the harness, that the operator performs by hand in
[Bootstrap a hardened host](../docs/tutorials/bootstrap-hardened-host.md). After the
reset, the role-switched `become_flags` shown above are load-bearing for every SELinux,
audit, and journal operation; a task that omits them silently fails to reach the store.

Each topic's `verify.sh` is then run in both contexts — once as plain `staff_t` and once
under the `sudo -r sysadm_r -t sysadm_t` role switch — as required by the exit criteria
in [the test concept](test-concept.md). A line that stays `SKIP` under the role-switched
pass means the switch did not take, not that the check passed.

## Out-of-band console and pre-reboot snapshots

An out-of-band console on each managed node is mandatory. Hetzner Cloud provides a
noVNC web console, reachable from the Cloud Console and from the API, that attaches to
the server's virtual display independently of `sshd` and of the network stack. When a
hardening drop-in breaks `sshd`, or a `ReadWritePaths` runtime race stalls boot, the
console is the only remaining way to read the boot log and revert the change. The
runtime-path failure class is described in
[the ReadWritePaths runtime race](../docs/explanation/readwritepaths-runtime-race.md);
the operator-facing revert steps are in
[Recover from boot failure](../docs/how-to/recover-from-boot-failure.md).

Before any reboot that carries boot-failure risk — every system-tier reboot, and any
component scenario whose topic is in the boot-failure class — the harness takes a
pre-reboot snapshot of the managed node. On Hetzner Cloud this is a server image of type
`snapshot`. If the host does not return from the reboot, the rollback handle is a
rebuild of the server from that snapshot image, which restores the last known-good
checkpoint and lets the run continue.

Rolling a snapshot back is an operational action, not a scripted test case. This is the
deliberate boundary recorded in [the test concept](test-concept.md): boot-survival is
the acceptance gate, and recovery-procedure testing is out of scope. The snapshot exists
for restartability and operational safety, not as a recovery-test fixture. Snapshots are
billed per stored gigabyte, so the suite deletes a snapshot once its node has passed the
reboot it guards.

## Headless session substrate

The session-effectiveness tier described in [the test concept](test-concept.md) is built
after the system tier is green and needs a running user session on the managed node to
exercise the topics classed `Session` and `Full (presence)` in
[the topic test matrix](topic-test-matrix.md). The substrate is fully automated and
software-rendered; no physical GPU and no human are involved.

The managed node is brought to the following state for the session tier:

- A lingering session for the `staff_u`-mapped user, so a user-level systemd instance and
  an `XDG_RUNTIME_DIR` exist without an interactive login. This is `loginctl enable-linger`
  on the connection account.
- A session D-Bus instance under that user instance, which is what
  `systemctl --user` and the document-portal services attach to.
- A headless, software-rendered display. A headless Wayland compositor runs with the Mesa
  `llvmpipe` software rasteriser (`LIBGL_ALWAYS_SOFTWARE=1`), so applications that need a
  compositor and a GL context start without a real framebuffer.

On that substrate the harness launches the target application or triggers the D-Bus flow,
then asserts kernel and audit state only:

- It reads `/proc/<pid>/attr/current` to confirm the process entered its expected SELinux
  domain, which is the observable for the `runtime_domain` checks the session topics carry.
- It inspects the audit store for AVC cleanliness, and for the expected denial in a
  negative test.

No pixel-level or visual assertion is made; rendered output is not a hardening control.
This tier has the highest variance in the suite, so it sits behind a readiness gate and
never blocks the daemon and boot acceptance that the system tier already covers.

## Provider account, credential, and cost control

The provider account setup belongs to Phase 1 of the lifecycle and is named here so the
environment is complete. The suite runs in an isolated Hetzner Cloud project so that its
resources never mix with unrelated ones, and the harness authenticates with a project-
scoped API token supplied through the `HCLOUD_TOKEN` environment variable. The token is
scoped to that one project and to nothing else, which bounds what a leaked token can
reach.

Cost is bounded primarily by the lifecycle, not by a billing threshold: servers are
ephemeral, `destroy.yml` runs on completion and on abort, hourly billing caps the cost of
a forgotten host at the running rate, and snapshots are deleted once their guarded reboot
passes. Hetzner Cloud has no native budget-threshold alert, so the spending check is a
periodic review of the project's billing page plus the project-scoped token as the hard
limit on what can be provisioned; the destroy-always discipline is the load-bearing
control.

## Provider neutrality

The concept needs only the primitives in the left column. The right column is how
Hetzner Cloud supplies each one; swapping providers means re-mapping this table and
rewriting `create.yml` and `destroy.yml`, with no change to the scenarios or the topic
matrix.

| Required primitive | Hetzner Cloud mechanism |
|---|---|
| Real KVM virtual machine (not a container) | `hetzner.hcloud.hcloud_server` |
| Private network between instances | `hcloud_network` plus `hcloud_server_network` |
| Managed node with no public address | `enable_ipv4: false` on the server |
| Public bastion for the harness and operator | control-node server with a public IPv4 |
| Out-of-band console independent of the network | noVNC web console |
| Pre-reboot snapshot and rollback | server image of type `snapshot`, then rebuild from it |
| Per-time billing to bound cost | hourly billing |
| Scoped credential | project-scoped `HCLOUD_TOKEN` |
| Provisioning driver for Molecule | delegated driver plus the `hetzner.hcloud` modules |

Anything outside this table — server type, region, image name, network address range —
is a tunable, not a structural dependency. The Fedora target release is the one
constraint that is not negotiable: the role tree targets Fedora 44 or later, so the image
must be a catalogue Fedora 44+ image or a custom snapshot built from one.
