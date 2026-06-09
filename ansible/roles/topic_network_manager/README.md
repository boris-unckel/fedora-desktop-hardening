<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_network_manager

## Purpose

Topic role that hardens the `NetworkManager.service` system network-management daemon on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/NetworkManager.service.d/` (a namespace-default baseline that carries the `Protect*` family with the `ReadWritePaths=` runtime-race mitigation, the address-family restriction, and the personality and architecture restrictions; and an isolated `NoNewPrivileges=yes` layer) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → NetworkManager_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** ship `MemoryDenyWriteExecute=`, `SystemCallFilter=`, or `CapabilityBoundingSet=` narrowing — the daemon `dlopen`'s plugins from the libnm family, VPN backends, and dispatcher hooks, and a process-internal kernel-restrictions layer requires a per-plugin audit that is operator-policy outside this role. The role does not interact with `nm-dispatcher.service`, `NetworkManager-wait-online.service`, NetworkManager plugin packages, or the connection-profile content under `/etc/NetworkManager/system-connections/`. The full topic end-state, the verify discipline, and the two-stage rollback posture are documented in `docs/reference/topics/network-manager.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_network_manager_dropin_dir` | `/etc/systemd/system/NetworkManager.service.d` | Drop-in directory for the unit. |
| `topic_network_manager_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_network_manager_required_packages` | `[NetworkManager]` | Required package; preflight asserts presence. |
| `topic_network_manager_expected_address_families` | `AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX` | Expected `RestrictAddressFamilies=` (alphabetical-source-order; verify normalises). |
| `topic_network_manager_expected_selinux_domain` | `NetworkManager_t` | Expected SELinux domain of the running daemon. |
| `topic_network_manager_expected_protect_system` | `strict` | Expected `ProtectSystem=`. |
| `topic_network_manager_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_network_manager_expected_restrict_namespaces` | `yes` | Expected `RestrictNamespaces=`. |
| `topic_network_manager_expected_lock_personality` | `yes` | Expected `LockPersonality=`. |
| `topic_network_manager_expected_nmcli_state` | `connected` | Expected `nmcli -t -f STATE general`. |
| `topic_network_manager_cil_module_name` | `nnp_network_manager` | CIL module name without extension. |
| `topic_network_manager_cil_priority` | `400` | CIL load priority. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, the AVC-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_network_manager` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart NetworkManager` handlers are wired through the `topic_network_manager dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count, post-deploy `nmcli STATE`) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
