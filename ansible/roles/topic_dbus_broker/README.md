<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_dbus_broker

## Purpose

Topic role that hardens the system-bus `dbus-broker.service` on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/dbus-broker.service.d/` (a topic-owned hardening drop-in that adds six conservative directives the F44 stock vendor unit does not already ship — `ProtectClock=yes`, `ProtectKernelLogs=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes` — and an isolated `NoNewPrivileges=yes` layer) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → system_dbusd_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** layer a topic-side `SystemCallFilter=`, `RestrictNamespaces=`, `RestrictAddressFamilies=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `ProcSubset=`, `UMask=`, `CapabilityBoundingSet=`, `User=`, or `Group=` directive: dbus-broker is the system-wide D-Bus message broker and the topic restricts the surface to six well-understood directives that are reboot-validated as side-effect-free. The role does not modify `/etc/dbus-1/system.conf` (system-bus configuration is upstream-managed) and does not interact with the configuration include directories under `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`. The role configures the system-bus broker only; the per-user session-bus broker is operator-policy outside this role. The full topic end-state, the verify discipline, and the two-stage rollback posture are documented in `docs/reference/topics/dbus-broker.md`.

A restart of `dbus-broker.service` interrupts the system message bus and disconnects every connected peer; the role's `restart dbus-broker` handler is the documented apply path on a host where a restart is acceptable, and the alternative is to apply the role and reboot.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_dbus_broker_dropin_dir` | `/etc/systemd/system/dbus-broker.service.d` | Drop-in directory for the unit. |
| `topic_dbus_broker_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_dbus_broker_required_packages` | `[dbus-broker]` | Required package; preflight asserts presence. |
| `topic_dbus_broker_cil_module_name` | `nnp_dbus_broker` | CIL module name without extension. |
| `topic_dbus_broker_cil_priority` | `400` | CIL load priority. |
| `topic_dbus_broker_expected_selinux_domain` | `system_dbusd_t` | Expected SELinux domain of the running daemon. |
| `topic_dbus_broker_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_dbus_broker_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_dbus_broker_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_dbus_broker_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_dbus_broker_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_dbus_broker_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_dbus_broker_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, the AVC-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_dbus_broker` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart dbus-broker` handlers are wired through the `topic_dbus_broker dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count, post-deploy `busctl --system list`) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
