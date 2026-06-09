<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_auditd

## Purpose

Topic role that hardens the `auditd.service` security-event log producer on a Fedora 44 or later host. The role deploys three shipping artefacts: two drop-in files under `/etc/systemd/system/auditd.service.d/` (a topic-owned hardening drop-in that adds the six directives the F44 stock vendor unit does not already ship — `ProtectClock=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `SystemCallArchitectures=native`, `RestrictNamespaces=yes`, `PrivateDevices=yes` — and an isolated `NoNewPrivileges=yes` layer) and one topic-owned single-rule SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → auditd_t : process2 nnp_transition` rule the NNP layer depends on.

Drop-in changes are activated only by reboot; the role pushes the artefacts, runs `daemon-reload`, and then prompts the operator for a reboot. Apply-on-running-daemon is structurally unavailable for this Topic.

The role does **not** layer a topic-side `SystemCallFilter=`, `MemoryDenyWriteExecute=`, `LockPersonality=`, `RestrictRealtime=`, `ProtectKernelLogs=`, `ProtectSystem=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectHostname=`, `ProtectProc=`, `ProcSubset=`, `PrivateTmp=`, `RestrictAddressFamilies=`, `RestrictSUIDSGID=`, `UMask=`, `CapabilityBoundingSet=`, `User=`, or `Group=` directive. `MemoryDenyWriteExecute=`, `LockPersonality=`, and `RestrictRealtime=` are upstream-shipped by the F44 vendor unit and the topic-owned profile does not restate them. `ProtectKernelLogs=` is deliberately excluded because auditd reads the kernel audit buffer via the netlink audit family and the directive overlaps the kernel-log subsystem auditd's own data path depends on. The role does not modify `/etc/audit/auditd.conf`, the audit-rule policy under `/etc/audit/rules.d/`, the audit-dispatch configuration under `/etc/audit/plugins.d/`, or the `audit-rules.service` companion unit (audit-rule policy is operator-policy outside this Topic). The full topic end-state, the verify discipline, the audit-control smoketest, and the two-stage rollback posture are documented in `docs/reference/topics/auditd.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_auditd_dropin_dir` | `/etc/systemd/system/auditd.service.d` | Drop-in directory for the unit. |
| `topic_auditd_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_auditd_required_packages` | `[audit]` | Required package; preflight asserts presence. |
| `topic_auditd_cil_module_name` | `nnp_auditd` | CIL module name without extension. |
| `topic_auditd_cil_priority` | `400` | CIL load priority. |
| `topic_auditd_expected_selinux_domain` | `auditd_t` | Expected SELinux domain of the running daemon. |
| `topic_auditd_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_auditd_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_auditd_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_auditd_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_auditd_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_auditd_expected_restrict_namespaces` | `yes` | Expected `RestrictNamespaces=`. |
| `topic_auditd_expected_private_devices` | `yes` | Expected `PrivateDevices=`. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, the live SELinux-domain read, the AVC-clean read, and the `auditctl`/`ausearch` audit-control smoketests all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned single-rule CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions. The relationship is structurally direct: auditd is the daemon producing the Layer-3 audit stream that Layer 3's diagnosis loop reads from.

## Tags

- `topic_auditd` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `reboot-prompt` — the final `pause:` step that prompts the operator for a reboot.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two drop-ins are pushed verbatim under `become_flags: "-r sysadm_r -t sysadm_t"` so that the install-time SELinux context lands on `auditd_unit_file_t` directly. The CIL source is pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon` and `daemon-reload` handlers are wired through the `topic_auditd dropin changed` notification name and fire only on a drop-in file change. **No `restart auditd` handler exists** — auditd's stock vendor unit ships `RefuseManualStop=yes` and `systemctl restart auditd` would fail because the stop step of the internal stop-then-start sequence is refused. Drop-in changes activate only on the next reboot.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (MainPID read, SELinux-domain read, AVC count, post-deploy `auditctl -s`) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- The role's final task is an Ansible `pause:` that prompts the operator to reboot the host out-of-band before relying on the topic-owned hardening surface in the running daemon.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
