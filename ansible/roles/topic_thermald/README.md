<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_thermald

## Purpose

Topic role that hardens the `thermald.service` CPU thermal-management daemon on a Fedora 44 or later host. The role deploys three shipping artefacts: three drop-in files under `/etc/systemd/system/thermald.service.d/` (a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` layer, and a process-internal kernel-restriction drop-in that carries `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, an additive plus subtractive `SystemCallFilter=` pair, and an empty `CapabilityBoundingSet=` that drops all stock-allowed capabilities). Unlike the sibling hardware-class topics, this role ships **no** topic-owned SELinux CIL module: thermald has no service-specific SELinux subtype in stock targeted policy on Fedora 44, runs in `init_t` (identity transition from PID 1 over a `bin_t`-labelled binary), and the kernel's NNP-transition constraint has no source-target distinction to evaluate for an identity transition.

The role does **not** modify the operator-side `/etc/thermald/thermal-conf.xml`, the platform Dynamic Platform and Thermal Framework table contents, the per-CPU model-specific-register layout, the `/dev/cpu/*/msr` character-device interface, the kernel `intel_pstate` or `amd_pstate` driver layer, or the `mcelog.service` companion daemon. The full topic end-state, the verify discipline (including the platform-symmetric `ActiveState`/`SubState`/`Result` branching), and the three-stage rollback posture are documented in `docs/reference/topics/thermald.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_thermald_dropin_dir` | `/etc/systemd/system/thermald.service.d` | Drop-in directory for the unit. |
| `topic_thermald_required_packages` | `[thermald]` | Required package; preflight asserts presence. |
| `topic_thermald_binary_path` | `/usr/bin/thermald` | Daemon binary path. |
| `topic_thermald_expected_fcontext` | `bin_t` | Expected fcontext for the binary; preflight fail-fasts on any other mapping (would indicate stock policy has gained a service-specific subtype). |
| `topic_thermald_forbidden_policy_types` | `[thermald_t, thermald_exec_t]` | Stock policy must ship neither type; preflight fail-fasts on either. |
| `topic_thermald_expected_runtime_domain` | `init_t` | Expected SELinux domain of the running daemon on a DPTF-bearing host. |
| `topic_thermald_expected_uid` / `_gid` | `0` / `0` | Expected steady-state UID/GID on a DPTF-bearing host; thermald runs as root throughout. |
| `topic_thermald_expected_type` | `dbus` | Expected `Type=`. |
| `topic_thermald_expected_result` | `success` | Expected `Result=` for both Soll states. |
| `topic_thermald_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_thermald_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_thermald_expected_protect_system` | `full` | Expected `ProtectSystem=`. |
| `topic_thermald_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_thermald_expected_caps_normalized` | `""` (empty) | Expected `CapabilityBoundingSet=` — verify normalises observed value before comparison. |
| `topic_thermald_expected_raf_source_order` | `[AF_UNIX, AF_NETLINK]` | Expected `RestrictAddressFamilies=` source-order. |
| `topic_thermald_expected_scf_length_min` | `1500` | Conservative lower bound on resolved `SystemCallFilter=` length. |
| `topic_thermald_expected_scf_anchor_tokens` | `[epoll_wait, recvfrom]` | Anchor tokens for the `@system-service` group; absence of `setgroups`/`setuid`/`capset` anchors is intentional. |
| `topic_thermald_dptf_less_journal_anchor` | `Unsupported cpu model\|Unsupported platform` | Journal anchor on DPTF-less hosts; the binary's signature exit reason. |

The drop-in bodies are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the `restorecon` handler, the AVC-clean read, the SECCOMP-clean read, and the live SELinux-domain read transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean and SECCOMP-clean assertions in the role's modify stage and in `verify.sh` consume the audit pipeline that Layer 3 provisions.

`foundation_selinux_cil_bootstrap` is **not** a dependency. This topic ships no CIL module and does not invoke `semodule`. The dependency set is intentionally smaller than the sibling hardware-class topic roles.

## Tags

- `topic_thermald` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins are pushed verbatim from `files/`.
- The `restorecon`, `daemon-reload`, and `restart thermald` handlers are wired through the `topic_thermald dropin changed` notification name and fire only on a drop-in file change.
- There is no `semodule install` handler (no CIL artefact ships) and no `meta: flush_handlers` synchronisation (no CIL load to sequence the drop-in push against).
- The live-state probe (MainPID read, SELinux-domain read, live UID/GID read, AVC count, SECCOMP count, DPTF-less journal anchor count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
