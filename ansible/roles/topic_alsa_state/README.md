<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_alsa_state

## Purpose

Topic role that hardens the `alsa-state.service` ALSA-mixer-state-restore daemon on a Fedora 44 or later host. The role deploys four shipping artefacts: three drop-in files under `/etc/systemd/system/alsa-state.service.d/` (a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` layer, and a process-internal kernel-restriction drop-in that carries `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, an additive plus subtractive `SystemCallFilter=` pair, and an empty `CapabilityBoundingSet=` that drops all stock-allowed capabilities) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → alsa_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** modify the ALSA kernel driver layer, the `/dev/snd/*` character devices, the per-user PulseAudio or PipeWire stack, the companion `alsa-restore.service` oneshot, or the `alsamixer` interactive CLI. The full topic end-state, the verify discipline (including the paired `comm=alsactl` probe that defeats the vendor `ExecStart=-` dash-prefix exit-masking), and the three-stage rollback posture are documented in `docs/reference/topics/alsa-state.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_alsa_state_dropin_dir` | `/etc/systemd/system/alsa-state.service.d` | Drop-in directory for the unit. |
| `topic_alsa_state_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_alsa_state_required_packages` | `[alsa-utils]` | Required package; preflight asserts presence. |
| `topic_alsa_state_cil_module_name` | `nnp_alsa` | CIL module name without extension. |
| `topic_alsa_state_cil_priority` | `400` | CIL load priority. |
| `topic_alsa_state_binary_bin_path` | `/usr/bin/alsactl` | F44-canonical daemon binary path. |
| `topic_alsa_state_binary_sbin_path` | `/usr/sbin/alsactl` | Compatibility symlink under sbin/bin equivalency. |
| `topic_alsa_state_expected_fcontext` | `alsa_exec_t` | Expected fcontext for both binary paths; preflight fail-fasts on `bin_t`. |
| `topic_alsa_state_expected_selinux_domain` | `alsa_t` | Expected SELinux domain of the running daemon. |
| `topic_alsa_state_expected_uid` / `_gid` | `0` / `0` | Expected steady-state UID/GID; alsactl runs as root throughout. |
| `topic_alsa_state_expected_comm` | `alsactl` | Expected `/proc/<MainPID>/comm`; defeats dash-prefix exit-masking. |
| `topic_alsa_state_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_alsa_state_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_alsa_state_expected_protect_system` | `full` | Expected `ProtectSystem=`. |
| `topic_alsa_state_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_alsa_state_expected_caps_normalized` | `""` (empty) | Expected `CapabilityBoundingSet=` — verify normalises observed value before comparison. |
| `topic_alsa_state_expected_raf_source_order` | `[AF_UNIX, AF_NETLINK]` | Expected `RestrictAddressFamilies=` source-order. |
| `topic_alsa_state_expected_scf_length_min` | `1500` | Conservative lower bound on resolved `SystemCallFilter=` length. |
| `topic_alsa_state_expected_scf_anchor_tokens` | `[epoll_wait, recvfrom]` | Anchor tokens for the `@system-service` group; absence of `setgroups`/`setuid`/`capset` anchors is intentional. |
| `topic_alsa_state_state_file` | `/var/lib/alsa/asound.state` | Saved-state file checked by the verify smoketest. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install handler, the `restorecon` handler, the AVC-clean read, the SECCOMP-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean and SECCOMP-clean assertions in the role's modify stage and in `verify.sh` consume the audit pipeline that Layer 3 provisions.

## Tags

- `topic_alsa_state` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart alsa-state` handlers are wired through the `topic_alsa_state dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (MainPID read, SELinux-domain read, live UID/GID read, live comm read, AVC count, SECCOMP count, post-deploy saved-state-file size) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
