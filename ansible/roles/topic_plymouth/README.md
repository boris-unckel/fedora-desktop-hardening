<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_plymouth

## Purpose

Topic role that hardens the boot-splash renderer `plymouth-start.service` on a Fedora 44 or later host. The role deploys four shipping artefacts: three drop-in files under `/etc/systemd/system/plymouth-start.service.d/` (a topic-owned filesystem-and-process-isolation drop-in carrying seventeen directives — `ProtectSystem=strict`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`, `PrivateTmp=`, `ReadWritePaths=-/run/plymouth /var/lib/plymouth /var/spool/plymouth`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `RestrictNamespaces=`, `SystemCallArchitectures=native`, `PrivateNetwork=`, `RestrictAddressFamilies=AF_UNIX` — an isolated `NoNewPrivileges=yes` layer, and a paired drop-in carrying the three NNP-companion process-internal-restriction directives `MemoryDenyWriteExecute=`, the subtractive `SystemCallFilter=@system-service` baseline minus eleven privileged subclasses, and `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_TTY_CONFIG CAP_CHOWN`) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the boot-time `init_t → plymouthd_t : process2 nnp_transition` allow rule.

The role does **not** add `PrivateDevices=`, `PrivateUsers=`, `DeviceAllow=`, `NoExecPaths=`, `ExecPaths=`, `ProtectProc=`, `ProcSubset=`, or `UMask=` (extending the surface to those classes is operator-policy outside this role), does **not** modify `/etc/plymouth/plymouthd.conf` (theme selection is operator-policy), does **not** modify `/usr/share/plymouth/themes/` content (theme content is package- or operator-policy), and does **not** touch the kernel cmdline plymouth flags (`splash`, `quiet`, `plymouth.enable=`). The role does **not** configure the companion units `plymouth-quit.service`, `plymouth-quit-wait.service`, or `plymouth-read-write.service` beyond using `plymouth-quit-wait.service` as a passive boot-completion smoketest anchor in the verify discipline. The full topic end-state, the verify discipline, the dual-class splash smoketest, and the three-stage rollback posture are documented in `docs/reference/topics/plymouth.md`.

There is no `restart plymouth-start.service` task or handler in this role: plymouth-start runs once during the early-boot sequence and the splash hand-off has already completed by the time the role finishes deploying, so the deploy lands in the live unit-state on the next reboot only.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_plymouth_dropin_dir` | `/etc/systemd/system/plymouth-start.service.d` | Drop-in directory for the unit. |
| `topic_plymouth_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_plymouth_required_packages` | `[plymouth]` | Required package; preflight asserts presence. |
| `topic_plymouth_cil_module_name` | `nnp_plymouth` | CIL module name without extension. |
| `topic_plymouth_cil_priority` | `400` | CIL load priority. |
| `topic_plymouth_daemon_bin_path` | `/usr/bin/plymouthd` | Stock daemon binary path validated by `matchpathcon` in preflight. |
| `topic_plymouth_expected_selinux_domain` | `plymouthd_t` | Expected SELinux domain referenced in preflight pre-test and verify checks. |
| `topic_plymouth_expected_type` | `forking` | Expected unit type. |
| `topic_plymouth_expected_active_state` | `active` | Expected `ActiveState` after a clean boot. |
| `topic_plymouth_expected_sub_state` | `exited` | Expected `SubState` after the splash hand-off completes. |
| `topic_plymouth_expected_result` | `success` | Expected unit `Result`. |
| `topic_plymouth_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_plymouth_expected_protect_system` | `strict` | Expected `ProtectSystem=`. |
| `topic_plymouth_expected_protect_home` | `yes` | Expected `ProtectHome=`. |
| `topic_plymouth_expected_protect_kernel_tunables` | `yes` | Expected `ProtectKernelTunables=`. |
| `topic_plymouth_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_plymouth_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_plymouth_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_plymouth_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_plymouth_expected_protect_hostname` | `yes` | Expected `ProtectHostname=`. |
| `topic_plymouth_expected_private_tmp` | `yes` | Expected `PrivateTmp=`. |
| `topic_plymouth_expected_lock_personality` | `yes` | Expected `LockPersonality=`. |
| `topic_plymouth_expected_restrict_realtime` | `yes` | Expected `RestrictRealtime=`. |
| `topic_plymouth_expected_restrict_suid_sgid` | `yes` | Expected `RestrictSUIDSGID=`. |
| `topic_plymouth_expected_restrict_namespaces` | `yes` | Expected `RestrictNamespaces=`. |
| `topic_plymouth_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_plymouth_expected_private_network` | `yes` | Expected `PrivateNetwork=`. |
| `topic_plymouth_expected_restrict_address_families` | `AF_UNIX` | Expected `RestrictAddressFamilies=` (single-element exact match). |
| `topic_plymouth_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_plymouth_expected_read_write_paths_substrings` | `[/run/plymouth, /var/lib/plymouth, /var/spool/plymouth]` | Substrings that must all appear in the runtime `ReadWritePaths` value. |
| `topic_plymouth_expected_syscall_filter_baseline_anchors` | `[read, write, openat, close, mmap, brk, exit_group, rt_sigaction]` | At least four must be present in the alphabetical syscall list. |
| `topic_plymouth_expected_syscall_filter_class_tokens` | `[@system-service, ~@privileged, ~@resources, ~@debug, ~@mount, ~@cpu-emulation, ~@obsolete, ~@raw-io, ~@reboot, ~@swap, ~@module, ~@clock]` | All twelve must be present in the merged unit body. |
| `topic_plymouth_expected_cap_bounding_set` | `[CAP_SYS_ADMIN, CAP_SYS_TTY_CONFIG, CAP_CHOWN]` | Three-set exact match for the capability-bounding set. |
| `topic_plymouth_expected_quitwait_active_state` | `active` | Expected `plymouth-quit-wait.service` `ActiveState`. |
| `topic_plymouth_expected_quitwait_sub_state` | `exited` | Expected `plymouth-quit-wait.service` `SubState`. |
| `topic_plymouth_expected_quitwait_result` | `success` | Expected `plymouth-quit-wait.service` `Result`. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the `restorecon` handler, and the AVC-clean read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_plymouth` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon` and `daemon-reload` handlers are wired through the `topic_plymouth dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in.
- There is no `restart plymouth-start.service` handler; the apply path is the next reboot.
- The live-state probe (post-deploy `plymouth-start` and `plymouth-quit-wait` state read, AVC count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
