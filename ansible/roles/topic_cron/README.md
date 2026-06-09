<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_cron

## Purpose

Topic role that hardens the `crond.service` deferred-job-execution daemon shipped by the `cronie` package on a Fedora 44 or later host. The role deploys four shipping artefacts: three drop-in files under `/etc/systemd/system/crond.service.d/` (a Phase-A namespace-default baseline, an isolated `NoNewPrivileges=yes` layer, and a process-internal kernel-restriction drop-in that carries the cronjob-user-switch privilege-drop carve-out — one positive `SystemCallFilter=` line for the `set{groups,gid,uid,resgid,resuid,regid,reuid}` family plus a three-cap `CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH`) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the two `process2 nnp_transition` rules the NNP layer depends on (rule 1: `init_t → crond_t`, boot-failure class; rule 2: `crond_t → system_cronjob_t`, confinement-leak class).

The role does **not** modify `/etc/crontab`, the operator-policy directories under `/etc/cron.{d,hourly,daily,weekly,monthly}/`, the access-control files `/etc/cron.allow` / `/etc/cron.deny`, the per-user crontab spool content under `/var/spool/cron/<user>/`, the `EnvironmentFile=/etc/sysconfig/crond` content, or the `/etc/anacrontab` file. Cronjob policy is operator-policy outside this role. The full topic end-state, the verify discipline (including the cronjob-spawn domain assertion via a one-minute test cronjob), and the three-stage rollback posture are documented in `docs/reference/topics/cron.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_cron_dropin_dir` | `/etc/systemd/system/crond.service.d` | Drop-in directory for the unit. |
| `topic_cron_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_cron_required_packages` | `[cronie]` | Required package; preflight asserts presence. |
| `topic_cron_cil_module_name` | `nnp_crond` | CIL module name without extension. |
| `topic_cron_cil_priority` | `400` | CIL load priority. |
| `topic_cron_binary_canonical` | `/usr/bin/crond` | Canonical (post-merge) daemon binary path checked by `matchpathcon`. |
| `topic_cron_binary_pre_merge` | `/usr/sbin/crond` | Pre-merge `ExecStart=` path checked by `matchpathcon`. |
| `topic_cron_expected_fcontext` | `crond_exec_t` | Expected fcontext mapping for the binary; preflight fail-fasts when neither path resolves to it. |
| `topic_cron_expected_selinux_domain` | `crond_t` | Expected SELinux domain of the running daemon. |
| `topic_cron_expected_cronjob_domain` | `system_cronjob_t` | Expected SELinux domain of cronjob-spawn child processes. |
| `topic_cron_expected_nnp` | `yes` | Expected `NoNewPrivileges=`. |
| `topic_cron_expected_mdwe` | `yes` | Expected `MemoryDenyWriteExecute=`. |
| `topic_cron_expected_protect_system` | `full` | Expected `ProtectSystem=`. |
| `topic_cron_expected_protect_home` | `yes` | Expected `ProtectHome=`. |
| `topic_cron_expected_protect_kernel_tunables` | `yes` | Expected `ProtectKernelTunables=`. |
| `topic_cron_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_cron_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_cron_expected_protect_control_groups` | `yes` | Expected `ProtectControlGroups=`. |
| `topic_cron_expected_private_tmp` | `yes` | Expected `PrivateTmp=`. |
| `topic_cron_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_cron_expected_protect_hostname` | `yes` | Expected `ProtectHostname=`. |
| `topic_cron_expected_lock_personality` | `yes` | Expected `LockPersonality=`. |
| `topic_cron_expected_restrict_realtime` | `yes` | Expected `RestrictRealtime=`. |
| `topic_cron_expected_restrict_suid_sgid` | `yes` | Expected `RestrictSUIDSGID=`. |
| `topic_cron_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_cron_expected_restrict_address_families` | `AF_UNIX AF_INET AF_INET6 AF_NETLINK` | Expected `RestrictAddressFamilies=` source-order four-element multiset. |
| `topic_cron_expected_cap_bounding_set_sorted` | `cap_dac_read_search cap_setgid cap_setuid` | Expected `CapabilityBoundingSet=` lowercase, alphabetically sorted. |
| `topic_cron_expected_scf_length_min` | `200` | Conservative lower bound on resolved `SystemCallFilter=` length. |
| `topic_cron_expected_scf_anchor_tokens` | `[@system-service, ~@privileged, setresuid, setgroups]` | Substring anchors asserted in resolved `SystemCallFilter=`. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` queries (one per CIL rule), the CIL install handler, the `restorecon` handler, the AVC-clean read, the SECCOMP-clean read, the live SELinux-domain read, and the cronjob-spawn domain assertion's test-cronjob write all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned two-rule CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean and SECCOMP-clean assertions in the role's modify stage and in `verify.sh` consume the audit pipeline that Layer 3 provisions.

## Tags

- `topic_cron` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification including the cronjob-spawn domain assertion.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart crond` handlers are wired through the `topic_cron dropin changed` notification name and fire only on a drop-in file change.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the two-rule CIL module is installed before the NNP drop-in is dropped in.
- The live-state probe (MainPID read, SELinux-domain read, AVC count, SECCOMP count) is read-only.
- The cronjob-spawn domain assertion in `verify.sh` writes a one-minute test cronjob at `/etc/cron.d/diataxis-verify-test`, waits up to 90 seconds for it to fire, reads `/run/diataxis-verify-cron.out`, and removes both files at end-of-run regardless of outcome via a `trap` on `EXIT`. The check is gated behind a `sysadm_t` domain check and reports `SKIP` from `staff_t` (cannot write under `/etc/cron.d/`).
- The `rescue:` block on the modify `block:` does **not** auto-rollback. Drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
- The unit ships no `RefuseManualStop=` directive; the `restart crond` handler path is structurally available, and reboot is **not** required for the drop-ins to take effect on the running daemon.
