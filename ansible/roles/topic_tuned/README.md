<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_tuned

## Purpose

Topic role that hardens the `tuned.service` dynamic-system-tuning daemon on a Fedora 44 or later host. The role deploys a single shipping artefact: one drop-in file under `/etc/systemd/system/tuned.service.d/` (a Phase-A namespace-default baseline that establishes the `Protect*` family with two operator-tunable opt-outs, plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, and `SystemCallArchitectures=`). Unlike the sibling hardware-class topics, this role ships **no** `99-nnp.conf` and **no** `99-process-restrict.conf` and **no** topic-owned SELinux CIL module: the deferred process-internal kernel-restriction layer for this Python-runtime daemon has not been validated end-to-end, so the present end-state is the Phase-A baseline only.

The two opt-outs (`ProtectKernelTunables=no` and `ProtectControlGroups=no`) are deliberate concessions to the daemon's profile execution path, which writes sysctl tunables under `/proc/sys/` and cgroup attributes under `/sys/fs/cgroup/` as part of every standard profile that ships with the package. Tightening either to `yes` is drift against this end-state. `ProtectSystem=full`-not-`strict` is the chosen value because the daemon self-creates `/run/tuned/` for its `PIDFile=/run/tuned/tuned.pid`; `full` leaves `/run` writable and avoids the need for a `ReadWritePaths=` carve-out.

The role does **not** modify `/etc/tuned/tuned-main.conf`, `/etc/tuned/active_profile`, the operator-policy profiles under `/etc/tuned/tuned-profiles/`, or the package-default profile data under `/usr/lib/tuned/`. Profile selection and profile content are operator-policy outside this topic. The full topic end-state, the verify discipline (including the deliberate `tuned-adm verify` non-invocation), and the two-stage rollback posture are documented in `docs/reference/topics/tuned.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_tuned_dropin_dir` | `/etc/systemd/system/tuned.service.d` | Drop-in directory for the unit. |
| `topic_tuned_required_packages` | `[tuned]` | Required package; preflight asserts presence. |
| `topic_tuned_binary_path_canonical` | `/usr/bin/tuned` | Canonical post-merge binary path. |
| `topic_tuned_binary_path_premerge` | `/usr/sbin/tuned` | Pre-merge binary path (the equivalency rewrites this to the canonical path). |
| `topic_tuned_expected_fcontext_canonical` | `tuned_exec_t` | Expected fcontext at the canonical path; preflight fail-fasts on any other mapping. |
| `topic_tuned_expected_fcontext_premerge` | `bin_t` | Expected fcontext at the pre-merge path (informational; the equivalency rewrites the lookup). |
| `topic_tuned_dropin_fcontext` | `systemd_unit_file_t` | Expected fcontext on the drop-in path; preflight fail-fasts on any other mapping. |
| `topic_tuned_expected_runtime_domain` | `tuned_t` | Expected SELinux domain of the running daemon. |
| `topic_tuned_expected_protect_system` | `full` | Expected `ProtectSystem=`. |
| `topic_tuned_expected_protect_home` | `yes` | Expected `ProtectHome=`. |
| `topic_tuned_expected_protect_kernel_tunables` | `no` | Deliberate opt-out — `yes` is drift. |
| `topic_tuned_expected_protect_kernel_modules` | `yes` | Expected `ProtectKernelModules=`. |
| `topic_tuned_expected_protect_kernel_logs` | `yes` | Expected `ProtectKernelLogs=`. |
| `topic_tuned_expected_protect_control_groups` | `no` | Deliberate opt-out — `yes` is drift. |
| `topic_tuned_expected_private_tmp` | `yes` | Expected `PrivateTmp=`. |
| `topic_tuned_expected_protect_clock` | `yes` | Expected `ProtectClock=`. |
| `topic_tuned_expected_protect_hostname` | `yes` | Expected `ProtectHostname=`. |
| `topic_tuned_expected_lock_personality` | `yes` | Expected `LockPersonality=`. |
| `topic_tuned_expected_restrict_realtime` | `yes` | Expected `RestrictRealtime=`. |
| `topic_tuned_expected_restrict_suid_sgid` | `yes` | Expected `RestrictSUIDSGID=`. |
| `topic_tuned_expected_syscall_architectures` | `native` | Expected `SystemCallArchitectures=`. |
| `topic_tuned_active_profile_marker` | `Current active profile:` | Marker the `tuned-adm active` smoketest expects on stdout. |
| `topic_tuned_avc_filter` | `(tuned_t\|tuned_exec_t\|tuned_log_t\|tuned_etc_t\|tuned_rw_etc_t)` | AVC filter expression; any non-zero hit is drift. |
| `topic_tuned_seccomp_filter` | `tuned` | SECCOMP filter expression; any non-zero hit is drift. |

The drop-in body is not exposed as a tunable. Operators who need to deviate from the shipped profile fork the role.

There is no `topic_tuned_expected_nnp` key (deliberate absence — no NNP drop-in shipped). There is no `topic_tuned_expected_mdwe`, `topic_tuned_expected_syscall_filter`, `topic_tuned_expected_cap_bounding_set`, or `topic_tuned_expected_restrict_address_families` key (deliberate absence — the deferred process-internal kernel-restriction layer is not part of this end-state). There is no `topic_tuned_expected_active_profile` key (operator-policy outside this topic). There is no `topic_tuned_cil_module_name` or `topic_tuned_cil_priority` key (no CIL module shipped).

## Dependencies

- `foundation_umask` (Layer 0) — the role writes the drop-in under `/etc/`. The `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the `restorecon` handler, the AVC-clean read, the SECCOMP-clean read, and the live SELinux-domain read transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean and SECCOMP-clean assertions in the role's modify stage and in `verify.sh` consume the audit pipeline that Layer 3 provisions.

`foundation_selinux_cil_bootstrap` is **not** a dependency. This topic ships no CIL module and does not invoke `semodule`. The dependency set is intentionally smaller than the sibling hardware-class topic roles.

## Tags

- `topic_tuned` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The single drop-in is pushed verbatim from `files/`.
- The `restorecon`, `daemon-reload`, and `restart tuned` handlers are wired through the `topic_tuned dropin changed` notification name and fire only on a drop-in file change.
- There is no `semodule install` handler (no CIL artefact ships) and no `meta: flush_handlers` synchronisation (no CIL load to sequence the drop-in push against).
- The live-state probe (MainPID read, SELinux-domain read, `tuned-adm active` read, AVC count, SECCOMP count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
