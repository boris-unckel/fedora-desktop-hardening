<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_aide

## Purpose

Topic role that deploys the AIDE file-integrity-monitor profile on a Fedora 44 or later host. The role ships three core artefacts plus one optional artefact and one managed configuration block: an operator-supplied oneshot service unit `aide-check.service` and a daily timer `aide-check.timer` under `/etc/systemd/system/`, a topic-owned three-rule SELinux CIL module `aide_extras.cil` under `/usr/local/share/selinux/` (rule 1: `aide_t × dosfs_t : filesystem getattr`; rule 2: `aide_t × xdm_var_run_t : sock_file write`; rule 3: `aide_t × xdm_t : unix_stream_socket connectto`), an opt-in acknowledgement-aware interactive-shell push-banner `aide-alert.sh` under `/etc/profile.d/`, and a managed marker-delimited scope-tuning block appended to the stock `/etc/aide.conf` via `ansible.builtin.blockinfile`. The role does **not** run `aide --init` itself; the operator runs the canonical baseline-refresh sequence under `sudo -r sysadm_r -t sysadm_t` and the role surfaces a `pause:` task with the exact command sequence when the database is missing or when the managed scope block changed.

The role manages `/etc/aide.conf` only through its marker-delimited scope-tuning block; the stock body outside that block, the cron-driven `/etc/cron.daily/aide` package wrapper, and the broader AIDE selector grammar are out of scope. The block edit preserves the file's `0600 root:root` mode and `etc_t` label and never widens the mode. The full topic end-state, the verify discipline (timer activity, three-rule CIL presence, AVC-clean assertion, database-presence assertion, configuration-mode assertion, scope-block marker presence, `aide --config-check` clean parse, banner acknowledgement-block presence, `matchpathcon` either-or fail-fast for `aide_exec_t`), the database refresh discipline, the AIDE bitmask exit-code semantics, and the rollback posture are documented in `docs/reference/topics/aide.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_aide_unit_dir` | `/etc/systemd/system` | Unit-file directory for the operator-supplied service and timer. |
| `topic_aide_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_aide_profile_d_dir` | `/etc/profile.d` | Directory for the optional push-banner. |
| `topic_aide_required_packages` | `[aide]` | Required package; preflight asserts presence. |
| `topic_aide_cil_module_name` | `aide_extras` | CIL module name without extension. |
| `topic_aide_cil_priority` | `400` | CIL load priority. |
| `topic_aide_install_alert_banner` | `true` | Toggle for the optional `/etc/profile.d/aide-alert.sh` artefact. |
| `topic_aide_binary_canonical` | `/usr/bin/aide` | Canonical (post-merge) daemon binary path checked by `matchpathcon`. |
| `topic_aide_binary_pre_merge` | `/usr/sbin/aide` | Package-installed path checked by `matchpathcon`. |
| `topic_aide_expected_fcontext` | `aide_exec_t` | Expected fcontext mapping for the binary; preflight fail-fasts when neither path resolves to it. |
| `topic_aide_expected_selinux_domain` | `aide_t` | Expected SELinux runtime domain of the timer-spawned process. |
| `topic_aide_db_path` | `/var/lib/aide/aide.db.gz` | Database file path. |
| `topic_aide_db_dir` | `/var/lib/aide` | Database directory. |
| `topic_aide_log_dir` | `/var/log/aide` | Log directory. |
| `topic_aide_conf_path` | `/etc/aide.conf` | Configuration file path. |
| `topic_aide_expected_db_mode` | `600` | Expected database mode. |
| `topic_aide_expected_db_owner` | `root` | Expected database owner. |
| `topic_aide_expected_db_group` | `root` | Expected database group. |
| `topic_aide_expected_db_seltype` | `aide_db_t` | Expected database SELinux type. |
| `topic_aide_expected_conf_mode` | `600` | Expected configuration mode. |
| `topic_aide_expected_conf_owner` | `root` | Expected configuration owner. |
| `topic_aide_expected_conf_group` | `root` | Expected configuration group. |
| `topic_aide_expected_conf_seltype` | `etc_t` | Expected configuration SELinux type. |
| `topic_aide_expected_unit_mode` | `0644` | Expected unit-file mode. |
| `topic_aide_expected_unit_owner` | `root` | Expected unit-file owner. |
| `topic_aide_expected_unit_group` | `root` | Expected unit-file group. |
| `topic_aide_expected_unit_seltype` | `systemd_unit_file_t` | Expected unit-file SELinux type. |
| `topic_aide_expected_timer_active` | `active` | Expected `systemctl is-active aide-check.timer`. |
| `topic_aide_expected_timer_enabled` | `enabled` | Expected `systemctl is-enabled aide-check.timer`. |
| `topic_aide_expected_cil_allow_rules` | `3` | Expected number of allow rules in `aide_extras.cil`. |

The unit-file bodies, the CIL body, and the banner body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes unit files under `/etc/systemd/system/`, the CIL source under `/usr/local/share/selinux/`, and the optional banner under `/etc/profile.d/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` queries (one per CIL rule), the CIL install handler, the `restorecon` handlers, the AVC-clean read, the file `ansible.builtin.copy` tasks, and the operator's database refresh sequence all transit through `sudo -r sysadm_r -t sysadm_t`. Plain `sudo` from a `staff_sudo_t` context fails with `execmem` AVCs against AIDE's hash-routine `mmap(PROT_EXEC)` and lacks DAC search rights on `/var/log/aide/`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned three-rule CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_aide` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — CIL install, unit-file deployment, optional banner deployment, timer enable, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The two unit files, the CIL source, and the optional banner are pushed verbatim from `files/`.
- `ansible.builtin.blockinfile` is idempotent on the marker-delimited block: a re-apply against an unchanged `topic_aide_scope_block` reports no change. The task sets `mode: "0600"`, `owner: root`, `group: root` explicitly so an in-place edit preserves the stock `0600 root:root` triplet rather than widening it.
- `aide --config-check` is read-only (`changed_when: false`); it gates the apply (`failed_when: rc != 0`) so a malformed merged configuration aborts the run before the timer is enabled.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart aide-check.timer` handlers are wired through the `topic_aide unit changed` notification name and fire only on a unit-file change. The banner-only `restorecon` handler is wired through the `topic_aide banner changed` channel.
- There is **no** `restart aide-check.service` handler; the service is `Type=oneshot` and is not held active between runs.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for the unit files and the timer enable: the three-rule CIL module is loaded before the timer first fires, so the daily check sees the closed policy gaps from the first run.
- The role does **not** run `aide --init`. When the database file at `/var/lib/aide/aide.db.gz` is absent, or when the managed scope block changed `/etc/aide.conf` on this run, the role surfaces a `pause:` task with the canonical refresh-discipline command sequence; the operator runs the sequence in another shell and presses ENTER to continue. The first baseline and any rebaseline are operator-driven and not part of the idempotent flow.
- Setting `topic_aide_install_alert_banner: false` removes the `/etc/profile.d/aide-alert.sh` file via an `ansible.builtin.file` task with `state: absent`. The toggle is symmetric across re-applies.
- The live-state probe (`ExecMainStatus` read, AVC count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. Drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and documented in the topic Reference.
- On a correctly applied host with the database baseline in place, `--check` reports zero changes. Stated as a claim, not a guarantee.
