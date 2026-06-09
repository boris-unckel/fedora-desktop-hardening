<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Apply the Foundation tier

## Goal

At the end of this procedure, the four Foundation layers are applied, verified, and ready to receive Topic roles.

## Prerequisites

- The target host runs Fedora 44 or later. The new tree's baseline is Fedora 44; earlier releases are out of scope.
- `ansible-core` is installed on the control node, and a working Python interpreter is available on the target. The four Foundation roles use only built-in Ansible modules (`ansible.builtin.*`), so no Galaxy collection install is required on the control node beyond `ansible-core`.
- The four Foundation roles are present under `ansible/roles/foundation_umask/`, `ansible/roles/foundation_sudo_roles/`, `ansible/roles/foundation_selinux_cil_bootstrap/`, and `ansible/roles/foundation_audit_logging_baseline/` in the checkout. The procedure assumes the checkout matches the published tree; missing roles abort apply before any host-side change.
- The target's SELinux runtime mode is `Enforcing` or `Permissive`. The mode `Disabled` is out of scope: the Layer 2 verify script reports `Disabled` as `FAIL` because recovery from `Disabled` requires a kernel-time toggle that no Foundation role performs.
- The operator's POSIX account exists on the target. This account is the one that the Layer 1 role maps to `staff_u`; passing the wrong account name to the role variable produces a confined session for a different user and leaves the operator unconfined.
- A second, password-protected login channel is reachable on the target. This is either a separate console login or a separate `ssh` session that authenticates as a different account (`root` or a second admin account). The channel is the recovery path for the post-apply re-login in Step 3 if the new `staff_u` session refuses to establish.

## Steps

1. Probe the host's current Foundation state before any apply.
   ```bash
   bash ansible/roles/foundation_umask/files/probe.sh
   bash ansible/roles/foundation_selinux_cil_bootstrap/files/probe.sh
   bash ansible/roles/foundation_sudo_roles/files/probe.sh
   bash ansible/roles/foundation_audit_logging_baseline/files/probe.sh
   ```
   Expected outcome: each of the four per-role `probe.sh` scripts runs from a plain shell with no role switch and prints a read-only inventory of the current state. Probe output is informational only — the gate to apply is the `## Prerequisites` checklist above, not the probe.

2. Apply Layer 0 (`foundation_umask`) through the control node.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_umask ansible/playbooks/foundation.yml
   ```
   Expected outcome: the role's `verify.sh` task exits `0` and the playbook reports eight `OK …` lines from the Layer 0 verify — `login_defs_umask`, `login_defs_home_mode`, `login_defs_usergroups_enab`, `pam_postlogin_umask`, `shell_init_no_umask_override`, `bashrc_fallback_unchanged`, `system_conf_no_default_umask`, and `live_login_umask`. The line semantics are documented in [UMASK 0027](../reference/foundation/umask.md).

3. Apply Layer 1 (`foundation_sudo_roles`) and re-login on the target to activate the `staff_u` mapping.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_sudo_roles ansible/playbooks/foundation.yml
   ```
   Expected outcome: the role writes the per-user mapping to `/etc/selinux/targeted/seusers` through `semanage login -m`, but `pam_selinux` reads the mapping only at the next session establishment. Terminate the current login on the target and open a fresh login through GDM, `sshd`, or a console before Step 4; the next `id -Z` must report `staff_u:staff_r:staff_t:s0-s0:c0.c1023`. If the new login refuses to establish, fall back to the second login channel named in `## Prerequisites` and follow recovery path R2 in `## Recovery`. The role's surface, the `staff_sudo_t` versus `sysadm_t` distinction, and the canonical role-switch syntax are documented in [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md).

4. Apply Layer 2 (`foundation_selinux_cil_bootstrap`) from the new `staff_u`-confined login.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_selinux_cil_bootstrap ansible/playbooks/foundation.yml
   ```
   From this layer onward, every interactive `semodule`, `semanage`, `restorecon`, `ausearch`, `audit2allow`, and `audit2why` invocation runs as `sudo -r sysadm_r -t sysadm_t <cmd>` from the now-`staff_u`-confined login; the syntax and rationale live in [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md) and are not re-derived here. Expected outcome: the Layer 2 `verify.sh` exits `0` and reports the public-readable `OK …` lines (`selinux_runtime_mode`, `selinux_config_mode`, `selinux_config_type`, `selinux_dir_present`, `selinux_dir_label`, `pkg_policycoreutils_python`, `pkg_selinux_policy_targeted`) along with one `SKIP semodule_callable needs sysadm_t` line; re-running `bash ansible/roles/foundation_selinux_cil_bootstrap/files/verify.sh` under `sudo -r sysadm_r -t sysadm_t` flips that line to `OK semodule_callable`, as documented in [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md).

5. Apply Layer 3 (`foundation_audit_logging_baseline`).
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_audit_logging_baseline ansible/playbooks/foundation.yml
   ```
   Expected outcome: the role's `verify.sh` exits `0` and reports the package, unit, and persistent-journal lines that the verify reads from `staff_t` (`pkg_audit`, `pkg_audit_libs`, `pkg_audit_rules`, `pkg_policycoreutils_python`, `unit_auditd`, `unit_systemd_journald`, `journal_dir_present`, `journal_dir_label`, `journald_storage_effective`), along with two `SKIP needs sysadm_t` lines for `auditctl_state` and `journalctl_disk_usage`; re-running the verify under `sudo -r sysadm_r -t sysadm_t` flips both `SKIP` lines to `OK`. The line semantics and the read-discipline that motivates the split are documented in [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md).

6. Run the final post-apply verification across all four layers from a fresh login shell.
   ```bash
   for r in foundation_umask foundation_sudo_roles foundation_selinux_cil_bootstrap foundation_audit_logging_baseline; do
     bash "ansible/roles/${r}/files/verify.sh"
     sudo -r sysadm_r -t sysadm_t bash "ansible/roles/${r}/files/verify.sh"
   done
   ```
   Expected outcome: every script exits `0` in both contexts, every `SKIP needs sysadm_t` line emitted in the `staff_t` pass is reported as `OK` in the `sysadm_t` pass, and the four `## Related patterns` cross-links from [UMASK 0027](../reference/foundation/umask.md), [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md), [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md), and [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md) resolve to existing Explanation articles under `docs/explanation/`.

## Recovery

R1 — Revert Layer 0. The Layer 0 `lineinfile` task writes a `.bak` backup alongside `/etc/login.defs` before editing. Restore the backup file in place and re-run `bash ansible/roles/foundation_umask/files/verify.sh`; the eight Layer 0 verify lines drop back to their pre-apply values and no reboot is required.

R2 — Recover from the Layer 1 re-login dead-end. If the post-apply login from Step 3 refuses to establish — typically because the operator's account has no `wheel` membership and the `sudoers` configuration has not yet been edited to permit the new role — authenticate through the second login channel named in `## Prerequisites` and revert the mapping with `semanage login -m -s unconfined_u <user>` run under `sudo -r sysadm_r -t sysadm_t`. The next interactive login as `<user>` returns to `unconfined_u`.

R3 — Revert a misbehaving priority-400 module. A custom CIL module loaded by Layer 2 or by a later Topic role that prevents the host from booting normally is removed with `sudo -r sysadm_r -t sysadm_t semodule -X 400 -r <name>`. The coarser host-wide brake is `sudo -r sysadm_r -t sysadm_t setenforce 0`, which logs denials without enforcing them; `setenforce 1` re-enables enforcement. If the host fails to boot at all, follow [Recover from boot failure](recover-from-boot-failure.md).

If the host fails to boot after applying changes, follow [Recover from boot failure](recover-from-boot-failure.md).
