<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Bootstrap a hardened host

At the end of this tutorial you have a hardened Fedora 44 (or later) host with the Foundation layer applied, one example Topic role applied on top, every Foundation and Topic verify probe returning `0` from both contexts, and a stable role-switch reflex in place that carries you into every subsequent Topic onboarding without re-derivation.

## Audience

You are an operator new to this tree, working from a fresh Fedora 44 (or later) install with full administrative access on the target. You want the canonical guided path from zero to a verified hardened posture, walked end to end, with the example Topic on top so you reach the post-bootstrap surface that subsequent Topic onboarding consumes.

## Prerequisites

- The target runs Fedora 44 or later. Earlier releases are out of scope for this tree.
- `ansible-core` is installed on your control node, and a working Python interpreter is reachable on the target. The roles you will apply use only built-in `ansible.builtin.*` modules, so no Galaxy collection install is required beyond `ansible-core`.
- Your checkout contains the four Foundation roles `foundation_umask`, `foundation_sudo_roles`, `foundation_selinux_cil_bootstrap`, `foundation_audit_logging_baseline` and the example Topic role `topic_alsa_state` under `ansible/roles/`. The tutorial assumes your checkout matches the published tree; a missing role aborts apply before any host-side change. For the condensed task-form recipe that this tutorial wraps for the Foundation tier, see [Apply the Foundation tier](../how-to/apply-foundation.md).
- The target's SELinux runtime mode is `Enforcing` or `Permissive`. The mode `Disabled` is out of scope: recovery from `Disabled` requires a kernel-time toggle that no role in this tree performs.
- A second, password-protected login channel is reachable on the target. This is either a separate console login or a separate `ssh` session that authenticates as a different account (for example `root` or a second admin account). The channel is the recovery handle for the post-apply re-login in Step 3 if the new `staff_u` session refuses to establish.

## Step 1 — Probe

### Goal

You read the host's current Foundation and example-Topic state before any apply, so the apply steps that follow have a clean starting inventory to compare against.

### Steps

1. Run the four Foundation probes plus the example-Topic probe from a plain shell with no role switch.
   ```bash
   bash ansible/roles/foundation_umask/files/probe.sh
   bash ansible/roles/foundation_sudo_roles/files/probe.sh
   bash ansible/roles/foundation_selinux_cil_bootstrap/files/probe.sh
   bash ansible/roles/foundation_audit_logging_baseline/files/probe.sh
   bash ansible/roles/topic_alsa_state/files/probe.sh
   ```

2. Read the inventory each probe prints. Probe output is informational only — the gate to proceed is the `## Prerequisites` checklist above, not the probe.

### Verification

Run the verify probe:

```bash
bash ansible/roles/foundation_umask/files/probe.sh | head -1
```

You should see:

```text
(state inventory printed on stdout — informational only, no pass/fail line)
```

If the probe produces no output at all, the role tree is not present on the target or the working directory is wrong. Fix the working directory or the checkout before continuing; the probe itself never gates apply.

## Step 2 — Apply UMASK 027

### Goal

You install Layer 0 of the Foundation tier, establishing the system-wide login-time `UMASK` value `027` and the `HOME_MODE` value `0700` that every later layer and every Topic role consumes.

### Steps

1. Apply `foundation_umask` through the control node.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_umask ansible/playbooks/foundation.yml
   ```

2. The role writes `/etc/login.defs` through `ansible.builtin.lineinfile` with `backup: true`, so a `.bak` file alongside the original is the rollback source if you need to revert. The role does not push a `UMask=` directive into any systemd unit — that surface belongs to individual Topic roles that hard-set per-unit masks.

### Verification

Run the verify probe:

```bash
bash ansible/roles/foundation_umask/files/verify.sh
```

You should see:

```text
OK   login_defs_umask               027
OK   login_defs_home_mode           0700
OK   login_defs_usergroups_enab     yes
OK   pam_postlogin_umask            session optional pam_umask.so silent
OK   shell_init_no_umask_override   none
OK   bashrc_fallback_unchanged      [ `umask` -eq 0 ] && umask 022
OK   system_conf_no_default_umask   none
OK   live_login_umask               0027
```

The eight `OK …` line names are stable. Their semantics — what each line probes, why the `live_login_umask` check requires a fresh login shell, the directive set that each line locks in — live in [UMASK 0027](../reference/foundation/umask.md) §"Verification" and are reached by link rather than restated here. If the output differs, do not proceed to the next step. The Recovery section below names the rollback path for this layer; otherwise re-run the apply step after addressing the failing line.

## Step 3 — Apply staff_u and sudo roles

### Goal

You install Layer 1 of the Foundation tier, mapping your interactive account to the SELinux user `staff_u`, then terminate the current login and re-establish a fresh session so `pam_selinux` picks up the new mapping at session establishment.

### Steps

1. Apply `foundation_sudo_roles` through the control node.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_sudo_roles ansible/playbooks/foundation.yml
   ```

2. Terminate the current login on the target and open a fresh login through GDM, `sshd`, or a console. `pam_selinux` reads the mapping at session establishment, so the active login stays on the old context until you re-login. If the new login refuses to establish, fall back to the second login channel named in `## Prerequisites` and follow recovery path R2 in `## Recovery`.

### Verification

Run the verify probe:

```bash
id -Z
```

You should see:

```text
staff_u:staff_r:staff_t:s0-s0:c0.c1023
```

The exact `staff_u:staff_r:staff_t:s0-s0:c0.c1023` string is the single observable that confirms the re-login took effect. The role's full Soll/Ist surface and the `staff_sudo_t` versus `sysadm_t` distinction live in [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md). If `id -Z` reports anything else, do not proceed to the next step; consult that Reference and the second login channel named in `## Prerequisites` as the recovery handle.

## Step 4 — Apply SELinux CIL bootstrap

### Goal

You install Layer 2 of the Foundation tier from your now-`staff_u`-confined login; from this layer onward every `semodule`, `semanage`, `restorecon`, `ausearch`, `audit2allow`, and `audit2why` invocation on this layer and on Layer 3 runs as `sudo -r sysadm_r -t sysadm_t <cmd>` because plain `sudo` lands in `staff_sudo_t`, where the policy store is unreadable.

### Steps

1. Apply `foundation_selinux_cil_bootstrap` from your `staff_u`-confined login.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_selinux_cil_bootstrap ansible/playbooks/foundation.yml
   ```

2. The role provisions the publish-path directory at `/usr/local/share/selinux/`, makes the required tooling packages present, and runs a read-only live-state probe. It installs no specific custom policy module — module install belongs to Topic roles that ship CIL content. The role-switch syntax `sudo -r sysadm_r -t sysadm_t <cmd>` is the reflex you carry into every later step that touches the policy store, the audit store, or the system journal.

### Verification

Run the verify probe:

```bash
bash ansible/roles/foundation_selinux_cil_bootstrap/files/verify.sh
sudo -r sysadm_r -t sysadm_t bash ansible/roles/foundation_selinux_cil_bootstrap/files/verify.sh
```

You should see:

```text
OK   selinux_runtime_mode           Enforcing
OK   selinux_config_mode            enforcing
OK   selinux_config_type            targeted
OK   selinux_dir_present            /usr/local/share/selinux mode=0755 owner=root:root
OK   selinux_dir_label              system_u:object_r:usr_t:s0
OK   pkg_policycoreutils_python     installed
OK   pkg_selinux_policy_targeted    installed
SKIP semodule_callable              needs sysadm_t

OK   selinux_runtime_mode           Enforcing
...
OK   semodule_callable              semodule -lfull returned 0
```

The first invocation runs from `staff_t` and reports `SKIP semodule_callable needs sysadm_t`; the second invocation runs under the role-switch and flips that line to `OK semodule_callable`. The `SKIP → OK` transition is the single observable that confirms the role-switch reflex you established in Step 4's Goal is reaching the policy store correctly. The full directive surface lives in [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md). If `OK semodule_callable` does not appear under the role-switched pass, do not proceed; the `## Recovery` R3 path covers the misbehaving-module case.

## Step 5 — Apply audit and logging baseline

### Goal

You install Layer 3 of the Foundation tier, which makes the audit and journal subsystems present at the expected package, unit, and persistent-storage shape so Topic roles that push audit rule fragments or read the system journal have a stable baseline to consume.

### Steps

1. Apply `foundation_audit_logging_baseline` through the control node, with the role-switch reflex already established.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t foundation_audit_logging_baseline ansible/playbooks/foundation.yml
   ```

2. The role pushes no `auditd.conf`, no `/etc/audit/rules.d/` fragment, and no `journald.conf.d` drop-in. Its modify stage is confined to package presence, persistent-journal-directory presence, and a read-only live-state probe under the role-switch. Per-Topic audit-rule pushes belong to individual Topic roles, not to this Foundation layer.

### Verification

Run the verify probe:

```bash
bash ansible/roles/foundation_audit_logging_baseline/files/verify.sh
sudo -r sysadm_r -t sysadm_t bash ansible/roles/foundation_audit_logging_baseline/files/verify.sh
```

You should see:

```text
OK   pkg_audit                      installed
OK   pkg_audit_libs                 installed
OK   pkg_audit_rules                installed
OK   pkg_policycoreutils_python     installed
OK   unit_auditd                    active
OK   unit_systemd_journald          active
OK   journal_dir_present            /var/log/journal mode=02755 owner=root:systemd-journal
OK   journal_dir_label              system_u:object_r:var_log_t:s0
OK   journald_storage_effective     persistent
SKIP auditctl_state                 needs sysadm_t
SKIP journalctl_disk_usage          needs sysadm_t

OK   pkg_audit                      installed
...
OK   auditctl_state                 enabled=1 pid=<pid>
OK   journalctl_disk_usage          <bytes> on disk
```

The package, unit, and persistent-journal lines read from `staff_t` without escalation; the two `SKIP needs sysadm_t` lines from the `staff_t` pass flip to `OK …` lines under the role-switch. The full directive surface, the read-discipline that motivates the split between staff-readable and `sysadm_t`-only checks, and the AVC diagnosis loop that consumes the audit store live in [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md). If a `SKIP` line stays `SKIP` under the role-switched pass, the role-switch reflex from Step 4 has not taken; re-establish it from a fresh login shell and re-run.

## Step 6 — Apply example topic alsa-state

### Goal

You apply the example Topic role `topic_alsa_state` on top of the four Foundation layers; the role's `meta/main.yml` declares the four Foundation roles as dependencies, so Ansible's dependency resolver catches a missing Foundation layer before the Topic's `apply` stage reaches the target.

### Steps

1. Apply `topic_alsa_state` through the control node.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t topic_alsa_state ansible/playbooks/topic-alsa_state.yml
   ```

2. The role ships three drop-in INI files under `/etc/systemd/system/alsa-state.service.d/` (`99-hardening.conf` for the namespace-default baseline, `99-nnp.conf` for `NoNewPrivileges=yes`, `99-process-restrict.conf` for the kernel-level process restrictions) plus one CIL module at `/usr/local/share/selinux/nnp_alsa.cil` that grants the `init_t → alsa_t : process2 nnp_transition` rule stock targeted policy does not ship. The deploy ordering invariant — CIL module loaded before the `99-nnp.conf` drop-in lands — is enforced by an `ansible.builtin.meta: flush_handlers` step between the CIL install handler and the drop-in push. The daemon runs as root throughout its lifetime; no internal privilege drop applies, so the topic does not invoke the multi-stage carve-out pattern that other profiles in this tree carry.

### Verification

Run the verify probe:

```bash
bash ansible/roles/topic_alsa_state/files/verify.sh
sudo -r sysadm_r -t sysadm_t bash ansible/roles/topic_alsa_state/files/verify.sh
```

You should see:

```text
OK   NoNewPrivileges                yes
OK   MemoryDenyWriteExecute         yes
OK   CapabilityBoundingSet          (empty)
OK   RestrictAddressFamilies        AF_UNIX AF_NETLINK
OK   SystemCallFilter_length        >= 1500 bytes
OK   SystemCallFilter_anchor_epoll  present
OK   SystemCallFilter_anchor_recv   present
OK   SystemCallArchitectures        native
OK   ProtectSystem                  full
OK   live_selinux_domain            alsa_t
OK   live_uid_gid                   0 / 0
OK   live_comm                      alsactl
OK   state_file_size                > 0
SKIP semodule_nnp_alsa              needs sysadm_t

OK   NoNewPrivileges                yes
...
OK   semodule_nnp_alsa              400 nnp_alsa cil
```

The line set in full plus the source-order, length-plus-anchor, and live-`comm` probes that defeat the vendor `ExecStart=` dash-prefix exit-masking live in [alsa-state](../reference/topics/alsa-state.md). The Topic's `## Related patterns` section cross-links to [NNP and SELinux transition trap](../explanation/nnp-selinux-transition-trap.md) — the class of trap that the topic-owned `nnp_alsa.cil` lifts — and the link resolves on this tree. If `live_comm` is anything other than `alsactl`, the daemon has died after `execve(2)` and the vendor unit's dash-prefix has masked the exit; do not proceed, and inspect SECCOMP records from `sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot`.

## Step 7 — Final verification

### Goal

You re-run every verify script in dependency order from a fresh login shell, first as `staff_t` and then under the role-switch, and confirm that the five `## Related patterns` cross-link targets resolve on this tree.

### Steps

1. Open a fresh login shell and re-run the five verify scripts in both contexts.
   ```bash
   for r in foundation_umask foundation_sudo_roles foundation_selinux_cil_bootstrap foundation_audit_logging_baseline topic_alsa_state; do
     bash "ansible/roles/${r}/files/verify.sh"
     sudo -r sysadm_r -t sysadm_t bash "ansible/roles/${r}/files/verify.sh"
   done
   ```

2. Read each script's exit code. Each script exits `0` on a clean host, `1` on drift, and `2` on invocation error.

### Verification

Run the verify probe:

```bash
for r in foundation_umask foundation_sudo_roles foundation_selinux_cil_bootstrap foundation_audit_logging_baseline topic_alsa_state; do
  bash "ansible/roles/${r}/files/verify.sh"   >/dev/null && echo "OK   ${r} staff_t pass"   || echo "FAIL ${r} staff_t pass"
  sudo -r sysadm_r -t sysadm_t bash "ansible/roles/${r}/files/verify.sh" >/dev/null && echo "OK   ${r} sysadm_t pass" || echo "FAIL ${r} sysadm_t pass"
done
```

You should see:

```text
OK   foundation_umask staff_t pass
OK   foundation_umask sysadm_t pass
OK   foundation_sudo_roles staff_t pass
OK   foundation_sudo_roles sysadm_t pass
OK   foundation_selinux_cil_bootstrap staff_t pass
OK   foundation_selinux_cil_bootstrap sysadm_t pass
OK   foundation_audit_logging_baseline staff_t pass
OK   foundation_audit_logging_baseline sysadm_t pass
OK   topic_alsa_state staff_t pass
OK   topic_alsa_state sysadm_t pass
```

Every verify exits `0` in both contexts, every `SKIP needs sysadm_t` line emitted in the `staff_t` pass is reported as `OK …` in the `sysadm_t` pass, and the cross-links from the five Reference articles to their `docs/explanation/*.md` Pattern targets all resolve to existing files: [UMASK 0027](../reference/foundation/umask.md) links to [UMASK and daemon readability](../explanation/umask-and-daemon-readability.md); [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md) links to [Sudo custom logfile and SELinux labeling](../explanation/sudo-logfile-seclabel.md) plus the same [UMASK and daemon readability](../explanation/umask-and-daemon-readability.md); [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) cross-links to the Layer 1 Reference; [Audit and logging baseline](../reference/foundation/audit-logging-baseline.md) links to [Sudo custom logfile and SELinux labeling](../explanation/sudo-logfile-seclabel.md); [alsa-state](../reference/topics/alsa-state.md) links to [NNP and SELinux transition trap](../explanation/nnp-selinux-transition-trap.md) and [Multi-stage privilege-drop and SystemCallFilter carve-outs](../explanation/phase-b-scf-privdrop.md). From this point on, the canonical condensed task form for layering further Foundation re-applies or running the Foundation tier against a new host is [Apply the Foundation tier](../how-to/apply-foundation.md); the next-Topic recipe is in `## See also`.

## Recovery

R1 — Revert Layer 0. The Layer 0 `lineinfile` task writes a `.bak` backup alongside `/etc/login.defs` before editing. Restore the backup file in place and re-run `bash ansible/roles/foundation_umask/files/verify.sh`; the eight Layer 0 verify lines drop back to their pre-apply values and no reboot is required.

R2 — Recover from the Layer 1 re-login dead-end. If the post-apply login from Step 3 refuses to establish — typically because your account has no `wheel` membership and the `sudoers` configuration has not yet been edited to permit the new role — authenticate through the second login channel named in `## Prerequisites` and revert the mapping with `semanage login -m -s unconfined_u <user>` run under `sudo -r sysadm_r -t sysadm_t`. The next interactive login as `<user>` returns to `unconfined_u`.

R3 — Revert a misbehaving priority-400 module. A custom CIL module loaded by Layer 2 or by `topic_alsa_state` that prevents the host from booting normally is removed with `sudo -r sysadm_r -t sysadm_t semodule -X 400 -r <name>`. The coarser host-wide brake is `sudo -r sysadm_r -t sysadm_t setenforce 0`, which logs denials without enforcing them; `sudo -r sysadm_r -t sysadm_t setenforce 1` re-enables enforcement.

R4 — Roll `topic_alsa_state` back layer-by-layer. Remove `/etc/systemd/system/alsa-state.service.d/99-process-restrict.conf` alone, then `systemctl daemon-reload && systemctl restart alsa-state.service`, which reverts the kernel-level process restrictions while leaving NNP and the namespace-default baseline in effect; if the failure persists, remove `99-nnp.conf` in addition and unload the topic-owned CIL extension with `sudo -r sysadm_r -t sysadm_t semodule -X 400 -r nnp_alsa`; if the failure still persists, remove `99-hardening.conf` in addition; the last lever is the CIL module itself, which is harmless to leave on disk once the NNP drop-in is gone. The three-stage rollback maps the four shipping artefacts to four reverse-order operations.

If the host fails to boot after applying changes, follow [Recover from boot failure](../how-to/recover-from-boot-failure.md).

## See also

- [Apply the Foundation tier](../how-to/apply-foundation.md) — the condensed task-form Foundation recipe once this tutorial is internalised.
- [Apply one Topic role](../how-to/apply-topic.md) — the next-Topic recipe for layering additional Topic roles beyond `alsa-state`.
- [Recover from boot failure](../how-to/recover-from-boot-failure.md) — the recovery handle when a drop-in or CIL module the operator deployed prevents the host from completing boot.
