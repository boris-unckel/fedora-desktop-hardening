<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Preserve SELinux posture through a major Fedora upgrade

## Goal

At the end of this procedure, the host has been upgraded from Fedora release `<release-N>` to release `<release-N1>` (the canonical worked example used throughout this article is `F43→F44`; every later `N → N+1` follows the same shape), the SELinux posture established by the Foundation tier and by any applied Topic role is preserved across the upgrade boundary, the custom CIL modules at priority 400 are still loaded and active under the upgraded `selinux-policy` package, the runtime mode has been returned from `Permissive` (held during the upgrade) to `Enforcing` with no AVC storm in the post-switch observation window, and the four Foundation `verify.sh` scripts together with every previously-applied Topic `verify.sh` exit `0` in both `staff_t` and `sysadm_t` contexts.

## Prerequisites

- (a) The host is Foundation-hardened per [Apply the Foundation tier](apply-foundation.md) before the upgrade begins. The Foundation tier was in force when the upgrade began; this how-to preserves that state across the upgrade boundary and re-verifies it on the upgraded host.
- (b) The host runs Fedora release `N`, where `N` is one minor release behind the upstream-released `N+1` and `N+1` is Fedora 44 or later. The worked example named in `## Goal` is the only place this tree mentions a release earlier than 44; later `N → N+1` bumps follow the same procedure without modification.
- (c) A full off-host backup of the root filesystem is available — an external SSD image, a borg or restic snapshot, or an equivalent block-level capture taken within the preceding 24 hours. The capture is off-host and block-level (or equivalent) so the operator has a non-`dnf`-mediated rollback target that survives a half-applied upgrade. The form of the backup is operator choice; the prerequisite names only the shape, not a specific tool.
- (d) A configuration-tier tar snapshot of `/etc/{selinux,systemd,sysctl.d,sudoers.d,audit,pam.d,security}` and the priority-400 module directory (`/var/lib/selinux/targeted/active/modules/400/`) has been taken with extended attributes, ACLs, and SELinux labels preserved. The canonical capture shape is `tar --xattrs --xattrs-include='*' --acls --selinux --numeric-owner -czf …`; Step 1 takes a fresh snapshot just before the upgrade starts, but a baseline snapshot within the preceding 24 hours is the prerequisite that guarantees recovery is possible if Step 1 itself does not complete.
- (e) The SELinux runtime is `Enforcing` and the persistent setting in `/etc/selinux/config` is `enforcing`. Step 3 is the place where both are flipped to `permissive`; this prerequisite documents the pre-Step-3 state so the post-upgrade Enforcing-re-switch in Step 8 has a known target to return to.
- (f) Physical or remote-console access to the target is available, so the operator can address a boot-time failure if one occurs during the `dnf system-upgrade reboot` stage despite the Permissive-mode mitigation in Step 3. The recovery anchor is [Recover from boot failure](recover-from-boot-failure.md); the rescue surfaces it documents (rescue-target via GRUB edit, Live-image via firmware boot menu) both require pre-systemd kernel access, which network logins cannot provide.
- (g) An AIDE baseline refresh has been performed within the preceding 24 hours so that the post-upgrade daily AIDE check does not drown the operator in expected-mtime drift across the upgraded RPM set. The form is `sudo -r sysadm_r -t sysadm_t aide --update && sudo -r sysadm_r -t sysadm_t mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz`; Step 1 refreshes the baseline a second time inside the procedure window, and Step 8 closes the procedure with a deferred re-refresh.

## Steps

1. Capture a configuration-tier tar snapshot and refresh the AIDE baseline.
   ```bash
   sudo -r sysadm_r -t sysadm_t tar --xattrs --xattrs-include='*' --acls --selinux --numeric-owner -czf /var/tmp/pre-upgrade-config-<TS>.tar.gz /etc/{selinux,systemd,sysctl.d,sudoers.d,audit,pam.d,security} /var/lib/selinux/targeted/active/modules/400/
   sudo -r sysadm_r -t sysadm_t aide --update && sudo -r sysadm_r -t sysadm_t mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
   ```
   Expected outcome: the tar archive lands at `/var/tmp/pre-upgrade-config-<TS>.tar.gz` with the canonical option set preserving xattrs, ACLs, and SELinux labels, and includes both the host-side configuration tree and the compiled priority-400 module store. The snapshot is the source the operator unpacks in `## Recovery` path R3 when a priority-400 module does not survive the upgrade. The snapshot captures only host-side configuration; the Topic-role `tasks/main.yml` files that describe each topic's apply procedure live in the operator's repository checkout, are version-controlled separately, and are documented in [Apply one Topic role](apply-topic.md). The integrity baseline refresh produces a fresh `/var/lib/aide/aide.db.gz` so the post-upgrade daily check has a clean reference to diff against.

2. Snapshot the pre-upgrade AVC counter and the boot-time AVC backlog as the post-upgrade diff base.
   ```bash
   sudo -r sysadm_r -t sysadm_t auditctl -s > /var/tmp/avc-counter-pre-<TS>.txt
   sudo -r sysadm_r -t sysadm_t ausearch -m avc -ts boot > /var/tmp/avc-backlog-pre-<TS>.txt
   ```
   Expected outcome: the counter file records the running `auditd` state — `enabled`, `failure`, `pid`, `rate_limit`, `backlog_limit`, `lost`, `backlog`, and the `loginuid_immutable` flag — together with the AVC cluster count that the kernel has emitted up to this moment. The backlog file records every AVC record since the last boot, in the kernel's own line shape. Both files are the diff base for the Step 6 classification: any cluster that appears in the post-upgrade backlog but not in this pre-upgrade backlog is upgrade-induced, every cluster that appears in both is pre-existing and outside the upgrade's scope.

3. Switch SELinux to Permissive at runtime and persistently in `/etc/selinux/config`.
   ```bash
   sudo -r sysadm_r -t sysadm_t setenforce 0
   sudo -r sysadm_r -t sysadm_t sed -i.bak.<TS> 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
   ```
   Expected outcome: `getenforce` reports `Permissive` for the runtime check, `grep ^SELINUX= /etc/selinux/config` reports `SELINUX=permissive` for the persistent check, and the backup file lands at `/etc/selinux/config.bak.<TS>` — that backup is the rollback anchor for `## Recovery` path R1. After the in-place edit, the operator runs `sudo -r sysadm_r -t sysadm_t restorecon -v /etc/selinux/config` once to re-assert the `selinux_config_t` label on the rewritten file (the `sed -i` form removes and recreates the inode, which would otherwise inherit the operator's process context). The Permissive-not-Disabled rationale: an Enforcing-mode upgrade trips on any policy-load divergence between release `N` and release `N+1` as the new `selinux-policy` package activates at the end of `dnf system-upgrade reboot` — AVCs that would be silently logged under Permissive become enforced denials immediately and can take down system-init-time daemons. A Disabled-mode upgrade is worse: it forces a host-wide `/.autorelabel` walk on the next re-enable that takes minutes to hours on a populated host and risks the boot-failure class for any mislabelled init-time path. Permissive preserves the labels, keeps the priority-400 modules active in read-only-logging mode, and converts post-upgrade policy divergence from "enforcement risk" to "auditable AVC backlog".

4. Run `dnf system-upgrade download` and `dnf system-upgrade reboot`.
   ```bash
   sudo -r sysadm_r -t sysadm_t dnf system-upgrade download --releasever=<release-N1>
   sudo -r sysadm_r -t sysadm_t dnf system-upgrade reboot
   ```
   Expected outcome: the `download` stage fetches every package needed for the cross-release transition (`selinux-policy` is among them), resolves the dependency graph against `<release-N1>` repodata, and stages the packages in `/var/lib/dnf/system-upgrade/`. The `reboot` stage triggers the offline-upgrade reboot path: the host reboots into the `system-upgrade.target` early target, installs the staged packages without an interactive console, and reboots a second time into the first post-upgrade userspace. The host is reachable interactively again after the second reboot completes. If the second reboot does not complete, follow `## Recovery` path R2.

5. On the first post-upgrade boot under Permissive, run the operator's workflow smoketests and collect the AVC backlog since boot.
   ```bash
   <smoketest_command>
   sudo -r sysadm_r -t sysadm_t ausearch -m avc -ts boot > /var/tmp/avc-post-upgrade-permissive-<TS>.txt
   ```
   Expected outcome: the smoketests exercise the operator's daily-workflow surface (login session establishment under `staff_u`, terminal emulator, audio stack, font and codec discovery, web browser session, mail client) so that any upgrade-induced confinement gap surfaces as an AVC cluster in the backlog rather than as a silent user-visible regression. The backlog file is the comprehensive input the Step 6 classification reads; clusters in this file but not in the Step 2 baseline are upgrade-induced. The host is in Permissive mode at this point, so every AVC is log-only and no daemon is at risk of denial-induced failure.

6. Run the post-upgrade diagnostic wave — priority-400 module inventory, NNP-allow-rule probe across every previously-applied Topic-role domain, AVC cluster classification, and the `<release-N1>` fcontext scan-discipline. All four read-only probes run from one role-switched shell.
   ```bash
   # (a) priority-400 module inventory
   sudo -r sysadm_r -t sysadm_t semodule -lfull | awk '$1 == "400"'

   # (b) NNP-allow-rule probe against every previously-applied Topic-role domain
   sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t <topic_role_short>_t \
     -c process2 -p nnp_transition

   # (c) post-upgrade Permissive-phase AVC cluster classification
   sudo -r sysadm_r -t sysadm_t ausearch -m avc -ts boot \
     | sudo -r sysadm_r -t sysadm_t audit2allow -a

   # (d) post-upgrade fcontext scan-discipline; the scan loop body lives in the
   #     linked Pattern Explanation and is not duplicated here
   ```
   Expected outcome: the diagnostic wave is purely read-only and no host-state-changing operation is performed in this step. Probe (a) lists every active priority-400 module by name and CIL-versus-PP form; on `<release-N1>` the active-store CIL is bzip2-compressed where `<release-N>` stored it plain, so operators who read the CIL bodies directly use `bzcat` on the upgraded host when reaching into `/var/lib/selinux/targeted/active/modules/400/<module>/cil`. A module that was present before the upgrade and absent here is the trigger for `## Recovery` path R3 and is addressed by re-installing the missing module from the configuration-tier tar snapshot taken in Step 1. Probe (b) re-runs the per-domain NNP-transition check that the NNP and SELinux transition trap Pattern Explanation documents (the cross-link to that Explanation lives in Step 7's expected-outcome paragraph, where the same trap class is the recovery anchor for the cold-boot path), against every previously-applied Topic-role domain that the host carries; an empty result for any one `<topic_role_short>_t` domain is a stop-and-act event, and the operator extends the Layer 2 publish-path CIL module per [SELinux custom CIL bootstrap](../reference/foundation/selinux-cil-bootstrap.md) before Step 7 reboots into Enforcing. Probe (c) produces the post-upgrade Permissive-phase backlog as one block; the operator reads the `#!!!! This avc is allowed in the current policy` marker on each cluster, which distinguishes "permissive-logging of an already-allowed transition" from "actual denial that Enforcing would refuse" — the latter class is what Step 8 must converge to zero before the host is left in Enforcing. Probe (d) catches the silent confinement loss for any daemon whose stock `file_contexts` entry was written against the pre-merge `/usr/sbin/...` form on a release earlier than `<release-N1>`; the scan loop body, the reverse-equivalency anti-pattern that does not work, and the `semanage fcontext -a -t <type> /usr/bin/<daemon>` mitigation all live in [F44 sbin/bin merge fcontext](../explanation/f44-sbin-bin-merge.md). Any drift surfaced in (a)–(d) is addressed before Step 7's reboot.

7. Reboot once on the upgraded release to exercise the upgraded systemd directives against every Topic role's drop-in on a cold boot path.
   ```bash
   sudo -r sysadm_r -t sysadm_t systemctl reboot
   ```
   Expected outcome: the host completes its boot under the upgraded systemd major version, every previously-applied Topic role's unit reaches `active` (or the role's documented inactive end-state, where the role's Reference declares one), and the post-boot journal contains no `status=226/NAMESPACE` line and no `Failed to set up mount namespacing` line. Step 6's diagnostic wave classifies AVCs against the upgraded SELinux policy; this step is the symmetric check on the systemd side, against the upgraded systemd's directive semantics on a cold boot path. If the boot does not complete, two boot-failure classes account for the great majority of cold-boot regressions on the systemd side after a major upgrade: the [NNP and SELinux transition trap](../explanation/nnp-selinux-transition-trap.md) for an `avc denied { nnp_transition }` journal-line shape (which probe (b) of Step 6 catches before this reboot if the operator runs Step 6 to completion) and the [ReadWritePaths runtime race](../explanation/readwritepaths-runtime-race.md) for the `status=226/NAMESPACE` journal-line shape together with the preceding `Failed to set up mount namespacing: /run/<unit>: No such file or directory` line. If the reboot does not complete, follow [Recover from boot failure](recover-from-boot-failure.md) as the recovery anchor.

8. Switch SELinux back to Enforcing at runtime and persistently, then re-run every Foundation and Topic `verify.sh` in both `staff_t` and `sysadm_t` contexts.
   ```bash
   sudo -r sysadm_r -t sysadm_t setenforce 1
   sudo -r sysadm_r -t sysadm_t sed -i.bak.<TS> 's/^SELINUX=permissive$/SELINUX=enforcing/' /etc/selinux/config
   sudo -r sysadm_r -t sysadm_t restorecon -v /etc/selinux/config
   for r in foundation_umask foundation_sudo_roles foundation_selinux_cil_bootstrap foundation_audit_logging_baseline topic_<topic_role_short>; do
     bash "ansible/roles/${r}/files/verify.sh"
     sudo -r sysadm_r -t sysadm_t bash "ansible/roles/${r}/files/verify.sh"
   done
   ```
   Expected outcome: `getenforce` reports `Enforcing` for the runtime check; `grep ^SELINUX= /etc/selinux/config` reports `SELINUX=enforcing` for the persistent check; the symmetric `sed` edit lands its backup at `/etc/selinux/config.bak.<TS>` and the `restorecon -v` call re-asserts the `selinux_config_t` label after the in-place rewrite. The AVC delta over the 30-second post-switch observation window is `0` for every previously-applied Topic-role domain that the host carries and for the Foundation `staff_t` cluster — if any new AVC appears in this window, drop back to Permissive immediately and follow `## Recovery` path R4. Every Foundation `verify.sh` exits `0` in both contexts and every `SKIP needs sysadm_t` line of the `staff_t` pass reads `OK` under `sysadm_t`; the four-layer verify-loop form is the same loop documented in [Apply the Foundation tier](apply-foundation.md) Step 6. Every Topic-role `verify.sh` exits `0` in both contexts, in the same shape that [Apply one Topic role](apply-topic.md) Step 5 documents for the post-apply re-verify. As the closing operation, the operator re-accepts the integrity baseline with `sudo -r sysadm_r -t sysadm_t /usr/local/sbin/integrity-check accept`, deferred until at least one day after this Step 8 switch or until the next planned reboot, whichever is later — the deferral keeps the post-upgrade drift and the `/etc/selinux/config.bak.<TS>` files from Steps 3 and 8 out of the daily diff that would otherwise dominate the next 24 hours of audit output. Acceptance is a post-review step by design, so the deferral is not merely about noise: it exists so that the operator reads the diff before adopting it as the new reference. See [integrity monitoring](../reference/topics/integrity-monitoring.md).

## Recovery

R1 — Step 3's Permissive switch did not persist across `dnf system-upgrade reboot`. The operator boots the upgraded host, observes `getenforce → Enforcing` instead of the expected `Permissive`, and re-applies the Permissive switch from a `staff_u`-confined login before any other operation: `sudo -r sysadm_r -t sysadm_t setenforce 0` followed by the same `sed` edit form used in Step 3 against the upgraded `/etc/selinux/config`. The `/etc/selinux/config.bak.<TS>` backup file written by the Step 3 `sed -i.bak.<TS>` form is the rollback anchor if the in-place edit is lost during the upgrade — the operator restores it with `sudo -r sysadm_r -t sysadm_t install -m 0644 /etc/selinux/config.bak.<TS> /etc/selinux/config` and re-runs the runtime switch.

R2 — Step 4's `dnf system-upgrade reboot` did not complete and the host failed to boot. The operator falls through to the canonical recovery pointer at the end of this section. The first rescue surface to attempt is the Live-image surface: the previous-release Live image is mismatched to the half-upgraded on-disk state because the offline upgrade has already installed packages from `<release-N1>` against an `<release-N>` kernel, while the upgraded-release Live image will not be obtainable until the upgrade completes successfully on at least one host. The off-host backup from `## Prerequisites` (c) is the rollback anchor when recovery on the upgraded boot path is not feasible — restoring the backup returns the host to its pre-upgrade state without any partial-upgrade residue.

R3 — Step 6's diagnostic wave surfaced a priority-400 module that did not survive the upgrade. The operator re-installs the missing module from the configuration-tier tar snapshot taken in Step 1 via `sudo -r sysadm_r -t sysadm_t semodule -X 400 -i <module>.cil`, sourcing `<module>.cil` from the snapshot's `var/lib/selinux/targeted/active/modules/400/<module>/cil` path. On the upgraded host the on-disk CIL is bzip2-compressed, so the operator passes the file through `bzcat` (`bzcat <module>/cil > /tmp/<module>.cil` followed by `semodule -X 400 -i /tmp/<module>.cil`) before feeding it to the loader if the snapshot path is already decompressed.

R4 — Step 8's Enforcing-switch produced an AVC storm in the 30-second observation window. The operator falls back to Permissive immediately with `sudo -r sysadm_r -t sysadm_t setenforce 0`, classifies the AVC backlog with `sudo -r sysadm_r -t sysadm_t ausearch -m avc -ts <step-8-switch-time> | sudo -r sysadm_r -t sysadm_t audit2allow -m post_enforcing`, extends the relevant priority-400 CIL module per the Foundation tier's CIL-bootstrap publish-path mechanism, and re-attempts Step 8 once the new policy is in place. The `<step-8-switch-time>` argument to `ausearch` is critical: the full-history `ausearch -m avc -ts boot` form mixes Permissive-phase log-only records from Step 5 with Enforcing-phase denials from the brief window in Step 8, and obscures the post-switch delta that the classification needs to converge to zero.

If the host fails to boot after applying changes, follow [Recover from boot failure](recover-from-boot-failure.md).
