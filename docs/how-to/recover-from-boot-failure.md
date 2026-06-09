<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Recover from boot failure

## Goal

At the end of this procedure, the target host has been restored to a bootable state, the one hardening change that prevented boot has been identified and reverted, the operator has re-established a `staff_u`-confined interactive login under the remaining hardening posture and re-verified that posture, and the rolled-back change has been captured so the operator can decide whether to re-attempt it with the appropriate Pattern mitigation in place or to drop it.

## Prerequisites

- The Foundation tier was in force when boot broke. The procedure restores boot under the existing hardening posture, not by reverting all hardening. The Foundation-tier layer set and the apply gate that brought the host into this posture are documented in [Apply the Foundation tier](apply-foundation.md); this how-to does not re-derive them.
- A Fedora 44 or later Live image is available on physical media (USB stick or DVD) that the operator can attach to the target. The new tree's baseline is Fedora 44, and any rescue path that requires a chroot uses a Live image of the same major release as the host to keep the SELinux policy-store binary format compatible.
- Physical or remote-console access to the target is available, so the operator can interrupt the GRUB countdown, edit the kernel command line, or boot from removable media. Recovery cannot be performed from a network login, because every recovery surface requires pre-systemd kernel access.
- The LUKS passphrase is on hand if the host's root filesystem is LUKS-encrypted. The rescue procedure unlocks the root device through `cryptsetup luksOpen` from the Live image, and a missing passphrase blocks the chroot path in Step 2.
- The operator has a working hypothesis of which change triggered the failure — typically the most recent Foundation-role or Topic-role apply, identifiable from the operator's command history or the host's package-manager log. The hypothesis is not a hard prerequisite (Step 3 confirms it from the failed-boot journal), but it shortens the recovery loop materially.
- A second, password-protected login channel is reachable on the *control node* (not the target), so the operator can read the role tree's `tasks/main.yml`, `README.md`, and probe scripts during recovery. The recovery procedure references the role tree to locate the file path of the drop-in or CIL module to revert, and the control node's checkout is the canonical reference.

## Steps

1. Choose a rescue surface — either the rescue-target surface reached through the GRUB kernel-command-line editor, or the Live-image surface reached by booting the Fedora 44 or later Live medium.
   ```bash
   systemd.unit=rescue.target
   ```
   Expected outcome: on the rescue-target surface, the operator interrupts the GRUB countdown, presses `e` to edit the default boot entry, appends the fragment above to the kernel command line on the `linux` line, presses the GRUB-documented key combination to boot the edited entry, and reaches a root shell prompt of the form `sh-X.Y# ` on `tty1`. On the Live-image surface, the operator attaches the Fedora 44 or later Live medium, boots from it through the firmware's boot menu, and reaches the Live environment's shell at a prompt of the form `liveuser@...$ `. Decision criterion: the rescue-target surface is preferred when the failure cascades from a single failed unit and PID 1 can still reach `rescue.target` (the kernel and initramfs are intact); the Live-image surface is required when PID 1 itself cannot reach a usable target — most commonly when an SELinux policy load at boot prevents the policy store from loading, or when the rescue-target surface refuses to grant a root shell.

2. Establish a usable shell with write access to the host's root filesystem on the chosen rescue surface.
   ```bash
   cryptsetup luksOpen /dev/<root_dev> <luks_name>
   mount /dev/mapper/<luks_name> /mnt/sysimage
   mount /dev/<boot_dev> /mnt/sysimage/boot
   mount /dev/<efi_dev> /mnt/sysimage/boot/efi
   mount --bind /proc /mnt/sysimage/proc
   mount --bind /sys  /mnt/sysimage/sys
   mount --bind /dev  /mnt/sysimage/dev
   mount --bind /dev/pts /mnt/sysimage/dev/pts
   mount --bind /run  /mnt/sysimage/run
   chroot /mnt/sysimage /bin/bash
   ```
   Expected outcome: on the rescue-target surface, the host's root filesystem is already mounted because `rescue.target` runs after the local-fs target completes; the operator runs `mount -o remount,rw /sysroot` only if the root mount is read-only, and works directly under `/sysroot` for the remaining steps without any chroot. On the Live-image surface, the commands above unlock the LUKS root device (omit the `cryptsetup` line if the root filesystem is unencrypted, and substitute the LV path or partition path on `/dev/<root_dev>` accordingly), mount the host root under `/mnt/sysimage`, mount the boot and ESP partitions, bind-mount the kernel-vocabulary pseudo-filesystems, and enter the host's filesystem context. The chroot inherits the host's `PATH`, but `id -Z` from inside the chroot reports `kernel` or an unconfined Live-image label rather than `staff_u:staff_r:staff_t:s0-s0:c0.c1023`, because the chroot's SELinux context is the Live-image kernel's view of the chroot'd process — the operator does not rely on the `staff_u` mapping inside the chroot and runs the SELinux loader with the `-N` no-reload flag in Step 4.

3. Identify the offending change by reading the failed-boot journal and correlating it against the most recent apply.
   ```bash
   journalctl --boot=-1 --no-pager
   ```
   Expected outcome: on the rescue-target surface PID 1's journal is reachable directly with the form above; on the Live-image chroot surface the same content is reachable as `journalctl --directory=/var/log/journal --no-pager --since=-2hours`, which reads the host's persistent journal under `/var/log/journal/` (the Layer 3 Foundation role sets `Storage=persistent`, so the failed-boot journal survives into the recovery surface). The operator looks for one of three failure shapes and matches it to the rollback selection in Step 4. The first shape is an AVC line containing the phrase `avc:  denied  { nnp_transition }` against an `init_t → <svc>_t` transition; this is the [NNP and SELinux transition trap](../explanation/nnp-selinux-transition-trap.md), and the mechanism, the pre-deploy check that catches it, and the CIL extension that mitigates it live in that Explanation. The second shape is a `status=226/NAMESPACE` line preceded by a `Failed to set up mount namespacing: /run/<unit>: No such file or directory` line; this is the [ReadWritePaths runtime race](../explanation/readwritepaths-runtime-race.md), and the same Explanation documents the `-`-prefix mitigation and the restart-verify-lies invariant. Any other shape — a kernel oops, a missing module, a typo in `/etc/fstab` — is out of scope for this how-to, and the operator escalates to the meta-recovery paths under `## Recovery` below.

4. Apply the targeted rollback under the SELinux role-switch reflex; pick exactly one of the three forms below according to which symptom shape Step 3 identified.
   ```bash
   # (a) systemd drop-in rollback — for the ReadWritePaths runtime race shape
   #     or any other drop-in that the operator deployed since the last good boot:
   rm /etc/systemd/system/<unit>.d/99-*.conf

   # (b) SELinux custom CIL module rollback — for a misbehaving priority-400
   #     module that the operator installed since the last good boot:
   semodule -N -X 400 -r <module_name>

   # (c) SELinux emergency brake — when no single drop-in or CIL module is
   #     identifiable: append the fragment below to the kernel command line
   #     on the *next* boot through the same GRUB edit form as Step 1, which
   #     boots the host in permissive mode without unloading any policy:
   enforcing=0
   ```
   Expected outcome: form (a) exits `0` when the offending drop-in file is removed and is the right form when Step 3 identified the `status=226/NAMESPACE` shape (the drop-in carries a `ReadWritePaths=` entry without the `-`-prefix the Pattern Explanation documents). Form (b) exits `0` when the offending priority-400 module is removed from the policy store; the `-N` flag suppresses the post-removal policy rebuild and is required inside the Live-image chroot because the chroot's kernel cannot reload the host's running policy, and is used on the rescue-target surface as well because PID 1 has not loaded a userspace-policy-reload listener at `rescue.target`. Form (c) leaves the policy store untouched and boots the host in permissive mode on the next boot; once the host is interactively reachable, the operator runs `sudo -r sysadm_r -t sysadm_t setenforce 1` after addressing the underlying issue, which re-enables enforcement without a reboot. The rollback choice is exclusive: running two forms simultaneously masks which one actually unblocked the boot and complicates the post-recovery analysis.

5. Reboot the target and re-establish a `staff_u`-confined interactive login.
   ```bash
   # rescue-target surface:
   systemctl reboot

   # Live-image chroot surface (compound command — exit the chroot, unmount
   # the target tree under /mnt/sysimage recursively, then reboot the Live env):
   exit; umount -R /mnt/sysimage; reboot
   ```
   Expected outcome: the host completes its boot, reaches the GDM login (or the console login if no display manager is configured), and the operator's interactive login succeeds with `id -Z` reporting `staff_u:staff_r:staff_t:s0-s0:c0.c1023`. If the new login refuses to establish — typically because the rollback in Step 4 reverted only the boot-blocking change and a separate post-login issue remains — the operator authenticates from the second login channel named in `## Prerequisites` and re-enters the procedure at Step 3 against the journal of the post-rollback boot.

6. Re-verify the host's remaining hardening posture and record the rolled-back change for follow-up.
   ```bash
   for r in foundation_umask foundation_sudo_roles foundation_selinux_cil_bootstrap foundation_audit_logging_baseline; do
     bash "ansible/roles/${r}/files/verify.sh"
     sudo -r sysadm_r -t sysadm_t bash "ansible/roles/${r}/files/verify.sh"
   done
   ```
   Expected outcome: every Foundation `verify.sh` exits `0` in both contexts, every `SKIP needs sysadm_t` line of the `staff_t` pass reads `OK …` in the `sysadm_t` pass, and the four-layer verify-loop form matches the post-apply re-verify pattern documented in [Apply the Foundation tier](apply-foundation.md) Step 6. The operator then re-runs each previously-applied Topic role's `verify.sh` in both contexts per [Apply one Topic role](apply-topic.md) Step 5; every Topic `verify.sh` also exits `0`. The operator records the rolled-back change — the file path of the removed drop-in, the name of the removed CIL module, or the `enforcing=0` cmdline-brake decision — to a file outside the repository checkout, alongside the symptom-shape phrase from Step 3 that identified the failure class. The record is the input for the operator's next decision: re-attempt the change with the Pattern Explanation's mitigation in place, or drop the change permanently.

## Recovery

R1 — The rescue-target surface refused to come up. Re-attempt Step 1 with the Live-image surface instead. The Live image provides a kernel and a shell that are independent of the host's installed kernel and initramfs, and therefore covers failure shapes that take down PID 1 itself, including a corrupt host initramfs or an SELinux policy load that aborts boot before any userspace target is reachable.

R2 — The Live-image chroot's `semodule` reports a policy-store-format mismatch when Step 4's form (b) is attempted. This surfaces when the Live image is a different Fedora major release than the host; the `## Prerequisites` (b) item requires the same major release for exactly this reason. Obtain a Live image of the host's major release and re-attempt Step 4, or fall back to Step 4's form (c) — the `enforcing=0` kernel-cmdline brake is policy-store-version-independent because it does not load the policy at all, and it lets the host reach an interactive state from which the operator can address the underlying issue under permissive mode and then re-enable enforcement.

R3 — Step 4's rollback succeeded and Step 5's reboot completed, but the boot is still failing on a different change. Re-enter the procedure at Step 1 and treat the second failure as an independent rollback target. Compound failures across multiple hardening changes are recovered one change at a time, and the journal of the post-rollback boot now reflects the next failure shape rather than the original one; Step 3's journal read against this new boot identifies the next class.
