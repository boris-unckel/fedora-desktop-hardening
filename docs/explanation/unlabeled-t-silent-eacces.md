<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# The unlabeled_t silent EACCES trap

## The trap

A user shell running in a less-privileged confined domain — a `staff_t` login under the targeted policy with a `staff_u` user mapping is the typical example — accesses an externally-attached filesystem mounted with the `seclabel` mount option, where the files on disk carry SELinux xattrs from a source system whose label vocabulary the active targeted policy does not recognize. The top-level listing of the mount point succeeds, but `ls`, `cat`, or `cp` against any sub-directory fails with `EACCES`. The DAC mode and ownership on the failing path appear permissive, the file is owned by an account the operator can read elsewhere on the system, and there is no obvious DAC-side explanation for the refusal.

The visible symptom is silent at the audit boundary. `ausearch -m avc -ts recent` returns no record for the failing path, `journalctl -k` reports no `audit: type=1400` lines for it, and the operator's first hypothesis — a DAC-mode mismatch — is falsified the moment the mount-point root listing succeeds against the same ownership and mode pattern. The trap is the contradiction between an `EACCES` at the shell layer and an empty audit channel: the kernel refused the access, but the policy that refused it has chosen not to advertise the refusal.

## Why it happens

Under the stock targeted policy, the source domain `staff_t` carries only `{ getattr watch }` against `unlabeled_t:dir` (granted via the `login_userdomain` attribute) and `getattr` (granted via the `non_security_file_type` attribute), with no allow rule for `read`, `open`, or `search`. The kernel-side mount root — the directory at which the external filesystem is attached — typically carries an `mnt_t`-class label on which `staff_t` does have `read`, `open`, and `search`, so the top-level listing of the mount point succeeds. The sub-tree directories carry the on-disk `unlabeled_t` entries against which `staff_t` has no traversal permission, so directory traversal halts at depth one and presents itself as a per-sub-directory `EACCES`.

The `seclabel` mount option — the default for ext4, btrfs, and xfs under an active SELinux policy — makes the on-disk xattr `security.selinux` the authoritative label source for every file on the filesystem; there is no fallback default-context override and no policy-side relabeling at mount time. When the on-disk label names a type that the running policy does not define, the kernel surfaces the file's effective type as `unlabeled_t` — not as a generic fallback, but as the explicit "unknown type" sentinel. The xattr lands on user data through several drift sources: a filesystem labeled on a system that did not run the active targeted policy (a different distribution, an older policy version, a system without targeted SELinux at all); a copy made with xattr-preserving flags such as `rsync --xattrs`, `tar --selinux`, or `cp -a` from a source system whose policy defines types the destination policy does not; a filesystem written before the local host migrated to a stricter user mapping, so that the source domain that wrote the files is not the source domain that now reads them.

The denial that fires when `staff_t` attempts to search or read a directory of type `unlabeled_t` is suppressed by a `dontaudit` rule covering `staff_usertype × non_security_file_type:dir { ioctl lock open read search }`, so `ausearch -m avc` returns no record for the failing path. The suppression is a deliberate policy choice: the stock policy treats user-domain probes against unknown-type directories as expected noise rather than security-relevant events, and the audit channel is silenced accordingly. The same trap surfaces for any tool that runs in the caller's confined domain — the shell's own `cp`, `cat`, `ls`, and any user-installed archive or backup utility invoked from the user shell; tools that ship with their own targeted SELinux domain may carry stock allows on `unlabeled_t:dir read` and not share the trap, because their permission evaluation runs against a different source domain.

## How to detect it

Four observable signals identify the trap class unambiguously when taken together: `ls -ldZ <path>` reveals the failing path's effective type as `unlabeled_t`; `findmnt <mountpoint>` confirms the `seclabel` mount option is in force; `ausearch -m avc -ts recent` returns no record for the failing path; and from a role-transitioned `sysadm_t` shell, `sesearch --allow -s staff_t -t unlabeled_t -c dir` shows only `{ getattr watch }`, while `sesearch --dontaudit -s staff_t -t unlabeled_t` shows the suppressing rule that explains the empty audit output.

```text
$ ls -laZ /run/media/<user>/<drive>/<subdir>/
ls: cannot open directory '/run/media/<user>/<drive>/<subdir>/': Permission denied

$ ls -ldZ /run/media/<user>/<drive>/<subdir>/
drwxr-xr-x. 1 <user> <user> unconfined_u:object_r:unlabeled_t:s0 /run/media/<user>/<drive>/<subdir>/

$ findmnt /run/media/<user>/<drive>
TARGET                       SOURCE     FSTYPE OPTIONS
/run/media/<user>/<drive>    /dev/<dev> ext4   rw,nosuid,nodev,relatime,seclabel,...

$ ausearch -m avc -ts recent
<no matches>

$ sudo -r sysadm_r -t sysadm_t sesearch --allow -s staff_t -t unlabeled_t -c dir
allow staff_t unlabeled_t:dir { getattr watch };

$ sudo -r sysadm_r -t sysadm_t sesearch --dontaudit -s staff_t -t unlabeled_t
dontaudit staff_usertype non_security_file_type:dir { ioctl lock open read search };
```

## How to mitigate it

The mitigation that does not require any policy change is a role transition to a domain with `files_unconfined_type` semantics — for example, `sudo -r sysadm_r -t sysadm_t ls -laZ /run/media/<user>/<drive>/<subdir>/` — because that target domain carries broad file-class permissions on every `file_type`, including `unlabeled_t`. The transition does not relabel, remount, or otherwise mutate the on-disk state; it changes only the source domain of the read, which is the side of the access check that the carve-out narrows. The role transition closes the trap on a per-invocation basis without widening any policy boundary that applies to the source domain in its other use cases.

`unlabeled_t` is drift, not protection: the same files are readable through plain DAC on any system where the active targeted policy does not fire (a live-image boot, a different host with a different user mapping, a recovery shell), so the trap class must not be re-framed as a hardening property. The on-disk xattr is the same regardless of which policy is active, but the access restriction it produces depends entirely on the policy posture of the host doing the read. A drive removed from the hardened host and reattached elsewhere yields its contents to plain DAC; the access restriction has no off-host meaning.

Three workarounds suggest themselves and are wrong, each for a structural reason. A custom CIL `allow staff_t unlabeled_t:dir { read open search }` widens the source domain against every `unlabeled_t` resource on the host, not only the resource on the externally-attached filesystem, and the widening is permanent rather than scoped to the affected mount. A recursive `restorecon` or `chcon -R` over the affected sub-tree overwrites the on-disk xattr irreversibly, with no backup-side plan for the original labels and no certainty about which target type would be correct for files that arrived from a foreign policy vocabulary. A remount with `-o context=…` holds only for the current mount lifetime; the next hot-plug, auto-mount, or removal-and-reattachment cycle resets the context override and the trap returns.

Edge cases the mitigation does not cover:

- A drive that is detached from the hardened host and re-attached to a system without the active targeted policy (a live-image boot, a different distribution, a recovery shell, an external host with a different user mapping): the `unlabeled_t` xattr is still on disk, but the running policy on that other system does not consume the carve-out, and the files are readable through plain DAC. The mitigation does not protect against off-host access; the protection-classification rule (B4) is the operator-facing form of this fact.
- A sub-tree that mixes `unlabeled_t` entries with package-defined or otherwise-known types: the trap halts traversal at the first `unlabeled_t` directory, and the operator sees a partial listing that includes the package-typed entries and stops at the unknown ones. The replacement (role transition) restores full traversal, but a recursive operation invoked before the role transition produces partial output that does not match the on-disk state and must not be trusted as a backup or audit baseline.
- A recursive `cp`, `tar`, or archive operation invoked from a `staff_t` shell across a mixed sub-tree: the operation succeeds on the package-typed branches and fails silently on the `unlabeled_t` branches, and the operator's exit-code-only check at the end of the run reports success for the wrapper while files are missing from the destination. The mitigation is to perform the operation from `sysadm_t` for the read side; the destination-side label question is a separate concern that this Pattern does not resolve.
- The backup write-side: a backup tool that runs in the caller's confined domain and writes files with xattr-preserving flags carries the same read-side restriction on the next backup pass, because re-reading what was just written reproduces the trap. A backup tool that runs in its own targeted domain with stock allows on `unlabeled_t:dir read` does not have the read-side restriction. The Pattern does not prescribe a backup-tool choice; it only states that the read-side permission semantics persist across write-and-re-read.

## See also

- [The kill-0 cross-user EPERM trap](./kill-0-cross-user-eperm.md) — A verify-shell that probes a foreign-uid daemon with `kill(2)`-and-signal-zero and a user-shell that reads a directory typed `unlabeled_t` are the same trap shape at different layers of the kernel's access-control stack: in both, a permission boundary closes silently from the operator's point of view (collapsed exit code in one, suppressed audit record in the other), and in both the canonical mitigation is a role transition to a domain with broader permissions on the affected resource class.
- [UMASK and daemon readability](./umask-and-daemon-readability.md) — Both Patterns are silent-`EACCES` traps that arise from a permission boundary the operator did not see at the moment of writing — a DAC file-mode boundary in `umask-and-daemon-readability` (a `0640` configuration file unreadable by the daemon's uid) and a MAC label-vocabulary boundary in this Pattern (an `unlabeled_t` directory entry unreadable by the user shell's domain) — and in both the error channel does not report what blocked the access.
