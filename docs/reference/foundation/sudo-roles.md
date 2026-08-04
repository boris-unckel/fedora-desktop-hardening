<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# staff_u and sudo role transitions

## Role in the hardening model

This Foundation layer maps the operator's interactive Linux account to the SELinux user `staff_u`, leaving every other login (system services, `root`, the `__default__` fallback) on the distribution's `unconfined_u`. The mapping confines the operator's daily session to `staff_t`, makes the role boundary between routine work and policy-store administration explicit (`staff_r` versus `sysadm_r`), and forces a deliberate role switch for every command that reads or writes SELinux state, the persistent audit log, or kernel modules. It also surfaces a residual capability gap (`staff_sudo_t` lacks `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`) and a custom-allow surface for daily-desktop interactions that stock targeted policy does not grant to `staff_u`.

This Foundation layer is a prerequisite for: every Topic role that uses `semanage`/`semodule`/`restorecon`/`audit2allow` against the live system, every Topic role that ships a custom SELinux module, and every operator-facing How-to that documents on-host inspection (the role-switch syntax is required to reproduce the documented commands). It depends on Layer 0 (UMASK 0027) for the file-mode discipline that turns the missing DAC capabilities into a recurring trap.

## End-state configuration

The first three subsections describe stock SELinux targeted policy in conjunction with operator-side `semanage` and sudoers configuration; no custom policy module is involved. The fourth subsection describes a custom CIL module that fills daily-desktop allow-gaps for `staff_u`. The CIL module is loaded through the policy-extension mechanism documented in a separate Foundation layer (the CIL bootstrap discipline — `semodule -X` priority conventions, install ordering, and module-store backup — is kept out of scope here so this layer remains focused on the role and sudoers surface).

### Per-user mapping

The operator's POSIX account is mapped to the SELinux user `staff_u`:

```text
semanage login -m -s staff_u -r 's0-s0:c0.c1023' <user>
```

The system-managed pseudo-account `__default__` and the `root` account remain on `unconfined_u`. Confining only the operator account preserves the distribution-default behavior for everything else: package post-install scripts, `dracut`, `systemd` user managers spawned for system services, and the rescue path through `root` keep their unconfined surface. After the mapping is set, `semanage login --list` reports:

```text
Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
<user>               staff_u              s0-s0:c0.c1023       *
root                 unconfined_u         s0-s0:c0.c1023       *
```

`semanage login -m` updates `/etc/selinux/targeted/seusers` and the policy-store mapping. The change does not affect any session that is currently open. `pam_selinux` reads the mapping at session establishment, so the next login through GDM, `sshd`, or a console becomes the first session to run as `staff_u`. A fresh `id -Z` after re-login reports:

```text
staff_u:staff_r:staff_t:s0-s0:c0.c1023
```

The mapping does not introduce boot-failure risk on its own. The boot path runs as `system_u`/`init_t` and never consults the user mapping; the mapping activates only when an interactive login is established. Reverting the mapping is `semanage login -m -s unconfined_u <user>` followed by a re-login. As a coarser emergency brake, `setenforce 0` switches the kernel to permissive mode (denials are logged but not enforced) and `setenforce 1` re-enables enforcement; both are reversible without reboot.

### Role transitions and the plain-sudo domain

Stock SELinux targeted policy lets `staff_u` enter two roles: `staff_r` (default, type `staff_t`) and `sysadm_r` (administrative escalation, type `sysadm_t`). The pair is policy-built; no custom CIL is required to make the transition available.

Per-command escalation to `sysadm_t` uses the canonical form:

```bash
sudo -r sysadm_r -t sysadm_t <cmd>
```

The transition lasts for the duration of `<cmd>` only. The next plain `sudo` invocation lands back in `staff_sudo_t` because `sudo` invoked without `-r` from a `staff_u` shell does **not** transition to `sysadm_t`. `staff_sudo_t` is intentionally SELinux-blind: stock policy denies it write/open on `semanage_store_t`, `auditd_log_t`, `auditd_etc_t`, several `*_exec_t` types (notably `udev_exec_t` and `systemd_*_exec_t`), and creating new files in non-systemd `/etc/**` subtrees (`/etc/sysctl.d/`, `/etc/modprobe.d/`, `/etc/logrotate.d/`).

The following commands and command classes mandate the role switch on a `staff_u`-confined host. The list is the operational surface — running any of them under plain `sudo` produces an AVC whose source context is `staff_t` or `staff_sudo_t`:

- `semodule`, `semanage`, and `restorecon` when the target file would change to a domain-typed context.
- `ausearch`, `audit2allow`, `audit2why`, `auditctl -l`/`-s`.
- `journalctl` against the persistent system journal (the rotated archive lives under `auditd_log_t` in the Audit-and-logging Foundation).
- `systemd-analyze verify`.
- `udevadm` (for trigger and control operations, not the read-only `info` form).
- `mandb --create`.
- `sysctl --system` and writes to namespaced sysctl keys such as `kernel.unprivileged_bpf_disabled`, `net.core.bpf_jit_harden`, `fs.protected_*`.
- `lynis audit system`.
- `flatpak` write subcommands (`install`, `update`, `uninstall`, `remote-add`, `remote-modify`).
- `install`, `tee`, `cp` into non-systemd `/etc/**` subtrees.

Rule of thumb: an AVC with `scontext=staff_u:staff_r:staff_t` or `scontext=staff_u:staff_r:staff_sudo_t` is an operator who forgot the role switch, not an application bug.

`staff_sudo_t` lacks `CAP_DAC_OVERRIDE` (capability 1) and `CAP_DAC_READ_SEARCH` (capability 2). Combined with the Layer 0 UMASK of `0027`, files written by the operator with mode `0640 user:user` (typical: a heredoc into `/tmp/`) are unreadable from plain `sudo` despite UID=0, because plain `sudo` runs in `staff_sudo_t` and the missing DAC overrides are not borrowed back from the running UID. The detection signal is an AVC pair on `denied { dac_read_search }` and `denied { dac_override }` for `comm="install"` (or `cat`, `cp`) with `scontext=staff_u:staff_r:staff_t`. The mitigations, in preferred order:

1. Write the destination file directly as root with no `/tmp` detour: `sudo tee <path>` from a heredoc, or `sudo install -m 0644 /dev/stdin <path>` from a heredoc.
2. `chmod 0644 <source>` before `sudo`.
3. Escalate to `sudo -r sysadm_r -t sysadm_t install -m 0600 …` when the file must remain restrictive at rest.

The daemon-side counterpart of the same UMASK 0027 inheritance — files left at mode `0640 root:root` that a non-root daemon cannot open — is documented in [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md). The cross-link is one-way: that pattern article covers the daemon-side symptom, this Reference covers the operator-side DAC-cap trap.

A second symptom of the missing role switch is silent label drift on newly created files in `/etc/**`. `sudo install`/`tee`/`cp` from `staff_sudo_t` cannot relabel the destination to a service-domain context — the file lands as `staff_u:object_r:<generic>_t:s0` (for example `systemd_unit_file_t` for any unit drop-in, instead of `auditd_unit_file_t` or `cupsd_unit_file_t`). The robust write pattern is `sudo -r sysadm_r -t sysadm_t install …` directly: the destination receives the correct domain context at creation time and no post-write `restorecon` is needed. The compatible alternative is `sudo install …` followed by `sudo -r sysadm_r -t sysadm_t restorecon -RFv <path>` to relabel after the fact. Topic roles in this tree pick the direct form so they do not depend on a subsequent `restorecon` step.

### Sudoers configuration

`/etc/sudoers` is the package default, mode `0440 root:root`. The only end-state edit is a `secure_path` cleanup that removes any residue from third-party package paths (notably `/var/lib/snapd/snap/bin`, which the package sometimes appends and which becomes stale once the package is removed). The relevant directives in `/etc/sudoers`:

```text
Defaults    !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    always_query_group_plugin

Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults    env_keep += "MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"

Defaults    secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

root    ALL=(ALL)     ALL
%wheel    ALL=(ALL)    ALL

#includedir /etc/sudoers.d
```

`%wheel` carries no `NOPASSWD`. The operator's password is required for every escalation that does not match a more specific drop-in. `#includedir /etc/sudoers.d` is the only drop-in include that is active; no global `Defaults logfile=` directive is set in `/etc/sudoers`, so the package-default audit path through `auth.log` and `journalctl _COMM=sudo` is in effect for every escalation that does not name a more specific drop-in.

Drop-ins under `/etc/sudoers.d/` may activate per-command sudo I/O logging via `Defaults!<absolute-path> logfile=/var/log/<wrapper>.log`. When a drop-in routes audit output to a custom path, the path **must** carry the SELinux type `sudo_log_t`. The default `var_log_t` is insufficient: stock policy grants the `sudodomain` attribute only `{ append getattr ioctl lock }` on `var_log_t`, with no `open`-write and no `create`. The symptom of the mismatch is silent — `sudo` emits a single `unable to open log file …: Permission denied` line on stderr, the command itself completes (PAM authentication and `execve` are independent of the audit-log open), and the audit trail is dead while the operator believes it is live. The mitigation is idempotent:

```bash
sudo -r sysadm_r -t sysadm_t semanage fcontext -a -t sudo_log_t '/var/log/<wrapper>\.log'
sudo -r sysadm_r -t sysadm_t restorecon -Fv /var/log/<wrapper>.log
```

The `iolog_dir=` directive (sudo I/O log directory) follows the same labeling rule for its target directory pattern. Both directives are out of scope for `/etc/sudoers` itself in this end-state — they apply only when an operator places a drop-in under `/etc/sudoers.d/`. The full mechanism, including the relabel-before-first-write ordering note and the symmetric `iolog_dir=` rule, is described in [Sudo custom logfile and SELinux labeling](../../explanation/sudo-logfile-seclabel.md).

### Custom CIL allow-spec for daily-desktop confinement gaps

The end-state ships one custom CIL module at priority 400. The module fills allow-gaps that stock targeted policy does not grant to `staff_u` for daily-desktop interactions (audio stack, font and codec discovery, emoji picker, terminal emulator, Wine subprocesses). The module is installed at:

```text
/usr/local/share/selinux/staff_extras.cil
```

Three clusters in the module are part of the operator-confinement surface and are documented here. A fourth cluster in the same physical file describes Flatpak/`bwrap` sandbox-construction allow rules and has no relationship to the `staff_u` mapping or the role-transition surface; that cluster is documented in a separate User-Applications topic (slug: `flatpak-bwrap-sandbox`). The Ansible role of this Foundation installs the entire file, including the fourth cluster, because the module is one CIL unit at the policy-store level — splitting it would require two priority-400 modules with overlapping `allow` rules and gain nothing operationally.

Cluster 1 — udmabuf (`/dev/udmabuf`). Required by Pipewire and `wireplumber` for audio buffer transport, by the GStreamer plugin scan that runs at first launch of every media-capable application, by the GNOME Character Map, by the Ptyxis terminal emulator, and by Wine subprocesses for shared-buffer interop:

```cil
(allow staff_t dma_device_t (chr_file (read write open getattr ioctl)))
(allow staff_wine_t dma_device_t (chr_file (read write open getattr ioctl)))
```

Cluster 2 — userfaultfd anon-inode. Required by Wine memory-fault handling. The first allow line covers create/read/write on the anon-inode; the follow-up line covers the `UFFDIO_API` ioctl handshake, which Wine performs separately after the inode is established:

```cil
(allow staff_wine_t userfaultfd_t (anon_inode (create read write)))
(allow staff_wine_t userfaultfd_t (anon_inode (ioctl)))
```

Cluster 3 — Wine devices. The joystick character device (`/dev/input/js0`, type `mouse_device_t`) is opened by Wine even when no joystick is attached, because the Win32 input enumeration probes the path unconditionally. The session DBus socket (`/run/user/<uid>/bus`, type `session_dbusd_tmp_t`) is opened by Wine for desktop-integration calls (theming, tray icons, file-chooser portals):

```cil
(allow staff_wine_t mouse_device_t (chr_file (read write open getattr ioctl)))
(allow staff_wine_t session_dbusd_tmp_t (sock_file (write open getattr)))
```

The CIL bootstrap mechanism — install discipline (`semodule -X 400 -i`), priority conventions, the role-switch requirement for `semodule` itself, module-store backup ordering — is documented in a separate Foundation layer: [SELinux custom CIL bootstrap](./selinux-cil-bootstrap.md). This Reference covers the module's content and its rationale; the loader is one layer down in the dependency graph.

## Verification

Probe:

```bash
bash ansible/roles/foundation_sudo_roles/files/probe.sh
```

Verify:

```bash
bash ansible/roles/foundation_sudo_roles/files/verify.sh
```

The verify script exits `0` on a clean host, `1` on drift, `2` on invocation error. It reports four classes of check: the per-user mapping in `seusers`, the SELinux user/role presence (`seinfo`), the policy module (`semodule -lfull` for `staff_extras` at priority 400), and the live-shell context (`id -Z`). The live-shell check only proves the post-login path when the verify script is run from a freshly opened login shell — running it from an inherited environment (a `sudo` chain, a `make` recipe, or a desktop-launcher session) reports the inherited context, not the value that a fresh login would establish. The script falls back gracefully when a check needs `sysadm_t` (for example, `semodule -lfull`) and the current shell is not in that domain: the failed read is reported as `(skipped: needs sysadm_t)` rather than as drift.

Expected verify output on a correctly applied host, with the script run as `staff_t` from a fresh login shell — checks that need `sysadm_t` are reported as `SKIP` until the operator re-runs from `sudo -r sysadm_r -t sysadm_t bash …`:

```text
OK   semanage_login_mapping        <user>:staff_u:s0-s0:c0.c1023:*
OK   seinfo_user_staff_u           present
OK   seinfo_role_sysadm_r          present
SKIP semodule_staff_extras_p400    needs sysadm_t
OK   id_z_current_shell            staff_u:staff_r:staff_t:s0-s0:c0.c1023
OK   sudoers_secure_path           /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OK   sudoers_no_global_logfile     none
OK   sudoers_d_drop_ins            (no custom logfile drop-ins detected)
```

On the same host re-run as `sudo -r sysadm_r -t sysadm_t bash files/verify.sh`, the `SKIP` line becomes:

```text
OK   semodule_staff_extras_p400    400 staff_extras cil
```

## Related patterns

- [Sudo custom logfile and SELinux labeling](../../explanation/sudo-logfile-seclabel.md) — Why a custom `Defaults!<cmd> logfile=` path silently drops audit data unless the path carries `sudo_log_t`, and the symmetric rule for `iolog_dir=`.
- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — The Layer 0 origin of the `0640` file-mode default that, combined with the missing `staff_sudo_t` DAC overrides, produces the operator-side DAC-cap trap.
