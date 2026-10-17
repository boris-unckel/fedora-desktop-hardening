<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# UMASK 0027

## Role in the hardening model

UMASK 0027 is Layer 0 of the Foundation tier. It establishes a system-wide default file-creation mask that produces files with mode `0640` (`-rw-r-----`) and directories with mode `0750` (`drwxr-x---`) for every interactive login session. Removing the "other" permission bits prevents files created by an operator's login session — including root-owned configuration files written under `/etc/**` — from being world-readable by default.

This Foundation layer is a prerequisite for every other Foundation layer and every Topic role. Topic roles assume `0640`/`0750` semantics on operator-authored files and apply the daemon-readability discipline that follows from them.

## End-state configuration

The end-state spans two independent layers and one countermeasure. The login-side default applies to interactive sessions through PAM. The per-unit override applies to systemd-managed services and is set in topic-specific drop-ins. The two are orthogonal: neither implies the other, and changing one does not weaken the other. The countermeasure keeps the package manager's own state files readable, the one collateral of the login-side mask that no write pattern can fix.

### Login-side UMASK

The source of truth is `/etc/login.defs`:

```ini
UMASK           027
HOME_MODE       0700
USERGROUPS_ENAB yes
```

`UMASK 027` is the value `pam_umask` reads at session start. `HOME_MODE 0700` is consulted by `useradd` and `newusers` when a new home directory is created and overrides `UMASK` for that single use case. `USERGROUPS_ENAB yes` governs whether `useradd`/`usermod` create a private per-user group; it is documented here only because operators sometimes assume it transforms `027` into `007` at login. It does not — the Fedora `pam_umask` invocation in `/etc/pam.d/postlogin` does not pass the `usergroups` module argument, so the login-time umask path is unaffected by this directive.

The PAM hook is in `/etc/pam.d/postlogin`:

```text
session     optional                   pam_umask.so silent
```

`postlogin` is included into the login, sshd, and console PAM stacks via `@include`, so every interactive session inherits the value from `login.defs`.

No system-wide shell-init file overrides `pam_umask`:

- `/etc/profile` contains no `umask` line.
- No file under `/etc/profile.d/*.sh` sets a `umask`.
- `/etc/bashrc` retains the package-default defensive fallback line, exactly:

  ```bash
  # Set default umask for non-login shell only if it is set to 0
  [ `umask` -eq 0 ] && umask 022
  ```

  The fallback fires only when the inherited umask is `0`. Under `pam_umask`, the inherited value is `0027`, so the line is a confirmed no-op and is intentionally left untouched by this Foundation.

The default file mode produced under UMASK 027 is `0640` for files and `0750` for directories.

### Per-unit `UMask=` directive

Login-side UMASK does not propagate to system-spawned services. The systemd PID 1 default `UMask` is `0022` (compile-time default). `/etc/systemd/system.conf` and `/etc/systemd/system.conf.d/*` carry no active `DefaultUMask=` override in the end-state.

Topic roles that want a hardened daemon-side mask set `UMask=` in their per-unit drop-in. Three reference end-state examples in this hardening tree:

```ini
# /etc/systemd/system/avahi-daemon.service.d/99-hardening.conf
[Service]
UMask=0027
```

```ini
# /etc/systemd/system/chronyd.service.d/99-hardening.conf
[Service]
UMask=0027
```

```ini
# /etc/systemd/system/NetworkManager.service.d/99-hardening.conf
[Service]
UMask=0027
```

These drop-ins do not belong to the `foundation_umask` role. They belong to the respective Topic roles, which declare `foundation_umask` as a dependency. The Foundation layer establishes the system-wide login-side default and the file-mode discipline; Topic roles consume both — by writing their config drop-ins with the correct mode and by setting `UMask=` on the daemon's own runtime-written files (logs, sockets, state).

A consequence of UMASK 0027 on operator-authored config files: `sudo` does not reset the invoking user's umask when switching to UID 0. Root-spawned writes via `tee`, `cat >`, or `printf >` therefore produce files with mode `0640`. Daemons that run under a dedicated non-root user cannot read such files, because the "other" permission bit is `0`. The recommended write pattern for `/etc/**` configs is `install -m 0644 /dev/stdin <path>` from a heredoc or pipe, or `chmod 0644 <path>` immediately after a `tee`/`cat >` redirect. The drop-in's effective parse status is verified with `systemd-analyze cat-config <unit>`; a permission failure shows up on its own line as `Failed to open …: Permission denied`. Files where `0640` is correct or where the mode is fixed by other rules: `/etc/sudoers.d/*` must be `0440` (enforced by `visudo -c`); `/etc/security/limits.d/*` and `/etc/pam.d/*` are world-readable by package default and need no manual mode change. The mechanism behind this trap and the full mitigation pattern are covered in [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md).

### Package-manager state files

libdnf5 keeps its system state in six files under the `system_state_dir`, `/usr/lib/sysimage/libdnf5/`: `environments.toml`, `groups.toml`, `modules.toml`, `nevras.toml`, `packages.toml`, and `system.toml`. The package default is mode `0644 root:root`, which is what lets an unprivileged user run `dnf info`, `dnf list --installed`, `dnf repoquery --installed`, and `dnf group list`.

libdnf5 rewrites all six files at the end of every transaction: it writes `<name>.toml.new` and renames it over the old file. The new file takes its mode from the umask of the process running the transaction, and `sudo` combines the caller's `0027` with its own default `0022`, so a transaction started through `sudo` leaves the files at `0640`. A one-time `chmod 0644` does not hold; the next transaction replaces the file and its mode with it. `transaction_history.sqlite` in the same directory is written in place and keeps its mode.

The end state installs the libdnf5 actions plugin and one action file:

| Path | Mode | Owner | Content |
|---|---|---|---|
| package `libdnf5-plugin-actions` | — | — | provides the plugin; its `/etc/dnf/libdnf5-plugins/actions.conf` carries `enabled = 1` |
| `/etc/dnf/libdnf5-plugins/actions.d/50-system-state-perms.actions` | `0644` | `root:root` | one `post_transaction` action, below |

```text
post_transaction:::enabled=host-only:/usr/bin/chmod 0644 /usr/lib/sysimage/libdnf5/environments.toml /usr/lib/sysimage/libdnf5/groups.toml /usr/lib/sysimage/libdnf5/modules.toml /usr/lib/sysimage/libdnf5/nevras.toml /usr/lib/sysimage/libdnf5/packages.toml /usr/lib/sysimage/libdnf5/system.toml
```

The `post_transaction` hook runs after libdnf5 has saved the system state, so the `chmod` acts on the files the transaction has just written. It runs for every caller of the transaction, whatever umask that caller has. `enabled=host-only` keeps the action out of `--installroot` transactions, whose state lives under a different root. The action runs inside the package manager's own domain, `rpm_t`, which already manages these files; no SELinux policy module is involved.

The grant is read access on six files and nothing else. It does not disclose more than the host already does: `dnf history info`, served from the world-readable `transaction_history.sqlite`, reports the same packages, install reasons, and source repositories, and the RPM database is world-readable as well.

## Verification

Probe:

```bash
bash ansible/roles/foundation_umask/files/probe.sh
```

Verify:

```bash
bash ansible/roles/foundation_umask/files/verify.sh
```

Expected verify output on a correctly applied host:

```text
OK   login_defs_umask               027
OK   login_defs_home_mode           0700
OK   login_defs_usergroups_enab     yes
OK   pam_postlogin_umask            session optional pam_umask.so silent
OK   shell_init_no_umask_override   none
OK   bashrc_fallback_unchanged      [ `umask` -eq 0 ] && umask 022
OK   system_conf_no_default_umask   none
OK   live_login_umask               0027
OK   pkg_libdnf5_plugin_actions     installed
OK   dnf_actions_plugin_enabled     /etc/dnf/libdnf5-plugins/actions.conf
OK   dnf_state_action_file          644 root:root
OK   dnf_state_action_label         system_u:object_r:etc_t:s0
OK   dnf_state_files_mode           6 files 644
```

The verify script exits `0` on a clean host, `1` on drift, `2` on invocation error. `dnf_state_action_file` compares the single non-comment line of the action file against the expected action. `dnf_state_action_label` compares the full SELinux context, user field included, against `matchpathcon`. `dnf_state_files_mode` is meaningful only after at least one transaction has run since the action file was installed: before that, it reflects the role's own `chmod`, afterwards the action. A `0640` here on a host where `dnf_state_action_file` is `OK` means the action did not fire. The `live_login_umask` check inspects the running shell's umask; running it from an inherited environment (for example, a `sudo` chain or a `make` recipe) may report a different value than a fresh login. Run the verify script from a freshly opened login shell to evaluate the login-time path.

## Related patterns

- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — Why a tightened login UMASK silently breaks system daemons that run under a dedicated non-root user, and how to write `/etc/**` configs so the daemon can still read them.
- [Replaced files lose their mode](../../explanation/replaced-files-lose-mode.md) — Why a `chmod` on a file that its owning tool rewrites by rename does not hold, how to recognise the class, and why the fix belongs in the tool's post-write hook.
