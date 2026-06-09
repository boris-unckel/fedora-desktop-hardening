<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# UMASK 0027

## Role in the hardening model

UMASK 0027 is Layer 0 of the Foundation tier. It establishes a system-wide default file-creation mask that produces files with mode `0640` (`-rw-r-----`) and directories with mode `0750` (`drwxr-x---`) for every interactive login session. Removing the "other" permission bits prevents files created by an operator's login session — including root-owned configuration files written under `/etc/**` — from being world-readable by default.

This Foundation layer is a prerequisite for every other Foundation layer and every Topic role. Topic roles assume `0640`/`0750` semantics on operator-authored files and apply the daemon-readability discipline that follows from them.

## End-state configuration

The end-state spans two independent layers. The login-side default applies to interactive sessions through PAM. The per-unit override applies to systemd-managed services and is set in topic-specific drop-ins. The two are orthogonal: neither implies the other, and changing one does not weaken the other.

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
```

The verify script exits `0` on a clean host, `1` on drift, `2` on invocation error. The `live_login_umask` check inspects the running shell's umask; running it from an inherited environment (for example, a `sudo` chain or a `make` recipe) may report a different value than a fresh login. Run the verify script from a freshly opened login shell to evaluate the login-time path.

## Related patterns

- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — Why a tightened login UMASK silently breaks system daemons that run under a dedicated non-root user, and how to write `/etc/**` configs so the daemon can still read them.
