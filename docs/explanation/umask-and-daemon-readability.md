<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# UMASK and daemon readability

## The trap

A hardened system-wide UMASK of `0027` produces files with mode `0640` (`-rw-r-----`) by default. A configuration file placed under `/etc/**` by an operator's `tee`, `cat >`, `printf >`, or heredoc redirect inherits that mode, even when the redirect runs as root through `sudo`. A daemon that runs under a dedicated non-root user account then fails to open the file with `Permission denied`, because the "other" permission bit is `0` and the daemon belongs neither to `root` (the file's owner) nor to the file's group.

The trap is silent. The redirect command exits `0`, the file appears in place with the expected content, and the daemon's status remains `active`. Any directives in the file are simply ignored, because the parser never opened them. Subsequent verification through the daemon's own status command — for example, `resolvectl status` or `chronyc tracking` — shows the pre-change behavior, suggesting that the drop-in had no effect rather than that it was unreadable.

## Why it happens

Two mechanisms compose:

- `sudo` does not reset the invoking user's umask when switching to UID 0. Even with `Defaults env_reset` in `sudoers`, the umask is inherited from the calling shell. A login session that started under `pam_umask` with `UMASK 027` keeps `0027` across `sudo`, including in the redirect-creation step.
- A redirect or `tee` from a non-zero umask produces files with mode `0666 & ~umask`, which evaluates to `0640` under umask `0027`. The file is owned by `root:root` because the redirect runs as UID 0, but the "other" bit is masked off.

A daemon that runs under a dedicated non-root user — that is, a user account distinct from `root`, with a primary group also distinct from the file's group — has no read access to a `0640` file owned by `root:root`. The daemon attempts to open the file as part of its configuration parse. The kernel returns `EACCES`. Most systemd-managed services use `cat-config`-style parsers that record the failure as a single warning and continue with the previous configuration; the failure does not cascade into a service-level error and does not move the unit out of the `active` state. The daemon is running with a stale view of its configuration, not failing.

```text
$ systemd-analyze cat-config <unit>
…
Failed to open "/etc/<service>/conf.d/99-hardening.conf": Permission denied
…
```

## How to detect it

Three observable signals, in order of how reliably they appear:

- `systemd-analyze cat-config <unit>` prints the offending path with `Permission denied` on its own line. This is the canonical detection mechanism — the parser reports the failure even when the daemon does not.
- `find /etc -type f -newer <reference-file> -not -perm -004` lists configuration files written after a known-good reference and missing the world-read bit. A file written before the UMASK change makes a serviceable reference.
- The daemon's runtime behavior does not match the directives in the dropped-in file. Service status remains `active`, configuration verification reports the previous state. This signal is unreliable in isolation and only confirms the trap after a `cat-config` check has already pointed at the file.

```text
$ ls -l /etc/<service>/conf.d/99-hardening.conf
-rw-r-----. 1 root root 274 ... 99-hardening.conf
$ systemd-analyze cat-config <service>/<unit>
… Failed to open "/etc/<service>/conf.d/99-hardening.conf": Permission denied …
```

## How to mitigate it

Apply one of two write patterns at file creation time. Both produce a root-owned, mode `0644`, world-readable file.

```bash
# Pattern A — install reads from stdin and applies mode atomically.
sudo install -m 0644 /dev/stdin /etc/<service>/conf.d/99-hardening.conf <<'EOF'
…
EOF

# Pattern B — tee writes the file, chmod fixes the mode immediately after.
sudo tee /etc/<service>/conf.d/99-hardening.conf > /dev/null <<'EOF'
…
EOF
sudo chmod 0644 /etc/<service>/conf.d/99-hardening.conf
sudo chown root:root /etc/<service>/conf.d/99-hardening.conf
```

After writing, run `systemd-analyze cat-config <unit>` once to confirm the parser opened the file. If the unit ships its own reload semantics, run `systemctl daemon-reload` before the check.

Edge cases the mitigation does not cover:

- `/etc/sudoers.d/*` must be mode `0440`, enforced by `visudo -c`. Do not apply `0644` here. The sudo binary runs as root and does not need world-read.
- `/etc/security/limits.d/*` and `/etc/pam.d/*` are world-readable by package default. Operators rarely produce them through the affected redirect pattern, and the readability failure mode does not apply to in-tree files installed by packages.
- Some daemons read configuration through a helper that runs under a different uid than the main process. The helper's uid determines whether `0640` with a matching group is sufficient; the `0644` rule remains the safer default unless the operator can prove the helper's uid matches the file's group.

## See also

- [UMASK 0027](../reference/foundation/umask.md) — The Foundation layer that establishes the system-wide UMASK from which this trap follows.
- [Drop-in files and SELinux context inheritance](dropin-selinux-context-inheritance.md) — The SELinux sibling of this trap. The same deploy step leaves the file with the type of its parent directory instead of the type its path maps to; fixing the mode does not fix the label.
