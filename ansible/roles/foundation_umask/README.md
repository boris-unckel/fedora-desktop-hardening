<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# foundation_umask

## Purpose

Layer 0 of the Foundation tier. Establishes the system-wide login-time UMASK as `027` in `/etc/login.defs`, so that `pam_umask` applies a default file-creation mask of `0027` to every interactive session. Topic roles depend on this layer for their `0640`/`0750` file-mode assumptions and for the daemon-readability discipline that follows from them.

The role does not write per-unit `UMask=` drop-ins. Those belong to Topic roles (for example `topic_avahi_daemon`, `topic_chronyd`, `topic_network_manager`) that consume the Foundation. The role also does not edit `/etc/bashrc`; the package-default defensive fallback line `[ \`umask\` -eq 0 ] && umask 022` is verified to remain in place but is never modified.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `foundation_umask_value` | `027` | Octal value written to the `UMASK` line of `login.defs`. |
| `foundation_umask_home_mode` | `0700` | Expected `HOME_MODE` value in `login.defs`. Verified, not enforced — the package default already matches. |
| `foundation_umask_login_defs_path` | `/etc/login.defs` | Path to `login.defs`. Overridable for tests. |

## Dependencies

None. `foundation_umask` is Layer 0 in the Foundation tier; later Foundation roles and all Topic roles list it in their `meta/main.yml` `dependencies:` block.

## Tags

- `foundation_umask` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — `lineinfile` change in `login.defs`.
- `verify` — Soll/Ist verification.

## Idempotence notes

- The single modify task is `ansible.builtin.lineinfile` against the `^UMASK\s+` regex. Re-applying on a host already at `UMASK 027` produces no change. The `validate:` clause runs `grep` against the post-write file and rejects any value that does not match the expected end state.
- The role does not restart any service. `pam_umask` reads `/etc/login.defs` at session start, so the change becomes effective for new login sessions; existing sessions retain their inherited umask until they end. Running the role against the host that is currently logged in does not affect the running session.
- The verify script reads files only and uses the shell's `umask` builtin to read the live value. Running it under `sudo` or under a non-login shell may report the inherited umask of the calling environment rather than the value that a fresh login would apply; run from a freshly opened login shell to evaluate the login-time path.
