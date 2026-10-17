<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# foundation_umask

## Purpose

Layer 0 of the Foundation tier. Establishes the system-wide login-time UMASK as `027` in `/etc/login.defs`, so that `pam_umask` applies a default file-creation mask of `0027` to every interactive session. Topic roles depend on this layer for their `0640`/`0750` file-mode assumptions and for the daemon-readability discipline that follows from them.

The role also carries the countermeasure for the one collateral of that mask that a `chmod` cannot fix. libdnf5 rewrites its system-state files under `/usr/lib/sysimage/libdnf5/` on every transaction (new file, then rename), so their mode comes from the caller's umask; under `0027` they would be created `0640`, and unprivileged `dnf info`, `dnf list --installed`, and `dnf repoquery --installed` fail. The role installs `libdnf5-plugin-actions` and ships `/etc/dnf/libdnf5-plugins/actions.d/50-system-state-perms.actions`, a `post_transaction` action that restores `0644` after the state has been saved. See [Replaced files lose their mode](../../../docs/explanation/replaced-files-lose-mode.md).

The role does not write per-unit `UMask=` drop-ins. Those belong to Topic roles (for example `topic_avahi_daemon`, `topic_chronyd`, `topic_network_manager`) that consume the Foundation. The role also does not edit `/etc/bashrc`; the package-default defensive fallback line `[ \`umask\` -eq 0 ] && umask 022` is verified to remain in place but is never modified.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `foundation_umask_value` | `027` | Octal value written to the `UMASK` line of `login.defs`. |
| `foundation_umask_home_mode` | `0700` | Expected `HOME_MODE` value in `login.defs`. Verified, not enforced — the package default already matches. |
| `foundation_umask_login_defs_path` | `/etc/login.defs` | Path to `login.defs`. Overridable for tests. |
| `foundation_umask_dnf_actions_package` | `libdnf5-plugin-actions` | Package providing the libdnf5 actions plugin. |
| `foundation_umask_dnf_actions_conf` | `/etc/dnf/libdnf5-plugins/actions.conf` | Plugin configuration; verified to carry `enabled = 1`, not written. |
| `foundation_umask_dnf_actions_dir` | `/etc/dnf/libdnf5-plugins/actions.d` | Directory relabelled by the handler. |
| `foundation_umask_dnf_actions_file` | `/etc/dnf/libdnf5-plugins/actions.d/50-system-state-perms.actions` | The `post_transaction` action file. |
| `foundation_umask_dnf_state_dir` | `/usr/lib/sysimage/libdnf5` | libdnf5 `system_state_dir`; preflight asserts it matches `dnf --dump-main-config`. |
| `foundation_umask_dnf_state_files` | `environments`, `groups`, `modules`, `nevras`, `packages`, `system` | State files (`<name>.toml`) the action keeps at `0644`. |

## Dependencies

None. `foundation_umask` is Layer 0 in the Foundation tier; later Foundation roles and all Topic roles list it in their `meta/main.yml` `dependencies:` block.

## Tags

- `foundation_umask` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — `lineinfile` change in `login.defs`, the actions plugin, the action file, and the current state-file mode.
- `verify` — Soll/Ist verification.

## Idempotence notes

- The `login.defs` modify task is `ansible.builtin.lineinfile` against the `^UMASK\s+` regex. Re-applying on a host already at `UMASK 027` produces no change. The `validate:` clause runs `grep` against the post-write file and rejects any value that does not match the expected end state.
- The dnf part converges in one run: the package task, the action file, and the `0644` mode on the existing state files report no change once in place. A later transaction rewrites the state files and the action restores the mode, so a second run still finds `0644`. A changed state-file task on a re-run means the action did not fire.
- The handler runs `restorecon -F -v -R` on the actions directory and inherits the play's become context: Layer 0 runs before the `staff_u` login mapping on a fresh host, where a fixed `sysadm_r` role switch is not yet authorized.
- The role does not restart any service. `pam_umask` reads `/etc/login.defs` at session start, so the change becomes effective for new login sessions; existing sessions retain their inherited umask until they end. Running the role against the host that is currently logged in does not affect the running session.
- The verify script reads files only and uses the shell's `umask` builtin to read the live value. Running it under `sudo` or under a non-login shell may report the inherited umask of the calling environment rather than the value that a fresh login would apply; run from a freshly opened login shell to evaluate the login-time path.
