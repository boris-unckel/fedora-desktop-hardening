<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# foundation_sudo_roles

## Purpose

Layer 1 of the Foundation tier. Maps the operator's POSIX account to the SELinux user `staff_u` via `semanage login -m`, cleans up `/etc/sudoers`'s `secure_path` directive, installs the `staff_extras` priority-400 CIL module that fills daily-desktop allow-gaps for `staff_u`, and (when applicable) labels custom `Defaults!<cmd> logfile=` paths in `/etc/sudoers.d/` as `sudo_log_t`.

The role does not document the CIL bootstrap mechanism (priority conventions, install discipline, module-store backup ordering); that lives in a separate Foundation layer. The role does not document the Flatpak/`bwrap` sandbox-construction cluster of `staff_extras.cil`, even though it ships the cluster as part of the same physical CIL file; that cluster is documented in a separate User-Applications topic.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `foundation_sudo_roles_user` | (none — must be set) | POSIX account name to map to `staff_u`. The preflight fails if this is unset. |
| `foundation_sudo_roles_mls_range` | `s0-s0:c0.c1023` | MLS/MCS range for the mapping. Matches the distribution default for `unconfined_u`. |
| `foundation_sudo_roles_cil_module_path` | `/usr/local/share/selinux/staff_extras.cil` | Install path for the CIL module. |
| `foundation_sudo_roles_cil_priority` | `400` | `semodule -X` priority. |
| `foundation_sudo_roles_secure_path` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | End-state value for the sudoers `secure_path` directive. |

## Dependencies

`foundation_umask` (Foundation Layer 0). The DAC-cap trap surfaced by this layer is rooted in the UMASK 0027 file-mode default that Layer 0 establishes; without Layer 0 applied, the operator-side trap manifests differently and the cross-link in the Reference article would be incorrect.

## Tags

- `foundation_sudo_roles` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — modify steps (semanage login, sudoers edit, semodule install, optional sudo_log_t relabel).
- `verify` — Soll/Ist verification.

## Idempotence notes

- The `semanage login -m` task is gated by a preceding read of `/etc/selinux/targeted/seusers`; when the operator's mapping is already `staff_u`, the modify step is skipped and the task reports `ok=1 changed=0`.
- The `lineinfile` task on `/etc/sudoers` is a no-op when the `secure_path` value already matches `foundation_sudo_roles_secure_path`. The `validate: 'visudo -c -f %s'` clause guarantees a syntactically valid file before the original is replaced; a malformed sudoers block would otherwise lock out `sudo` entirely.
- The `copy` of `staff_extras.cil` registers a change only when the destination differs from the role-shipped source. The `semodule -X 400 -i` reload is gated on that change. Older `semodule` versions report `changed=true` for an identical-checksum re-install; this is tolerated and is not a true drift signal.
- The custom-`logfile=` relabel branch is gated by a probe of `/etc/sudoers.d/`. When no drop-in carries a custom `logfile=` directive, the `semanage fcontext -a` and `restorecon -Fv` tasks loop over an empty list and produce no change. When the file-context entry already exists, `semanage fcontext -a` returns "already defined" on stderr and the `failed_when` clause tolerates it.
- The role registers no handlers and does not restart any service. `pam_selinux` reads the mapping at the next interactive login; existing sessions retain their inherited context until they end. `sudo` re-reads `/etc/sudoers` on every invocation. `semodule` activates the policy module at exit. The role pauses for nothing.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. Auto-rollback would risk leaving the host in an unconfined state without the operator's awareness.
