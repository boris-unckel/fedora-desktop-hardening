<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# foundation_selinux_cil_bootstrap

## Purpose

Layer 2 of the Foundation tier. Establishes the loader contract for custom SELinux CIL modules at priority 400: ensures the source-file directory `/usr/local/share/selinux/` exists at mode `0755 root:root`, ensures the SELinux tooling packages (`policycoreutils-python-utils`, `selinux-policy-targeted`) are installed, and reads the live SELinux runtime mode without flipping enforcement state.

The role does **not** install any specific CIL module and does **not** call `semodule`. Roles that ship a CIL module (Layer 1's `foundation_sudo_roles` and any Topic role that ships a transition-grant module) issue `semodule -X 400 -i` from their own `tasks/main.yml`. This role provides the directory and tooling those roles depend on.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `foundation_selinux_cil_bootstrap_directory` | `/usr/local/share/selinux` | Custom-CIL source directory. |
| `foundation_selinux_cil_bootstrap_directory_mode` | `0755` | End-state directory mode. |
| `foundation_selinux_cil_bootstrap_required_packages` | `[policycoreutils-python-utils, selinux-policy-targeted]` | SELinux tooling packages. |
| `foundation_selinux_cil_bootstrap_priority` | `400` | Priority for every custom CIL module across this tree. Hardcoded by convention; future roles read this value but do not override it. |

## Dependencies

- `foundation_umask` (Layer 0) — the UMASK 0027 file-mode discipline applies to operator-authored source CIL files at write time. The directory created by this role is `0755`; individual source-file modes are the responsibility of the role that writes each module.
- `foundation_sudo_roles` (Layer 1) — every command that mutates the policy store (`semodule -X N -i`, `semodule -X N -r`, `semodule -B`) and every read that walks `/var/lib/selinux/targeted/active/modules/` requires `sysadm_t`. The role-switch syntax lives in Layer 1; this role's preflight asserts that the Layer 1 artifact is present and that the `sudo -r sysadm_r -t sysadm_t semodule -lfull` escalation succeeds.

## Tags

- `foundation_selinux_cil_bootstrap` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — modify steps (package presence, directory presence, SELinux state read).
- `verify` — Soll/Ist verification.

## Idempotence notes

- `dnf` package presence is naturally idempotent.
- `ansible.builtin.file` on the directory is a no-op when the directory already exists at the expected mode and ownership.
- The SELinux runtime-mode read is `getenforce` and is read-only.
- The role issues no `semodule` call. There is no policy-mutation source from which a `changed=true` could arise; the only `changed=true` sources are the package install and the directory creation, both of which converge to no-op on subsequent runs.
- The role registers no handlers and does not restart any service. The loader has no daemon: `semodule -X 400 -i` activates a module at `semodule` exit, which happens in the roles that ship the module, not here.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. Auto-rollback for a missing tooling package or a non-default directory mode would mask the failure.
