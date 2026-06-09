<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# foundation_audit_logging_baseline

## Purpose

Layer 3 of the Foundation tier. Establishes the audit-and-logging baseline on a Fedora 44+ host: ensures the kernel audit pipeline (`audit`, `audit-libs`, `audit-rules`) and the SELinux audit-diagnosis tooling (`policycoreutils-python-utils`) are installed, ensures the persistent-journal directory `/var/log/journal/` exists at the package-default mode and ownership, and reads the live audit and journald state without flipping it.

The role does **not** push `/etc/audit/auditd.conf`, does **not** ship any rule fragment under `/etc/audit/rules.d/`, and does **not** push any drop-in under `/etc/systemd/journald.conf.d/`. Roles that ship audit rules (per-Topic) issue `augenrules --load` from their own `tasks/main.yml`. Roles that harden `auditd.service` itself (per-Topic) ship the service-level drop-in from their own role.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `foundation_audit_logging_baseline_required_packages` | `[audit, audit-libs, audit-rules, policycoreutils-python-utils]` | Audit pipeline plus SELinux audit-diagnosis tooling. |
| `foundation_audit_logging_baseline_persistent_journal_dir` | `/var/log/journal` | Persistent-storage trigger for `Storage=auto`. |
| `foundation_audit_logging_baseline_persistent_journal_dir_mode` | `2755` | Setgid bit propagates `systemd-journal` group to per-machine-id subdirectories. |
| `foundation_audit_logging_baseline_persistent_journal_dir_group` | `systemd-journal` | End-state group ownership. |

## Dependencies

- `foundation_umask` (Layer 0) — UMASK 0027 file-mode discipline applies to operator-authored config under `/etc/audit/` and `/etc/systemd/journald.conf.d/`. The role itself writes no such file; the dependency is declared so that any later role layered on top inherits the discipline.
- `foundation_sudo_roles` (Layer 1) — every audit tool (`auditctl`, `ausearch`, `aureport`, `audit2why`, `audit2allow`, `autrace`, `augenrules`) and every system-journal read requires the `sysadm_t` escalation. The role's preflight asserts the Layer 1 artifact is present and that the `sudo -r sysadm_r -t sysadm_t auditctl -s` escalation succeeds.

## Tags

- `foundation_audit_logging_baseline` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — modify steps (package presence, persistent-journal-directory presence, live-state read).
- `verify` — Soll/Ist verification.

## Idempotence notes

- `dnf` package presence is naturally idempotent.
- `ansible.builtin.file` on `/var/log/journal` is a no-op when the directory already exists at the expected mode and ownership.
- The live-state read uses `auditctl -s` under the role-switch and is read-only.
- The role issues no `augenrules --load`, no `auditctl -R`, no `systemctl restart systemd-journald`. There is no policy-mutation source from which a `changed=true` could arise; the only `changed=true` sources are the package install and the directory creation, both of which converge to no-op on subsequent runs.
- The role registers no handlers and restarts no service. `auditd.service` carries `RefuseManualStart=yes`/`RefuseManualStop=yes` and `systemd-journald.service` is not touched because the role pushes no journald drop-in.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. Auto-rollback for a missing tooling package or a non-default journal-directory mode would mask the failure.
