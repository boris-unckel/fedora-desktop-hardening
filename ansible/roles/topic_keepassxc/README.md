<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_keepassxc

## Purpose

Harden the KeePassXC password manager as a user-launched application under a
custom SELinux sub-domain plus an enforced data-file cut. The role installs
three priority-400 CIL modules, adds four `semanage fcontext` mappings, and
runs a four-target `restorecon`. The end state:

- `keepassxc_extras` declares `keepassxc_t` (the runtime sub-domain),
  `keepassxc_exec_t` (the entrypoint label on the three binaries), and
  `keepassxc_db_t` (a `file_type`-only data label), wires the entrypoint
  transition from `staff_t` / `sysadm_t`, and grants the database-access
  surface. The domain runs in a permissive discovery posture; the
  `staff_t × keepassxc_db_t` cut is enforced regardless.
- `keepassxc_dbtype_autotrans` keeps `keepassxc_db_t` on files the application
  writes through its write-temp-then-`rename(2)` save.
- `keepassxc_spawn_isolation` kicks any `bin_t` exec from `keepassxc_t` back to
  `staff_t`, so helpers the application launches (a browser via
  `flatpak`/`bwrap`, `xdg-open`) do not inherit the sub-domain.

The role ships no systemd unit, no drop-in, no `/etc` configuration, no polkit
rule, no sudoers fragment, and no desktop-entry override.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `topic_keepassxc_required_packages` | `['keepassxc']` | Packages asserted present in preflight. |
| `topic_keepassxc_binaries` | the three `/usr/bin/keepassxc*` | Binaries relabeled to `keepassxc_exec_t`. |
| `topic_keepassxc_database_dir` | `/home/{{ ansible_user_id }}/keepass` | Operator-chosen database directory. Not created by the role; a missing path is a preflight fail-fast. |
| `topic_keepassxc_database_fcontext_regex` | `{{ database_dir }}(/.*)?\.kdbx(\.backup)?` | fcontext regex for `*.kdbx` / `*.kdbx.backup`. |
| `topic_keepassxc_cil_priority` | `400` | CIL load priority. |
| `topic_keepassxc_cil_source_dir` | `/root` | Where the three CIL sources are materialized. |
| `topic_keepassxc_cil_modules` | the three module names | Module set installed in one `semodule` transaction. |
| `topic_keepassxc_expected_typepermissive_keepassxc_t` | `yes` | Discovery-posture marker; an operator-policy lockdown sets this to `no`. |
| `topic_keepassxc_binary_setype` | `keepassxc_exec_t` | Expected binary label. |
| `topic_keepassxc_database_setype` | `keepassxc_db_t` | Expected database-file label. |

## Dependencies

The full Foundation set — the maximum dependency set in this tree:

- `foundation_umask` — the three CIL sources land under `/root/` with an
  explicit `0644` against operator UMASK 0027.
- `foundation_sudo_roles` — every privileged step transits the
  `staff_u → sysadm_r → sysadm_t` role-switch.
- `foundation_selinux_cil_bootstrap` — the priority-400 `semodule` publish path.
- `foundation_audit_logging_baseline` — the AVC-stream read in verify.

## Tags

- `topic_keepassxc` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — CIL install, fcontext mappings, restorecon, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The
  three CIL sources are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a CIL-source change
  and installs all three modules in one transaction, so the companion modules'
  references to `keepassxc_t` / `keepassxc_db_t` / `bin_t` resolve at link time.
  `semodule` overwrites a same-priority module idempotently.
- `community.general.sefcontext` with `state: present` is idempotent: it adds
  the four fcontext entries on first run and reports unchanged afterwards.
- The two `restorecon` handlers fire only on the corresponding fcontext change.
- The `meta: flush_handlers` after the CIL source push enforces the
  load-before-fcontext invariant (the custom types must exist before
  `restorecon` resolves them).
- The live-state probe (GUI PID read, SELinux-domain read, AVC count) is
  read-only.
- The `rescue:` block does **not** auto-rollback. Drift detected by verify is
  reported, not silently corrected. The rollback removes the companion modules
  before `keepassxc_extras` (they reference its types) and is documented in the
  topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a
  claim, not a guarantee.
