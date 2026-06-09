<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_switcheroo_control

## Purpose

Topic role that disables `switcheroo-control.service` on a Fedora 44 or later host whose graphics configuration is single-GPU or non-switchable multi-GPU. The end-state is the unit `disabled`, the unit `inactive(dead)`, and the `WantedBy=graphical.target` symlink absent under `/etc/systemd/system/graphical.target.wants/`. The role ships **no** drop-in INI file under `/etc/systemd/system/switcheroo-control.service.d/`, **no** SELinux CIL module, **no** `Protect*` family, **no** `SystemCallFilter=`, **no** `CapabilityBoundingSet=` reduction, and **no** namespace-default baseline. The hardening surface is the absence of the running daemon.

The role's preflight stage performs hybrid-GPU detection through PCI enumeration as the upstream-canonical signal: a combined display-plus-3D PCI controller count of two or more is the hybrid-GPU class, on which the daemon is required for normal desktop operation; the role fail-fasts in that case. The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/switcheroo-control.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_switcheroo_control_unit_name` | `switcheroo-control.service` | Unit name. |
| `topic_switcheroo_control_required_packages` | `[switcheroo-control]` | Required package; preflight asserts presence. |
| `topic_switcheroo_control_graphical_target_wants_symlink` | `/etc/systemd/system/graphical.target.wants/switcheroo-control.service` | Symlink whose absence is the third end-state fact. |
| `topic_switcheroo_control_expected_unit_file_state` | `disabled` | Expected `UnitFileState=`. |
| `topic_switcheroo_control_expected_active_state` | `inactive` | Expected `ActiveState=`. |
| `topic_switcheroo_control_expected_sub_state` | `dead` | Expected `SubState=`. |
| `topic_switcheroo_control_expected_result` | `success` | Expected `Result=`. |
| `topic_switcheroo_control_expected_main_pid` | `0` | Expected `MainPID=`. |
| `topic_switcheroo_control_max_gpu_count_for_applicability` | `1` | Combined display+3D PCI controller count above which the role's preflight fail-fasts. |

The drop-in directory and CIL module are not exposed as tunables because the role ships neither.

## Dependencies

- `foundation_sudo_roles` (Layer 1) — the modify action runs through `sudo -r sysadm_r -t sysadm_t systemctl disable --now switcheroo-control.service`; the AVC-clean assertion in `files/verify.sh` runs through the same role-switch.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion consumes the audit pipeline that Layer 3 provisions.

`foundation_umask` is **not** a dependency. This role writes no configuration files under `/etc/`; the operator UMASK 0027 mode-reflex has nothing to apply against. `foundation_selinux_cil_bootstrap` is **not** a dependency. This role ships no CIL module; the priority-400 publish path is not invoked. The dependency set is intentionally smaller than every other Topic-tier role in this tree.

## Tags

- `topic_switcheroo_control` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, hybrid-GPU detection, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — single canonical disable+stop action and live-state read.
- `verify` — Soll/Ist verification (three end-state facts plus AVC-clean).

## Idempotence notes

- `ansible.builtin.systemd_service` with `enabled: false` and `state: stopped` is idempotent on a host already in the end-state; the module reports `changed=false`.
- The role ships no `ansible.builtin.copy` task, no `ansible.builtin.template` task, and no `ansible.builtin.lineinfile` task; there are no configuration artefacts to push.
- The role ships no handler — there is nothing to `daemon-reload`, `restart`, or `restorecon`. No `meta: flush_handlers` synchronisation is required.
- The live-state probe (MainPID read, symlink stat, AVC count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The single-stage rollback action (`systemctl enable --now switcheroo-control.service` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
