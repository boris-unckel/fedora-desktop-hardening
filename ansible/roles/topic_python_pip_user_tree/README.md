<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_python_pip_user_tree

## Purpose

Topic role that deploys the Python pip user-tree discipline on a Fedora 44 or later host. The role writes one persistent on-disk artefact — the PEP-668 `EXTERNALLY-MANAGED` marker file at the active interpreter's stdlib path (resolved at deploy time from `sysconfig.get_path("stdlib")`, mode `0644 root:root`, not RPM-owned) — and surfaces two operator-policy conventions as recommended discipline rather than auto-applying them: a symmetric `--user`-only `pip` form for operator update scripts and an opinionated curated whitelist of pip-only packages maintained in the user-tree. The role does **not** issue `pip install`, `pip uninstall`, or any other mutation of user-tree contents; the role does **not** auto-edit any operator-named update script. Orphan user-trees and `/usr/local/lib/python3.*/` sudo-pip residue are detected and reported; the operator runs the destructive cleanup explicitly.

The role does **not** ship a systemd unit, a systemd drop-in, an `/etc/profile.d/` script, an SELinux CIL module, an `semanage fcontext` mapping, a `restorecon` invocation, a polkit rule, a sudoers fragment, or a desktop-entry override. The full topic end-state, the verify discipline (marker presence, marker mode/ownership, marker non-RPM-ownership, no `/usr/local/lib/python3.*` directories, no `/usr/local/{bin,sbin}/pip*` files, no orphan user-trees), the canonical live-test sequence under `sysadm_t` plus plain `sudo`, the per-Python-minor-bump migration discipline, the orphan-tree cleanup discipline, and the two-stage rollback posture are documented in `docs/reference/topics/python-pip-user-tree.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_python_pip_user_tree_marker_filename` | `EXTERNALLY-MANAGED` | Marker filename. The directory part of the path is resolved dynamically; only the basename is a tunable. |
| `topic_python_pip_user_tree_expected_marker_mode` | `644` | Expected file mode on the marker. |
| `topic_python_pip_user_tree_expected_marker_owner` | `root` | Expected owner on the marker. |
| `topic_python_pip_user_tree_expected_marker_group` | `root` | Expected group on the marker. |
| `topic_python_pip_user_tree_marker_body_first_line` | `[externally-managed]` | First line of the marker body; verify asserts this verbatim. |
| `topic_python_pip_user_tree_check_orphan_user_trees` | `true` | Toggle for the orphan-user-tree probe and report. |
| `topic_python_pip_user_tree_check_userlocal_pip_layer` | `true` | Toggle for the sudo-pip-layer probe and report. |
| `topic_python_pip_user_tree_user_home` | `/home/<user>` | Operator home directory used by the user-tree probe. Override per-host. |
| `topic_python_pip_user_tree_required_packages` | `[python3, python3-pip]` | Required packages; preflight asserts presence. |

The marker body is **not** exposed as a tunable. The marker path is **not** exposed as a tunable; hard-coding `/usr/lib/python3.X/` or `/usr/lib64/python3.X/` is the documented bug class, and the role discovers the path from `sysconfig.get_path("stdlib")` at deploy time. The curated whitelist is **not** exposed as a tunable; it is operator-policy outside Topic scope.

## Dependencies

- `foundation_umask` (Layer 0) — the marker lands at `/usr/lib64/python3.X/EXTERNALLY-MANAGED`. The `ansible.builtin.template` task sets `mode: '0644'` explicitly so the file is world-readable regardless of the operator's UMASK 0027. Without the explicit mode-set, the file would land at `0640 root:root` and pip would not be able to read it as the unprivileged user, silently bypassing the marker.
- `foundation_sudo_roles` (Layer 1) — the marker write under `/usr/lib64/python3.X/` runs through `sudo -r sysadm_r -t sysadm_t`. The `staff_sudo_t` domain lacks `DAC_OVERRIDE` and `DAC_READ_SEARCH`, so a plain-`sudo` write to a UMASK-027-locked path owned by `root:root` mode `0755` fails with `Permission denied` before SELinux ever evaluates the write. The same role-switch is structural for the operator's destructive cleanup of `/usr/local/lib/python3.X/` sudo-pip residue and for the canonical live-test that drives pip past the writability check into the marker-check path.

The role does **not** depend on `foundation_selinux_cil_bootstrap` (no CIL module is shipped) or on `foundation_audit_logging_baseline` (no AVC stream is read; the verify discipline is filesystem-level, not audit-stream-level).

## Tags

- `topic_python_pip_user_tree` — all role tasks.
- `preflight` — preflight checks only (OS family, required packages, stdlib-path discovery, RPM-non-ownership probe, user-tree probe, sudo-pip-layer probe).
- `probe` — read-only probe.
- `apply` — marker render, orphan-marker cleanup, orphan-tree report, symmetric-pip discipline `pause:` task.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.template` is content-hash-idempotent. The marker body is rendered from `templates/EXTERNALLY-MANAGED.j2`; a re-render of the same body is a no-op and triggers no change.
- The orphan-marker cleanup task (`ansible.builtin.file` with `state: absent` on each non-active-minor `EXTERNALLY-MANAGED` file under `/usr/lib64/python3.*/`) is idempotent: a missing file is not re-created, and a present file at the active-minor path is not removed (the loop excludes the active minor by name).
- The orphan-user-tree and sudo-pip-layer probes are read-only `shell:` tasks with `changed_when: false`.
- The role does **not** auto-remove orphan user-trees or `/usr/local/lib/python3.X/` sudo-pip residue. The operator runs the destructive cleanup from the topic Reference under "Orphan tree cleanup" because the cleanup is destructive against operator data even when the data is dead.
- The role does **not** auto-edit operator update scripts. The symmetric-pip discipline is surfaced via a `pause:` task with the byte-exact recommended form; the operator confirms or fixes the script in another shell.
- There are no systemd handlers, no `daemon-reload`, no `restart`, and no `restorecon`. The topic ships no daemon and the marker write does not require a label fix.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. Drift detected by verify is reported, not silently corrected. The two-stage rollback sequence is operator-driven and documented in the topic Reference.
- On a correctly applied host every modify task reports `ok` (no `changed`). Stated as a claim, not a guarantee.
