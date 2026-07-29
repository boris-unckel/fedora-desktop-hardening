<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_udisks2

## Purpose

Topic role that hardens the `udisks2.service` mount-manager unit on a Fedora 44 or later host by deploying three drop-in files under `/etc/systemd/system/udisks2.service.d/`: a namespace-neutral baseline, an isolated `NoNewPrivileges=yes` layer, and a process-internal restrictions layer that includes a SATA-SMART `CAP_SYS_RAWIO` carve-out. The role ships no SELinux CIL module — stock targeted policy on Fedora 44 or later already grants the `init_t → devicekit_disk_t : process2 nnp_transition` rule that the NNP layer depends on, and the role's preflight stage verifies the rule is present before applying.

The role does **not** modify `polkit` action rules, the `gvfs-udisks2-volume-monitor` user instance, or any other surface beyond the three drop-ins. The full topic end-state, including the verify discipline and the three-stage rollback posture, is documented in `docs/reference/topics/udisks2.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_udisks2_dropin_dir` | `/etc/systemd/system/udisks2.service.d` | Drop-in directory for the unit. |
| `topic_udisks2_required_packages` | `[udisks2]` | Core package; preflight asserts presence. |
| `topic_udisks2_optional_packages` | `[udisks2-iscsi, udisks2-lvm2, udisks2-btrfs]` | Backend sub-packages; preflight reports presence as inventory only. |
| `topic_udisks2_expected_caps` | `cap_sys_admin cap_sys_rawio` | Expected `CapabilityBoundingSet=` in `systemctl show --value` form (alphabetical, lower-case). |
| `topic_udisks2_expected_address_families` | `AF_UNIX AF_NETLINK` | Expected `RestrictAddressFamilies=` in source-order form. |
| `topic_udisks2_expected_selinux_domain` | `devicekit_disk_t` | Expected SELinux domain of the running daemon. |

The drop-in bodies themselves are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so that a daemon-spawned reader (none here, the daemon runs as `root`) would see a world-readable file regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the AVC-clean read, and the live SELinux-domain read all transition through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

The role does **not** depend on `foundation_selinux_cil_bootstrap` (Layer 2). It ships no CIL module.

## Tags

- `topic_udisks2` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins are pushed verbatim from `files/`.
- The `restorecon`, `daemon-reload`, and `restart udisks2` handlers are wired through a single notification name (`topic_udisks2 dropin changed`) and fire only on file change, in that order.
- The `restorecon -F -v -R` handler relabels the drop-in directory and its contents. Targeted policy maps no service-specific unit-file type for this path, so the call is a no-op on the type; `-F` still normalises the SELinux user field, which would otherwise record whoever applied the role.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count) is read-only and reports without flipping state.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
