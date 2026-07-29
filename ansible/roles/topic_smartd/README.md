<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_smartd

## Purpose

Topic role that hardens the `smartd.service` SATA-SMART-polling daemon on a Fedora 44 or later host. The role deploys four shipping artefacts: three drop-in files under `/etc/systemd/system/smartd.service.d/` (a namespace-default baseline, an isolated `NoNewPrivileges=yes` layer, and a process-internal restrictions layer with the SATA-SMART `CAP_SYS_RAWIO` carve-out) and one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that grants the `init_t → fsdaemon_t : process2 nnp_transition` rule the NNP layer depends on.

The role does **not** modify the `smartctl(8)` command-line client behaviour, the `/etc/smartmontools/smartd.conf` content (mail-notification, polling-interval, per-disk `DEVICESCAN` directives are operator-policy outside this role), or any other surface beyond the four shipping artefacts. The full topic end-state, the verify discipline, and the three-stage rollback posture are documented in `docs/reference/topics/smartd.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_smartd_dropin_dir` | `/etc/systemd/system/smartd.service.d` | Drop-in directory for the unit. |
| `topic_smartd_cil_dir` | `/usr/local/share/selinux` | Priority-400 CIL publish directory. |
| `topic_smartd_required_packages` | `[smartmontools]` | Required package; preflight asserts presence. |
| `topic_smartd_expected_caps` | `cap_sys_admin cap_sys_rawio` | Expected `CapabilityBoundingSet=` in `systemctl show --value` form (alphabetical, lower-case). |
| `topic_smartd_expected_address_families` | `AF_UNIX` | Expected `RestrictAddressFamilies=` (single value). |
| `topic_smartd_expected_selinux_domain` | `fsdaemon_t` | Expected SELinux domain of the running daemon. |
| `topic_smartd_cil_module_name` | `nnp_smartd` | CIL module name without extension. |
| `topic_smartd_cil_priority` | `400` | CIL load priority. |

The drop-in bodies and the CIL body are not exposed as tunables. Operators who need to deviate from the shipped profile fork the role.

## Dependencies

- `foundation_umask` (Layer 0) — the role writes drop-ins under `/etc/` and the CIL source under `/usr/local/share/selinux/`. Each `ansible.builtin.copy` task sets `mode: '0644'` explicitly so that a daemon-spawned reader (none here, smartd runs as `root`) would see a world-readable file regardless of the operator's UMASK.
- `foundation_sudo_roles` (Layer 1) — the preflight `sesearch` query, the CIL install, the AVC-clean read, and the live SELinux-domain read all transit through `sudo -r sysadm_r -t sysadm_t`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — **hard dependency**. The role ships a topic-owned CIL module and uses the priority-400 publish path provisioned by Layer 2.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in the role's modify stage and in `verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_smartd` — all role tasks.
- `preflight` — preflight checks only.
- `probe` — read-only probe.
- `apply` — drop-in deployment, CIL install, and live-state read.
- `verify` — Soll/Ist verification.

## Idempotence notes

- `ansible.builtin.copy` is idempotent on byte-for-byte content match. The three drop-ins and the CIL source are pushed verbatim from `files/`.
- The `semodule -X 400 -i` install handler fires only on a change to the CIL source. `semodule` itself overwrites a same-priority module idempotently; a re-run of the handler against an unchanged source is a no-op.
- The `restorecon`, `daemon-reload`, and `restart smartd` handlers are wired through the `topic_smartd dropin changed` notification name and fire only on a drop-in file change, in that order.
- The `restorecon -F -v -R` handler relabels the drop-in directory and its contents. Targeted policy maps no service-specific unit-file type for this path, so the call is a no-op on the type; `-F` still normalises the SELinux user field, which would otherwise record whoever applied the role.
- The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`.
- The live-state probe (`MainPID` read, SELinux-domain read, AVC count) is read-only.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. A drift detected by verify is reported, not silently corrected. The three-stage rollback sequence is operator-driven and is documented in the topic Reference.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
