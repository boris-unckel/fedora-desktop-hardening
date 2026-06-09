<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_staff_wayland_memfd

## Purpose

Topic role that patches one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 or later that affects the desktop Wayland compositor when the operator login is mapped to `staff_u` and the compositor consequently runs in the `staff_t` domain. The end-state is a single topic-owned CIL module `staff_wayland_memfd` loaded at priority 400, carrying exactly one `(allow ...)` rule with two permissions: `(allow staff_t tmpfs_t (file (write map)))`. The rule keeps the compositor's read-write `mmap(2)` of a Wayland client's `wl_shm` shared-memory buffer (an anonymous `memfd` labelled `tmpfs_t`) operational under a `staff_t`-confined compositor. The role ships **no** drop-in INI file under `/etc/systemd/system/`, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** `setsebool` toggle, **no** systemd unit, **no** systemd handler, and **no** service restart. The full topic end-state, the permission-set composition, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/staff-wayland-memfd.md`.

The role's preflight performs an applicability gate on the operator runtime SELinux mapping (`staff_u` substring in `id -Z`) and asserts the GNOME compositor packages (`gnome-shell`, `mutter`) are present. It emits a non-fatal informational note when the operator session is not a Wayland session (an X11 session routes clients through Xwayland and does not reach the gap; the patch is still applied pre-emptively). It also runs a pre-load `sesearch` probe of both permissions; when both are already present as unconditional grants in the loaded policy, the apply stage skips the CIL push as a clean no-op (the workaround-obsolescence path: a future stock-policy update has shipped the equivalent grant).

## Why two permissions

The single access vector — a read-write `mmap(2)` on a `tmpfs_t` file — decomposes into two distinct SELinux checks that stock policy does not satisfy for `staff_t`:

- `file:write` — the `PROT_WRITE` flag of the mapping. Absent from stock policy.
- `file:map` — the `mmap(2)` call itself. Stock policy grants `map` only through the `domain` attribute under the `domain_can_mmap_files` boolean, which is off by default, so the stock allow does not apply at runtime.

`file:read` (the `PROT_READ` flag) is already granted by stock policy and is **not** re-stated. The two missing permissions surface in sequence rather than together on an unmodified host, because the kernel short-circuits the access vector at the first missing permission; both ship in the single end-state rule. The general class is documented in `docs/explanation/selinux-denial-sequence-masking.md`.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_staff_wayland_memfd_required_packages` | `[gnome-shell, mutter]` | Compositor packages; preflight asserts presence. |
| `topic_staff_wayland_memfd_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_staff_wayland_memfd_expected_session_type` | `wayland` | Session-type hint; informational only, not a gate. |
| `topic_staff_wayland_memfd_cil_module_name` | `staff_wayland_memfd` | CIL module slot name. |
| `topic_staff_wayland_memfd_cil_priority` | `400` | CIL module priority. |
| `topic_staff_wayland_memfd_cil_source_path` | `/root/staff_wayland_memfd.cil` | On-disk CIL source path. |
| `topic_staff_wayland_memfd_cil_source_backup_path` | `/root/staff_wayland_memfd.cil.pre-reinstall` | Re-install audit-anchor path. |
| `topic_staff_wayland_memfd_expected_module_installed` | `yes` | Verify hardcoded expectation. |
| `topic_staff_wayland_memfd_expected_rule_write_present` | `yes` | Verify hardcoded expectation. |
| `topic_staff_wayland_memfd_expected_rule_map_present` | `yes` | Verify hardcoded expectation. |
| `topic_staff_wayland_memfd_expected_avc_class_since_boot` | `0` | Functional-class AVC-clean expectation. |

## Dependencies

- `foundation_umask` (Layer 0) — the explicit `0644` on the CIL source under `/root/` reflexes against the operator UMASK 0027 default.
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -i`, the `sesearch` probes, the `ausearch` AVC-clean read) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 publish path the topic-owned module rides on.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in `files/verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_staff_wayland_memfd` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, session-type informational note, pre-load `sesearch` on both permissions, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — CIL source push and `semodule -X 400 -i` install with creates-guard, plus the post-load `sesearch` assertion on both permissions.
- `verify` — Soll/Ist verification (four end-state facts: module-installed, `write` present, `map` present, AVC-clean for the functional class).

## Idempotence notes

- `ansible.builtin.copy` of the CIL source under `/root/` converges on byte-for-byte content match; on a host whose CIL source already matches the shipped content the task reports `changed=false`.
- The `semodule -X 400 -i` install task is wrapped in `creates: /var/lib/selinux/targeted/active/modules/400/staff_wayland_memfd/cil`, so a re-run on a host already carrying the module reports `changed=false`.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, no `setsebool` task, and no `systemctl` task other than the dependency-provisioned audit pipeline, and no handler.
- The post-load `sesearch` probes are read-only; the assertion fires only on a converged module slot carrying both permissions.
- The `rescue:` block on the modify `block:` does not auto-rollback. A failed apply is reported, not silently corrected; the single-stage rollback (`semodule -X 400 -r staff_wayland_memfd` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- The workaround-obsolescence no-op path: when both permissions are already present as unconditional grants in the loaded policy at preflight time, the apply step skips the CIL push entirely; the post-load `sesearch` assertion still fires and confirms the loaded policy.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
