# topic_flatpak_kfd_device

## Purpose

Topic role that patches one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 or later that affects the bwrap sandbox-construction step of every Flatpak application holding the `dri` device permission, on hosts running Flatpak 1.18 or later whose kernel exposes the AMD compute device node `/dev/kfd`, where the operator login is mapped to `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t`. Flatpak 1.18 includes `/dev/kfd` (SELinux type `hsa_device_t`) in the device-bind set derived from the `dri` permission; bwrap `stat(2)`s the bind source before mounting it, and stock policy carries zero allow rules on `staff_t × hsa_device_t : chr_file`, so the launch aborts with `bwrap: Can't get type of source /dev/kfd: Permission denied`. The denial is `dontaudit`-suppressed and produces no AVC record. The end-state is a single topic-owned CIL module `flatpak_kfd_device` loaded at priority 400 carrying exactly one `(allow ...)` rule on `staff_t × hsa_device_t : chr_file getattr`. The role ships **no** drop-in INI file, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** systemd unit, **no** systemd handler, and **no** service restart. The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/flatpak-kfd-device.md`.

The role's preflight performs three applicability gates: OS family (Fedora ≥ 44), required-package presence (`flatpak`, `bubblewrap`), and operator-mapping anchor (`staff_u` substring in `id -Z`). It also reports the `/dev/kfd` node state (absent node: informational note, the gap is unreachable but the patch is pre-applied for a future hardware change) and counts installed Flatpak applications whose permissions column contains the substring `dri` (zero: informational note, pre-apply rationale as above). A pre-load `sesearch` probe runs against the functional surface; if the allow is already present in the loaded policy, the apply stage skips the CIL push as a clean no-op (the workaround-obsolescence path).

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_kfd_device_required_packages` | `[flatpak, bubblewrap]` | Required packages; preflight asserts presence. |
| `topic_flatpak_kfd_device_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_flatpak_kfd_device_cil_module_name` | `flatpak_kfd_device` | CIL module slot name. |
| `topic_flatpak_kfd_device_cil_priority` | `400` | CIL module priority. |
| `topic_flatpak_kfd_device_cil_source_path` | `/root/flatpak_kfd_device.cil` | On-disk CIL source path. |
| `topic_flatpak_kfd_device_cil_source_backup_path` | `/root/flatpak_kfd_device.cil.pre-reinstall` | Re-install audit anchor. |
| `topic_flatpak_kfd_device_node_path` | `/dev/kfd` | Device node whose bind-source stat the functional rule keeps operational. |
| `topic_flatpak_kfd_device_dri_permission_substring` | `dri` | Per-application permission substring used to count dri-holding applications. |
| `topic_flatpak_kfd_device_expected_module_installed` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_kfd_device_expected_rule_present` | `yes` | Verify hardcoded expectation. |

## Dependencies

- `foundation_umask` (Layer 0) — the explicit `0644` on the CIL source under `/root/` reflexes against the operator UMASK 0027 default.
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -i`, the `sesearch` probe) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface. Layer 1 is also the applicability anchor: this Topic only applies to operators on the confined SELinux user `staff_u`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 publish path the topic-owned module rides on.
- `foundation_audit_logging_baseline` (Layer 3) — listed for tier consistency; note that this topic's functional class is `dontaudit`-suppressed and the role runs no `ausearch` stage of its own.

## Tags

- `topic_flatpak_kfd_device` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, device-node presence, dri-Flatpak inventory, pre-load `sesearch` probe, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — re-install audit anchor (when applicable), CIL source push, `semodule -X 400 -i` install with creates-guard, plus the post-load `sesearch` probe assertion.
- `verify` — Soll/Ist verification (module-installed, allow-rule present, functional `stat` from `staff_t`; no AVC-clean check for this `dontaudit`-suppressed class).

## Idempotence notes

- `ansible.builtin.copy` of the CIL source under `/root/` converges on byte-for-byte content match; on a host whose CIL source already matches the shipped content the task reports `changed=false`.
- The `semodule -X 400 -i` install task is wrapped in `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_kfd_device/cil`, so a re-run on a host already carrying the module reports `changed=false`.
- The re-install audit anchor (a `remote_src` copy of the currently installed CIL source to `/root/flatpak_kfd_device.cil.pre-reinstall`) only fires when the active-module slot exists; on subsequent runs the byte-for-byte content match keeps the task at `changed=false`.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, no `systemctl` task, and no handler.
- The post-load `sesearch` probe is read-only; the assertion fires only on a converged module slot.
- The `rescue:` block on the modify `block:` does not auto-rollback. A failed apply is reported, not silently corrected; the single-stage rollback (`semodule -X 400 -r flatpak_kfd_device` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- The workaround-obsolescence no-op path: when the allow surface is already present in the loaded policy at preflight time, the apply step skips the CIL push entirely; the post-load `sesearch` assertion still fires and confirms the loaded policy.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
