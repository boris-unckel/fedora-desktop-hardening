<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_flatpak_oci_pull_dbus

## Purpose

Topic role that patches one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 or later that affects the `flatpak install --system` admin pipeline when the operator login is mapped to `staff_u`, the install command is issued from a role-switched `sysadm_t` context, and the targeted Flatpak remote is OCI-typed (URL prefixed `oci+`, the canonical example being the stock `fedora` remote at `oci+https://registry.fedoraproject.org`). The end-state is a single topic-owned CIL module `flatpak_oci_pull_dbus` loaded at priority 400 carrying exactly one `(allow ...)` rule on `sysadm_t × unconfined_dbusd_t : unix_stream_socket connectto` (keeps the OCI pre-pull access-token request operational against the `uid=0` D-Bus session bus at `/run/user/0/bus`). The role ships **no** drop-in INI file under `/etc/systemd/system/`, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** systemd unit, **no** systemd handler, and **no** service restart. The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/flatpak-oci-pull-dbus.md`.

The role's preflight performs three applicability gates: OS family (Fedora ≥ 44), required-package presence (`flatpak`), and operator-mapping anchor (`staff_u` substring in `id -Z`). It also enumerates the operator-configured Flatpak remote inventory and counts OCI-typed entries (URL prefix `oci+`); on zero OCI-typed remotes the role emits an informational note that the gap is currently unreachable but pre-applies the policy patch anyway, on the rationale that a future remote addition still benefits. A pre-load `sesearch` probe runs against the functional surface; if the allow is already present in the loaded policy, the apply stage skips the CIL push as a clean no-op (the workaround-obsolescence path: a future stock-policy update has shipped the equivalent grant).

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_oci_pull_dbus_required_packages` | `[flatpak]` | Required packages; preflight asserts presence. |
| `topic_flatpak_oci_pull_dbus_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_flatpak_oci_pull_dbus_cil_module_name` | `flatpak_oci_pull_dbus` | CIL module slot name. |
| `topic_flatpak_oci_pull_dbus_cil_priority` | `400` | CIL module priority. |
| `topic_flatpak_oci_pull_dbus_cil_source_path` | `/root/flatpak_oci_pull_dbus.cil` | On-disk CIL source path. |
| `topic_flatpak_oci_pull_dbus_oci_remote_url_prefix` | `oci+` | URL-prefix substring for OCI-typed remote counting. |
| `topic_flatpak_oci_pull_dbus_expected_module_installed` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_oci_pull_dbus_expected_rule_present` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_oci_pull_dbus_expected_avc_class_since_boot` | `0` | Functional-class AVC-clean expectation. |

## Dependencies

- `foundation_umask` (Layer 0) — the explicit `0644` on the CIL source under `/root/` reflexes against the operator UMASK 0027 default.
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -i`, the `sesearch` probe, the `ausearch` AVC-clean read, and the `flatpak install --system` admin invocation itself) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 publish path the topic-owned module rides on.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in `files/verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_flatpak_oci_pull_dbus` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, OCI remote inventory, pre-load `sesearch` probe, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — CIL source push and `semodule -X 400 -i` install with creates-guard, plus the post-load `sesearch` probe assertion.
- `verify` — Soll/Ist verification (three end-state facts: module-installed, allow-rule present, AVC-clean for the functional class).

## Idempotence notes

- `ansible.builtin.copy` of the CIL source under `/root/` converges on byte-for-byte content match; on a host whose CIL source already matches the shipped content the task reports `changed=false`.
- The `semodule -X 400 -i` install task is wrapped in `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_oci_pull_dbus/cil`, so a re-run on a host already carrying the module reports `changed=false`.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, no `systemctl` task other than the dependency-provisioned audit pipeline, and no handler.
- The post-load `sesearch` probe is read-only; the assertion fires only on a converged module slot.
- The `rescue:` block on the modify `block:` does not auto-rollback. A failed apply is reported, not silently corrected; the single-stage rollback (`semodule -X 400 -r flatpak_oci_pull_dbus` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- The workaround-obsolescence no-op path: when the allow surface is already present in the loaded policy at preflight time, the apply step skips the CIL push entirely; the post-load `sesearch` assertion still fires and confirms the loaded policy.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
