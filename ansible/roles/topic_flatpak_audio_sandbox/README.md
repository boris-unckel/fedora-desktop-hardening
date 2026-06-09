<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_flatpak_audio_sandbox

## Purpose

Topic role that patches one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 or later that affects the bwrap sandbox-construction step of every Flatpak application holding the `pulseaudio` socket permission, on hosts where the operator login is mapped to `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t` (stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`). The end-state is a single topic-owned CIL module `flatpak_audio_sandbox` loaded at priority 400 carrying exactly one `(allow ...)` rule on `staff_t × device_t : dir mounton` (keeps the bwrap audio bind-mount of `/dev/snd` operational into the sandbox root at `/newroot/dev/snd`). The role ships **no** drop-in INI file under `/etc/systemd/system/`, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** systemd unit, **no** systemd handler, and **no** service restart. The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/flatpak-audio-sandbox.md`.

The role's preflight performs three applicability gates: OS family (Fedora ≥ 44), required-package presence (`flatpak`, `bubblewrap`), and operator-mapping anchor (`staff_u` substring in `id -Z`). It also enumerates the operator-installed Flatpak inventory and counts entries whose permissions column contains the substring `pulseaudio`; on zero audio-permission applications the role emits an informational note that the gap is currently unreachable but pre-applies the policy patch anyway, on the rationale that a future application install still benefits. A pre-load `sesearch` probe runs against the functional surface; if the allow is already present in the loaded policy, the apply stage skips the CIL push as a clean no-op (the workaround-obsolescence path: a future stock-policy update has shipped the equivalent grant).

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_audio_sandbox_required_packages` | `[flatpak, bubblewrap]` | Required packages; preflight asserts presence. |
| `topic_flatpak_audio_sandbox_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_flatpak_audio_sandbox_cil_module_name` | `flatpak_audio_sandbox` | CIL module slot name. |
| `topic_flatpak_audio_sandbox_cil_priority` | `400` | CIL module priority. |
| `topic_flatpak_audio_sandbox_cil_source_path` | `/root/flatpak_audio_sandbox.cil` | On-disk CIL source path. |
| `topic_flatpak_audio_sandbox_cil_source_backup_path` | `/root/flatpak_audio_sandbox.cil.pre-reinstall` | Re-install audit anchor. |
| `topic_flatpak_audio_sandbox_audio_permission_substring` | `pulseaudio` | Per-application permission substring used to count audio-using applications. |
| `topic_flatpak_audio_sandbox_expected_module_installed` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_audio_sandbox_expected_rule_present` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_audio_sandbox_expected_avc_class_since_boot` | `0` | Functional-class AVC-clean expectation. |

## Dependencies

- `foundation_umask` (Layer 0) — the explicit `0644` on the CIL source under `/root/` reflexes against the operator UMASK 0027 default.
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -i`, the `sesearch` probe, the `ausearch` AVC-clean read) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface. Layer 1 is also the applicability anchor: this Topic only applies to operators on the confined SELinux user `staff_u`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 publish path the topic-owned module rides on.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in `files/verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_flatpak_audio_sandbox` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, audio-Flatpak inventory, pre-load `sesearch` probe, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — re-install audit anchor (when applicable), CIL source push, `semodule -X 400 -i` install with creates-guard, plus the post-load `sesearch` probe assertion.
- `verify` — Soll/Ist verification (three end-state facts: module-installed, allow-rule present, AVC-clean for the functional class).

## Idempotence notes

- `ansible.builtin.copy` of the CIL source under `/root/` converges on byte-for-byte content match; on a host whose CIL source already matches the shipped content the task reports `changed=false`.
- The `semodule -X 400 -i` install task is wrapped in `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_audio_sandbox/cil`, so a re-run on a host already carrying the module reports `changed=false`.
- The re-install audit anchor (a `remote_src` copy of the currently installed CIL source to `/root/flatpak_audio_sandbox.cil.pre-reinstall`) only fires when the active-module slot exists; on subsequent runs the byte-for-byte content match keeps the task at `changed=false`.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, no `systemctl` task other than the dependency-provisioned audit pipeline, and no handler.
- The post-load `sesearch` probe is read-only; the assertion fires only on a converged module slot.
- The `rescue:` block on the modify `block:` does not auto-rollback. A failed apply is reported, not silently corrected; the single-stage rollback (`semodule -X 400 -r flatpak_audio_sandbox` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- The workaround-obsolescence no-op path: when the allow surface is already present in the loaded policy at preflight time, the apply step skips the CIL push entirely; the post-load `sesearch` assertion still fires and confirms the loaded policy.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
