<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_flatpak_audio_sandbox

## Purpose

Topic role that asserts one allow surface the bwrap sandbox-construction step of every Flatpak application holding the `pulseaudio` socket permission depends on, on hosts where the operator login is mapped to `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t` (stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`). The allow is `staff_t × device_t : dir mounton`; it keeps the bwrap audio bind-mount of `/dev/snd` into the sandbox root at `/newroot/dev/snd` operational. The stock targeted policy grants it through `dev_mounton(staff_t)` in `policy/modules/roles/staff.te`, shipped with `selinux-policy` 44.2 on Fedora 44.

The role ships no policy of its own. Its modify stage removes a priority-400 module named `flatpak_audio_sandbox` where one is installed, because such a module only duplicates the stock grant, and removes the matching CIL source files under `/root/`. It then asserts the allow surface is present in the loaded policy; the assertion is the detector for a stock-policy update that loses the grant. The role ships **no** drop-in INI file under `/etc/systemd/system/`, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** systemd unit, **no** handler, and **no** service restart. The full topic end-state, the verify discipline, and the recovery path are documented in `docs/reference/topics/flatpak-audio-sandbox.md`.

The role's preflight performs three applicability gates: OS family (Fedora ≥ 44), required-package presence (`flatpak`, `bubblewrap`), and operator-mapping anchor (`staff_u` substring in `id -Z`). It also enumerates the operator-installed Flatpak inventory and counts entries whose permissions column contains the substring `pulseaudio`; on zero audio-permission applications the role emits an informational note that the surface is not exercised on this host, and asserts it anyway.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_audio_sandbox_required_packages` | `[flatpak, bubblewrap]` | Required packages; preflight asserts presence. |
| `topic_flatpak_audio_sandbox_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_flatpak_audio_sandbox_cil_module_name` | `flatpak_audio_sandbox` | Name of a priority-400 module that duplicates the stock grant; removed where installed. |
| `topic_flatpak_audio_sandbox_cil_priority` | `400` | Priority of that module. |
| `topic_flatpak_audio_sandbox_stale_source_paths` | `/root/flatpak_audio_sandbox.cil`, `/root/flatpak_audio_sandbox.cil.pre-reinstall` | CIL source files of that module; removed where present. |
| `topic_flatpak_audio_sandbox_audio_permission_substring` | `pulseaudio` | Per-application permission substring used to count audio-using applications. |
| `topic_flatpak_audio_sandbox_expected_module_installed` | `no` | Verify hardcoded expectation. |
| `topic_flatpak_audio_sandbox_expected_rule_present` | `yes` | Verify hardcoded expectation. |
| `topic_flatpak_audio_sandbox_expected_avc_class_since_boot` | `0` | Functional-class AVC-clean expectation. |

## Dependencies

- `foundation_umask` (Layer 0).
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -r`, the `sesearch` assertion, the `ausearch` AVC-clean read) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface. Layer 1 is also the applicability anchor: this Topic only applies to operators on the confined SELinux user `staff_u`.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 module store the removal step reads.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in `files/verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_flatpak_audio_sandbox` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, audio-Flatpak inventory, pre-change sanity baseline).
- `probe` — read-only probe.
- `apply` — removal of a duplicate priority-400 module and its source files, plus the `sesearch` assertion on the stock allow surface.
- `verify` — Soll/Ist verification (three end-state facts: no duplicate module, allow-rule present, AVC-clean for the functional class).

## Idempotence notes

- The module removal runs only when the priority-400 module slot exists; on a host in the end-state the slot is absent and the task is skipped.
- The source-file removal uses `ansible.builtin.file` with `state: absent` and reports `changed=false` once the files are gone.
- The `sesearch` assertion is read-only.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, and no handler.
- The `rescue:` block on the modify `block:` reports the failing check and does not attempt a correction: a missing stock grant is resolved by a policy update or by the recovery path in the topic Reference, not by the role.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
