<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_gnupg_pinentry_dbus

## Purpose

Topic role that patches two narrowly-scoped gaps in the stock SELinux targeted policy on Fedora 44 or later that affect the GnuPG signing pipeline when the operator login is mapped to `staff_u` and the desktop ships `pinentry-gnome3` together with `gcr3`. The end-state is a single topic-owned CIL module `gnupg_pinentry_dbus` loaded at priority 400, carrying exactly two `(allow ...)` rules: one functional rule on `gpg_pinentry_t × session_dbusd_tmp_t : sock_file write` (keeps the GUI passphrase prompt operational), and one audit-cosmetic rule on `gpg_t × gpg_agent_t : process { noatsecure rlimitinh siginh }` (closes the dontaudit-suppressed lazy-spawn process-inheritance triple). The role ships **no** drop-in INI file under `/etc/systemd/system/`, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** systemd unit, **no** systemd handler, and **no** service restart. The full topic end-state, the verify discipline, and the single-stage rollback posture are documented in `docs/reference/topics/gnupg-pinentry-dbus.md`.

The role's preflight performs four applicability gates: OS family (Fedora ≥ 44), required-package presence (`gnupg2`, `pinentry`, `pinentry-gnome3`, `gcr3`), operator-mapping anchor (`staff_u` substring in `id -Z`), and pinentry-helper anchor (`pinentry-program=/usr/bin/pinentry-gnome3` in the operator's `~/.gnupg/gpg-agent.conf`). It also runs a pre-load `sesearch` quad-probe; if both allow surfaces are already present in the loaded policy, the apply stage skips the CIL push as a clean no-op (the workaround-obsolescence path: a future stock-policy update has shipped the equivalent grants).

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_gnupg_pinentry_dbus_required_packages` | `[gnupg2, pinentry, pinentry-gnome3, gcr3]` | Required packages; preflight asserts presence. |
| `topic_gnupg_pinentry_dbus_expected_pinentry_program` | `/usr/bin/pinentry-gnome3` | Operator pinentry-helper applicability anchor. |
| `topic_gnupg_pinentry_dbus_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping applicability anchor. |
| `topic_gnupg_pinentry_dbus_cil_module_name` | `gnupg_pinentry_dbus` | CIL module slot name. |
| `topic_gnupg_pinentry_dbus_cil_priority` | `400` | CIL module priority. |
| `topic_gnupg_pinentry_dbus_cil_source_path` | `/root/gnupg_pinentry_dbus.cil` | On-disk CIL source path. |
| `topic_gnupg_pinentry_dbus_user_gpg_agent_conf` | `/home/{{ ansible_user_id }}/.gnupg/gpg-agent.conf` | Operator gpg-agent.conf path; override for non-default home. |
| `topic_gnupg_pinentry_dbus_expected_module_installed` | `yes` | Verify hardcoded expectation. |
| `topic_gnupg_pinentry_dbus_expected_rule_a_present` | `yes` | Verify hardcoded expectation. |
| `topic_gnupg_pinentry_dbus_expected_rule_b_noatsecure_present` | `yes` | Verify hardcoded expectation. |
| `topic_gnupg_pinentry_dbus_expected_rule_b_rlimitinh_present` | `yes` | Verify hardcoded expectation. |
| `topic_gnupg_pinentry_dbus_expected_rule_b_siginh_present` | `yes` | Verify hardcoded expectation. |
| `topic_gnupg_pinentry_dbus_expected_avc_class_a_since_boot` | `0` | Functional-class AVC-clean expectation. |

## Dependencies

- `foundation_umask` (Layer 0) — the explicit `0644` on the CIL source under `/root/` reflexes against the operator UMASK 0027 default.
- `foundation_sudo_roles` (Layer 1) — every privileged step (`semodule -X 400 -i`, the `sesearch` quad-probe, the `ausearch` AVC-clean read) transits the `staff_u → sysadm_r → sysadm_t` role-switch surface.
- `foundation_selinux_cil_bootstrap` (Layer 2) — the priority-400 publish path the topic-owned module rides on.
- `foundation_audit_logging_baseline` (Layer 3) — the AVC-clean assertion in `files/verify.sh` consumes the audit pipeline that Layer 3 provisions.

## Tags

- `topic_gnupg_pinentry_dbus` — all role tasks.
- `preflight` — preflight checks only (OS family, package presence, operator-mapping applicability, pinentry-program applicability, pre-load `sesearch` quad-probe, pre-hardening sanity baseline).
- `probe` — read-only probe.
- `apply` — CIL source push and `semodule -X 400 -i` install with creates-guard, plus the post-load `sesearch` quad-probe assertion.
- `verify` — Soll/Ist verification (six end-state facts: module-installed, four allow-rule presents, AVC-clean for the functional class).

## Idempotence notes

- `ansible.builtin.copy` of the CIL source under `/root/` converges on byte-for-byte content match; on a host whose CIL source already matches the shipped content the task reports `changed=false`.
- The `semodule -X 400 -i` install task is wrapped in `creates: /var/lib/selinux/targeted/active/modules/400/gnupg_pinentry_dbus/cil`, so a re-run on a host already carrying the module reports `changed=false`.
- The role ships no `ansible.builtin.template` task, no `ansible.builtin.lineinfile` task, no `community.general.sefcontext` task, no `restorecon` invocation, no `systemctl` task other than the dependency-provisioned audit pipeline, and no handler.
- The post-load `sesearch` quad-probe is read-only; the assertion fires only on a converged module slot.
- The `rescue:` block on the modify `block:` does not auto-rollback. A failed apply is reported, not silently corrected; the single-stage rollback (`semodule -X 400 -r gnupg_pinentry_dbus` under `sysadm_r`) is operator-driven and is documented in the topic Reference.
- The workaround-obsolescence no-op path: when both allow surfaces are already present in the loaded policy at preflight time, the apply step skips the CIL push entirely; the post-load `sesearch` assertion still fires and confirms the loaded policy.
- On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.
