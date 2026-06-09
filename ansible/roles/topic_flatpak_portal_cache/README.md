<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_flatpak_portal_cache

## Purpose

Topic role that issues one mutating action — `systemctl --user restart xdg-document-portal.service` — against the operator's user-systemd instance to flush the per-user freedesktop Document portal token cache. The role wraps every upstream sandbox-tightening `flatpak override` operation: persistent and transient file-tokens that the portal granted under the prior sandbox posture remain materialized under `/run/user/${uid}/doc/by-app/<appid>/` until the per-user `xdg-document-portal.service` is restarted, even though the application's freshly-merged static manifest no longer mounts the originating host directories. The role ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** SELinux CIL module, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** file-label change, and **no** system-bus restart. The full topic end-state and the verify discipline are documented in `docs/reference/topics/flatpak-portal-cache.md`.

The role's preflight performs five applicability checks: OS family (Fedora ≥ 44), required-package presence (`flatpak`, `xdg-desktop-portal`), GTK/GNOME backend slot disposition (informational; either backend is acceptable), operator-mapping note (the role completes on `unconfined_u` with an informational note rather than aborting — the cache lifecycle is identical, only the surrounding hardening posture is owned by separate articles), and user-systemd addressability (the role aborts on a connection mode that does not propagate the user-bus DBUS address — typical for a non-graphical SSH session without `loginctl enable-linger`). The pre-reset cache snapshot (persistent count, FUSE-by-app inventory, system-wide override-store listing) is captured non-fatally for the run report.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_portal_cache_required_packages` | `[flatpak, xdg-desktop-portal]` | Required-package preflight; fail-fast on a missing entry. |
| `topic_flatpak_portal_cache_backend_packages` | `[xdg-desktop-portal-gtk, xdg-desktop-portal-gnome]` | GTK/GNOME backend slot; informational, either backend acceptable. |
| `topic_flatpak_portal_cache_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping anchor. |
| `topic_flatpak_portal_cache_portal_service_name` | `xdg-document-portal.service` | Per-user portal service that the role restarts. |
| `topic_flatpak_portal_cache_fuse_by_app_path` | `/run/user/{{ ansible_user_uid }}/doc/by-app` | FUSE truth-anchor path used by the verify. |
| `topic_flatpak_portal_cache_expected_portal_service_state` | `active` | Verify hardcoded expectation. |
| `topic_flatpak_portal_cache_expected_fuse_by_app_token_count` | `0` | Verify per-`<appid>` token count expectation. |
| `topic_flatpak_portal_cache_expected_persistent_documents_line_count` | `0` | Verify `flatpak documents list` data-row expectation. |

## Dependencies

- `foundation_sudo_roles` (Layer 1) — the probe transits the `staff_u → sysadm_r → sysadm_t` role-switch surface for the system-wide override-store read at `/var/lib/flatpak/overrides/<appid>` (read-only). Layer 1 is also the applicability anchor for the canonical `staff_u`-mapped login this Topic targets.

The role intentionally does not depend on the UMASK foundation (no `/etc/`-side or `/root/`-side file is written by the role), the SELinux CIL bootstrap (no CIL module is shipped), or the audit-logging baseline (no AVC-stream assertion is performed). The dependency set is deliberately narrower than the sibling Flatpak topics' four-Foundation set.

## Tags

- `topic_flatpak_portal_cache` — all role tasks.
- `preflight` — preflight checks only (OS family, required-package presence, GTK/GNOME backend slot disposition, operator-mapping note, user-systemd addressability, pre-reset cache snapshot, override-store inventory).
- `probe` — read-only probe (`files/probe.sh`).
- `apply` — the single mutating action (`systemctl --user restart xdg-document-portal.service`).
- `verify` — Soll/Ist verification (`files/verify.sh`).

## Idempotence notes

- The role is **not** strictly idempotent in the Ansible-`--check`-reports-zero-changes sense. `ansible.builtin.systemd_service` with `state: restarted` re-issues the user-bus restart on every Ansible run. This is a deliberate design choice: the role is post-override-applicable, an operator triggers the role manually (or via an orchestrating playbook) immediately after issuing an upstream `flatpak override` push, and the restart action is the role's primary deliverable.
- The role does not include a guard that skips the restart on a host where the cache was already empty, because the cost of an extra portal-service restart is negligible (the service re-spawns on the next D-Bus method call), and the alternative — a pre-restart probe of the FUSE path — would produce a TOCTOU window where a Flatpak application running in parallel could create a fresh token between the probe and the skip-decision.
- The role ships no `ansible.builtin.copy`, `ansible.builtin.template`, `ansible.builtin.lineinfile`, `community.general.sefcontext`, `restorecon`, or system-bus `systemctl` task; the only mutating call is the user-bus `state: restarted`.
- The `rescue:` block on the modify `block:` does not auto-rollback. The reset action is itself a recovery primitive — re-running the role at any later time re-flushes the cache to the same end-state. There is no "undo" semantics to define.
- Boot-failure risk is structurally zero: the reset action runs against a per-user user-systemd-managed unit that is not active during the system boot sequence and does not introduce any system-init dependency. The single-stage rollback is a re-application of the role itself.
- On a correctly applied host, `--check` reports the user-systemd restart task as a change. Stated as a claim, not a guarantee.
