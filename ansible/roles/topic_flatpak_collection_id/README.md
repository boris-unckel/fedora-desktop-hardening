<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_flatpak_collection_id

## Purpose

Topic role that issues one role-switched mutating call class per applicable remote — `sudo -r sysadm_r -t sysadm_t flatpak remote-modify --collection-id=<binding> <remote>` — against the system-wide Flatpak ostree store at `/var/lib/flatpak/repo/config`, followed by a single conditional `sudo -r sysadm_r -t sysadm_t flatpak update --appstream` AppStream refresh. The repair targets the per-remote `collection-id=` binding gap on hosts whose system-wide Flatpak install was initialized with a Pre-1.13 Flatpak: a `>= 1.13` Flatpak on a Pre-1.13-initialized ostree store falls back to a URL-based heuristic for ref-resolution, the heuristic does not stably re-bind installed refs to the configured remote, and `flatpak update` silently skips the affected refs while emitting one `Treating remote fetch error as non-fatal` warning per ref and exiting `0`. The role's defaults bind `flathub` to `org.flathub.Stable` and `gnome-nightly` to `org.gnome.Nightly` (both upstream-published constants); any additional system-wide remote the operator has configured can be added to the `topic_flatpak_collection_id_remote_bindings` mapping in `group_vars` or a playbook. The role ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** SELinux CIL module, **no** `semanage fcontext` mapping, **no** `restorecon` invocation, **no** file-label change, and **no** system-bus or per-user `systemctl` action. The full topic end-state and the verify discipline are documented in `docs/reference/topics/flatpak-collection-id.md`.

The role's preflight performs six applicability checks: OS family (Fedora >= 44), required-package presence (`flatpak`, `ostree`), system-wide Flatpak store presence (`/var/lib/flatpak/repo/` exists; the role aborts on a host whose only Flatpak install is per-user, with a clear "Topic not applicable" message that names the per-user path is out of scope), operator-mapping note (the role completes on `unconfined_u` with an informational note rather than aborting — the configuration-state repair behaves identically, only the surrounding hardening posture is owned by separate articles), remote-inventory enumeration (the role parses `flatpak remotes --columns=name,url,collection`, identifies ostree-typed remotes via URL prefix, and reports per-remote whether the `collection` column is empty), and identification of ostree-typed remotes targeted by this run (intersection of the role's binding mapping with the host's configured remote set, minus any OCI-typed entries). The pre-modify config-file content under role-switched `sysadm_t` and the pre-modify dry-run non-fatal-fetch-warning count are captured non-fatally for the run report.

## Variables

| Name | Default | Purpose |
|---|---|---|
| `topic_flatpak_collection_id_required_packages` | `[flatpak, ostree]` | Required-package preflight; fail-fast on a missing entry. |
| `topic_flatpak_collection_id_expected_seuser_substring` | `staff_u` | Operator runtime SELinux mapping anchor (informational; does not abort on mismatch). |
| `topic_flatpak_collection_id_repo_config_path` | `/var/lib/flatpak/repo/config` | The ostree-layer INI config file the modify call mutates in place. |
| `topic_flatpak_collection_id_remote_bindings` | `{flathub: org.flathub.Stable, gnome-nightly: org.gnome.Nightly}` | Per-remote binding mapping. Tunable for any additional system-wide remote the operator has configured. |
| `topic_flatpak_collection_id_oci_url_prefix` | `oci+` | URL-prefix substring used to identify OCI-typed remotes; the repair does not apply to OCI-typed remotes. |
| `topic_flatpak_collection_id_expected_nonfatal_fetch_warning_count` | `0` | Verify hardcoded expectation for the dry-run line-count. |

## Dependencies

- `foundation_sudo_roles` (Layer 1) — every mutating call (`flatpak remote-modify`, `flatpak update --appstream`) and every config-file inspection in the probe and verify transits the `staff_u -> sysadm_r -> sysadm_t` role-switch surface. Plain `sudo` from a `staff_u`-mapped login lands in `staff_sudo_t`, which lacks the DAC capability to write reliably against the UMASK-027-locked Flatpak system store and additionally lacks the SELinux write transition the policy expects for the system-wide remote configuration. Layer 1 is also the applicability anchor for the canonical `staff_u`-mapped login this Topic targets.

The role intentionally does not depend on the UMASK foundation (the role does not write a fresh file under operator UMASK influence; the per-remote configuration file already exists with stock-package-managed mode and is mutated in place by the `flatpak remote-modify` code path), the SELinux CIL bootstrap (no CIL module is shipped), or the audit-logging baseline (no AVC-stream assertion is performed). The dependency set is deliberately narrower than the sibling Flatpak topics' four-Foundation set.

## Tags

- `topic_flatpak_collection_id` — all role tasks.
- `preflight` — preflight checks only (OS family, required-package presence, system-store presence, operator-mapping note, remote-inventory enumeration, pre-modify config snapshot, pre-modify dry-run line-count, ostree-typed-target identification).
- `probe` — read-only probe (`files/probe.sh`).
- `apply` — per-remote modify loop and conditional AppStream refresh.
- `verify` — Soll/Ist verification (`files/verify.sh`).

## Idempotence notes

- The role is **idempotent** in the Ansible-`--check`-reports-zero-changes sense. Each per-remote `flatpak remote-modify --collection-id=<binding> <remote>` call is wrapped in a `changed_when` predicate that re-reads the relevant section of `/var/lib/flatpak/repo/config` after the call and reports `changed=true` only if the targeted remote's `collection-id=` line was added or modified. On a host where the targeted remote already carries the configured binding, the `flatpak remote-modify` implementation reads the existing config, computes the merged result, and writes the file only if the merged result differs (a Flatpak-internal no-op); the `changed_when` predicate accordingly reports `changed=false`.
- The trailing `flatpak update --appstream` is gated on the registered fact `__topic_flatpak_collection_id_any_changed`, set to `true` if at least one per-remote modify in the same run reported `changed=true`. The dependency is **not** encoded as a handler — handlers fire after the entire play and would defer the AppStream refresh past any subsequent task that needs it.
- The role ships no `ansible.builtin.copy`, `ansible.builtin.template`, `ansible.builtin.lineinfile`, `community.general.sefcontext`, `restorecon`, system-bus `systemctl` task, or per-user `systemctl --user` task; the only mutating calls are the per-remote `flatpak remote-modify` invocations and the conditional `flatpak update --appstream`.
- The `rescue:` block on the modify `block:` does **not** auto-rollback. The per-remote rollback verb (the empty-string call `flatpak remote-modify --collection-id="" <remote>` under role-switched `sysadm_t`) is the operator's deliberate decision and is documented in the Topic Reference under Recovery; an automatic rollback would be the wrong default, because the typical reason for a modify failure is a transient upstream condition or a partially-applied remote that the operator should inspect before unwinding.
- Boot-failure risk is **structurally zero**: the per-remote configuration file under `/var/lib/flatpak/repo/` is consulted only at `flatpak`-CLI invocation time and is not part of the system-init pipeline. The Recovery-Pointer banner in the Topic Reference is included for tree consistency, even though this role's failure modes do not include a boot failure.
- On a correctly applied host, `--check` reports zero changes (every per-remote modify reports `changed=false` and the AppStream refresh task is skipped on the `when:` clause). Stated as a claim, not a guarantee.
