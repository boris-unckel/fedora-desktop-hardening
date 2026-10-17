<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Delta run — foundation_umask dnf state files (plus topic_flatpak_audio_sandbox)

A scoped run for one Foundation change, not a full fan-out. Scope: the system tier, which
applies the Foundation and the cumulative cloud-testable topic set on one node, checks
idempotence, reboots, and verifies; plus the component scenario of
`topic_flatpak_audio_sandbox`, the one topic whose role changed in the same change set.

The change under test: `foundation_umask` installs `libdnf5-plugin-actions` and ships a
`post_transaction` action that restores `0644` on the six libdnf5 system-state files after
every transaction. libdnf5 rewrites those files by rename on each transaction, so under the
Foundation's umask `0027` they would otherwise come out `0640`
([Replaced files lose their mode](../../docs/explanation/replaced-files-lose-mode.md)).

The infrastructure was re-bootstrapped from an empty provider project
(`bootstrap_infra.sh`, `bake_base_snapshot.sh`; base image id 444677431, built from the
`fedora-44` image, which ships `selinux-policy-targeted` 44.7).

## Matrix

| Scenario | Result |
|---|---|
| system tier | PASS (create, prepare, converge, idempotence with zero changed tasks, side effect with the dnf state-file proof and a real reboot, verify in both SELinux contexts, destroy) |
| `topic_flatpak_audio_sandbox` component | PASS (create, foundation prepare, converge, idempotence, verify `staff_t` + `sysadm_t`, destroy) |

## The dnf state-file proof

The converge runs do not reliably produce a dnf transaction after Layer 0, because the base
snapshot already carries the packages. The system tier's side effect therefore runs four real
transactions before the reboot and records, after each one, whether libdnf5 replaced all six
state files (new inode) and whether all six are `0644`:

| Transaction | Front end | Rewritten | Mode `0644` | Verdict |
|---|---|---|---|---|
| reason change (`dnf mark`) | dnf CLI through `sudo`, umask `0027` | 6/6 | 6/6 | PASS |
| reason restored (`dnf mark`) | dnf CLI through `sudo`, umask `0027` | 6/6 | 6/6 | PASS |
| install one package | `ansible.builtin.dnf` | 6/6 | 6/6 | PASS |
| remove the same package | `ansible.builtin.dnf` | 6/6 | 6/6 | PASS |

Both front ends load the libdnf5 actions plugin, so the action fires on every transaction the
Foundation's operators and this tree's roles run. The post-reboot `foundation_umask` verify
reports all thirteen lines `OK` in both contexts, including `dnf_state_files_mode` after
these transactions.

## Post-reboot persistence now includes the Foundation

The persistence gate used to run every topic's `verify.sh` after the reboot but none of the
Foundation's. It now runs all four Foundation roles' `verify.sh` ahead of the topics, in both
contexts: `foundation_umask`, `foundation_sudo_roles`, `foundation_selinux_cil_bootstrap`,
`foundation_audit_logging_baseline`. Result: 4 Foundation roles and 21 topics clean in both
contexts.

`foundation_sudo_roles`' verify reads the mapped user from `FOUNDATION_SUDO_ROLES_USER`, which
its role passes as task environment. The gate passes it the same way; without it the verify
reports `semanage_login_mapping` as `FAIL`, which is an invocation gap, not drift.

## topic_flatpak_audio_sandbox: the stock policy carries the grant

On this base image the topic's preflight found `staff_t × device_t : dir mounton` already
present in the loaded policy before the role loaded anything, skipped its CIL module, and its
verify then failed on the missing module. The grant is stock: `dev_mounton(staff_t)` in
`policy/modules/roles/staff.te`, shipped with `selinux-policy` 44.2 on Fedora 44. The topic now
ships no module; it removes a priority-400 module named `flatpak_audio_sandbox` where one is
installed and asserts the stock grant, and its verify expects the module absent and the rule
present. `rule_present` remains the detector for a policy update that loses the grant.

Three other topics share the preflight shape that skips the module when the rule is already
loaded while their verify expects the module unconditionally: `topic_flatpak_kfd_device`,
`topic_flatpak_oci_pull_dbus`, and `topic_staff_wayland_memfd`. The stock policy on this base
does not carry their rules, so they pass; they would fail the same way once it does.

## Security scores (pre → post hardening)

The baseline is a fresh `fedora-44` image, so the pre-hardening figures differ from the
previous full run.

- OpenSCAP (`ssg-fedora-ds`) pass count 184 → 199; fail count 219 → 204.
- Lynis hardening index 65 → 73.
- `systemd-analyze security` exposure, pre → post: auditd 9.4 → 6.6, dbus-broker 8.7 → 7.2,
  NetworkManager 7.8 → 4.9, chronyd 3.5 → 3.2, crond 9.6 → 3.4, rngd 9.6 → 3.3, tuned 9.6 → 7.5,
  udisks2 9.6 → 4.7, avahi-daemon 9.6 → 2.7, smartd 9.6 → 3.0, thermald 9.6 → 2.6, alsa-state
  9.6 → 2.6, plymouth-start 9.5 → 1.9, cups (no pre figure) → 7.1.
