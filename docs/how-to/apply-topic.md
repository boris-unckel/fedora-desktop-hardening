<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Apply one Topic role

## Goal

At the end of this procedure, one Topic role of the operator's choosing is applied, its end-state directives are in force, the role's `verify.sh` exits `0` in both `staff_t` and `sysadm_t` contexts, and the host's hardening posture has grown by one topic without regression on any Foundation layer or on any previously-applied Topic role.

## Prerequisites

- The four Foundation layers are applied and verified per [Apply the Foundation tier](apply-foundation.md). The Foundation tier is the platform on which every Topic role runs; this how-to does not re-derive its layer list and does not re-check Foundation state.
- The operator's interactive login is `staff_u`-confined. A fresh `id -Z` reports `staff_u:staff_r:staff_t:s0-s0:c0.c1023`. This is the post-apply state established by the Layer 1 role, named here so the role-switch reflex used in Step 4 has its precondition declared.
- The role-switch reflex from `staff_t` to `sysadm_t` is in muscle memory. Every `semodule`, `semanage`, `restorecon`, `ausearch`, `audit2allow`, and `audit2why` invocation in this how-to runs as `sudo -r sysadm_r -t sysadm_t <cmd>`; the syntax and rationale live in [staff_u and sudo role transitions](../reference/foundation/sudo-roles.md) and are not re-derived here.
- The chosen Topic role is present in the operator's checkout under `ansible/roles/topic_<role_short>/`, and the role's `meta/main.yml` declares all four `foundation_*` roles as dependencies. Ansible refuses to apply the role against a host on which a Foundation dependency has not run; the prerequisite is reader-side awareness, not a separate manual check.
- A pre-hardening functional smoketest baseline for the topic's user-visible contract is recorded. Functional smoketests need a baseline so that hardware-side or kernel-side innocent failures that pre-existed the apply are not later misattributed to the role's apply.
- A second, password-protected login channel is reachable on the target. This is either a separate console login or a separate `ssh` session that authenticates as a different account and is the recovery path if the target stops responding to the operator's interactive login between Step 4 and Step 6.

## Steps

1. Read the chosen role's Reference and README before running anything else.
   ```bash
   ${EDITOR:-less} docs/reference/topics/<role_short>.md
   ${EDITOR:-less} ansible/roles/topic_<role_short>/README.md
   ```
   Expected outcome: from the Reference, the operator extracts the `## Scope` boundary (which directives the role owns and which it explicitly does not own) and the `## Verification` line shape (the per-topic line names that `verify.sh` emits in each context). From the README, the operator extracts the `## Tags` set (which tag-scoped runs the role supports) and the `## Idempotence notes` (which conditions allow `--check` to report `changed=0` after a successful first apply).

2. Probe the host's current state for the chosen topic.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t probe,topic_<role_short> ansible/playbooks/topic-<role_short>.yml
   ```
   Expected outcome: the role's `probe.sh` runs through Ansible's `become` chain from the `staff_u`-confined login. The probe is read-only and prints an inventory of the relevant directives, capability bounding sets, SELinux contexts, and unit states. Probe output is informational only — the gate to apply is the `## Prerequisites` checklist above and the role's own preflight (which Step 4 invokes), not the probe.

3. Record the pre-hardening functional smoketest baseline.
   ```bash
   <smoketest_command>
   ```
   Expected outcome: the operator records the pre-apply output verbatim — exit code, stdout, stderr — to a file outside the repository checkout. The post-apply verify in Step 5 reconciles the post-apply smoketest output against this baseline. The rationale in one sentence: hardware-side or kernel-side innocent failures that pre-existed the apply are not signals of role drift, and without a baseline the operator cannot tell the two classes apart.

4. Apply the role through the canonical `ansible-playbook` invocation.
   ```bash
   ansible-playbook -i inventory/<env>/hosts.yml -t topic_<role_short> ansible/playbooks/topic-<role_short>.yml
   ```
   Expected outcome: the role passes through four phases in order. Preflight runs the assertions in `tasks/preflight.yml` and may fail-fast on OS-family mismatch, missing vendor unit, missing packages, or a missing stock-policy SELinux allow rule. Probe re-runs the read-only inventory with `changed_when: false`. Apply runs the `block`/`rescue` body that pushes drop-ins, copies CIL staging files if any, and notifies the daemon-reload, service-restart, and `semodule -X 400 -i` handlers. Verify is the role's `verify.sh` invoked as the final task with `failed_when: rc != 0`. A `failed_when` hit on preflight or verify is a stop-and-investigate event, not a retry event; the role's `rescue` block intentionally does not auto-rollback because the operator decides which apply stage to revert and multi-stage drop-in topics require multi-stage rollback.

5. Re-verify from a fresh login shell in both `staff_t` and `sysadm_t` contexts.
   ```bash
   bash ansible/roles/topic_<role_short>/files/verify.sh
   sudo -r sysadm_r -t sysadm_t bash ansible/roles/topic_<role_short>/files/verify.sh
   ```
   Expected outcome: the `staff_t` pass exits `0`, with public-readable checks all reported as `OK …` and any `sysadm_t`-restricted check reported as `SKIP needs sysadm_t`; the `sysadm_t` pass exits `0`, with every `SKIP …` line of the `staff_t` pass now `OK …`. The role's Reference `## Verification` section names the per-topic line shapes; this how-to does not inline them. The fresh-login-shell requirement is load-bearing: handlers fired by Ansible's notify chain (daemon-reload, service restart, `semodule -X 400 -i`) settle inside the playbook run, but environment-variable changes that gate the operator's interactive context only land in the next login session.

6. Reboot the target and re-verify post-boot.
   ```bash
   sudo -r sysadm_r -t sysadm_t systemctl reboot
   ```
   Expected outcome: the operator re-establishes a `staff_u`-confined login after the reboot and re-runs the verify pair from Step 5. Both contexts exit `0`, every `SKIP` from the `staff_t` pass reads `OK` under `sysadm_t`, and the host has reached the role's documented end-state on a cold boot path. Apply-time verify cannot substitute for reboot-time verify because some systemd directives only exercise their full effect on a cold start.

## Recovery

R1 — Roll back a systemd drop-in. Remove the drop-in file under `/etc/systemd/system/<unit>.d/99-*.conf`, run `sudo -r sysadm_r -t sysadm_t systemctl daemon-reload` followed by `sudo -r sysadm_r -t sysadm_t systemctl restart <unit>`, then re-run the role's `verify.sh`. The directives drop back to their pre-apply values and the verify lines that depended on the drop-in revert to their pre-apply state.

R2 — Roll back a SELinux custom CIL module. `sudo -r sysadm_r -t sysadm_t semodule -X 400 -r <module_name>` removes a priority-400 module that the role installed; the role's README `## Variables` section names the module shipped (if any) and the priority used. The coarser host-wide brake is `sudo -r sysadm_r -t sysadm_t setenforce 0`, which logs denials without enforcing them; `setenforce 1` re-enables enforcement.

R3 — Recover from an unbootable host. If a drop-in or CIL module the role installed prevents the host from completing boot, follow [Recover from boot failure](recover-from-boot-failure.md).

If the host fails to boot after applying changes, follow [Recover from boot failure](recover-from-boot-failure.md).
