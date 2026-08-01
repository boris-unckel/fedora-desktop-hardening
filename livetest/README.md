<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Live-test suite

This directory holds the live-test suite for the hardening roles. It defines how the
roles under `../ansible/` are provisioned onto ephemeral cloud virtual machines, applied,
verified, scored against a pre-hardening baseline, and recycled, under a discipline that
keeps the cost bounded and a run restartable after an interruption.

The suite is built in three lifecycle phases: Phase 0 authors and lints these documents;
Phase 1 stands up an isolated provider project with a scoped credential; Phase 2 builds the
Molecule scenarios and runs them. Phase 2 is executed through both cloud tiers; the session
tier remains.

## Status

The current run record — environment realities, every defect found and its fix, the
per-topic disposition matrix, and the captured scores — is
[reports/full-run-2026-08.md](reports/full-run-2026-08.md); the preceding one is
[reports/component-tier-first-run.md](reports/component-tier-first-run.md). As of
2026-08-01:

- **Component tier: 23 of 23 green.** Every role that ships a component scenario passes its
  full Molecule scenario from the baked base snapshot: create, foundation prepare, converge,
  idempotence with zero changed tasks, verify in both SELinux contexts (`staff_t` and
  `sysadm_t`), destroy. The two former deferrals are resolved — `cups` was a real gap in its
  own CIL module, and `integrity_monitoring` (which replaced the `aide` topic) had never
  completed a converge at all. The four session topics (`keepassxc`, `mozilla_firefox`,
  `mozilla_thunderbird`, `flatpak_portal_cache`) ship no component scenario and stay outside
  cloud scope.
- **System tier: fully green over 22 topics.** Cumulative converge of the Foundation plus the
  22 cloud-testable topics, a second converge with zero changed tasks, a real reboot with
  boot-survival (`is-system-running=running`), and post-reboot per-topic persistence clean in
  both SELinux contexts for every one of the 22. `staff_wayland_memfd` is the one
  component-tested topic held out of the system tier, by design: it needs a Wayland session.
- **Security scores captured (pre → post hardening):** OpenSCAP (`ssg-fedora-ds`) pass
  count 184 → 201; Lynis hardening index 67 → 75; `systemd-analyze security` exposure
  drops for the hardened units, e.g. plymouth-start 9.5 → 1.9, alsa-state 9.6 → 2.6,
  NetworkManager 7.8 → 4.9. `cups.service` is scored from this run on and has no
  pre-hardening figure yet.
- **Not yet run:** the session tier (the four session topics plus the Wayland-session
  effectiveness branch of `staff_wayland_memfd`).

Both tiers have now earned their place. The system tier caught a boot-failure-class defect
the component tier structurally cannot see (plymouthd seccomp-SIGSYS-killed by its hardening
drop-in on the first hardened boot, in the previous run). In this run it caught a second
class the component tier had been blind to: a topic whose verify reported privileged-only
reads as drift, hidden by the only component scenario that ran a single SELinux context.

Scenario plumbing lives in the role tree: shared `create`/`destroy` and the
substrate-and-foundation `prepare` under `../ansible/molecule/shared/`, the system-tier
scenario under `../ansible/molecule/system/`, and a component scenario per cloud-testable
topic role (23 of the 27) at `../ansible/roles/<role>/molecule/default/`. The system tier's
topic list lives once, in `../ansible/molecule/system/vars/system-tier-topics.yml`, and is
loaded by both its converge and its verify: the two previously held separate copies and
silently diverged, so the run applied more topics than it checked.

## Relation to the rest of the tree

The suite verifies the rest of the tree; it adds nothing to the end-state definition.

- `../ansible/` is the system under test. Four Foundation roles and 27 topic roles apply
  the hardened end state. Each role ships `files/probe.sh` (a read-only inventory) and
  `files/verify.sh` (computes expected versus observed and exits non-zero on drift); these
  are the executable test cases.
- `../docs/` is the oracle. The Reference articles under `../docs/reference/` declare the
  expected end state, and a topic's `verify.sh` is the machine encoding of its Reference
  article's `## Verification` section. The guided application path the scenarios automate
  is the tutorial [Bootstrap a hardened host](../docs/tutorials/bootstrap-hardened-host.md).

The dependency runs one way: this suite reads `../docs/` and `../ansible/`, and those
trees never reference the suite back.

## The documents

Read them in this order.

1. [The test concept](test-concept.md) is the master plan: scope, the two scenario tiers
   plus the phased session tier, the three quality characteristics, the entry and exit
   criteria, the product-risk model, the metric catalogue, and the run-state model that
   makes a run restartable. Start here.
2. [The topic test matrix](topic-test-matrix.md) classifies every role by cloud
   testability — `Full`, `Full (presence)`, `Session`, or `HW-gap` — and assigns a
   proposed product-risk priority. It decides which topics run on a virtual machine and in
   what order.
3. [The test environment](test-environment.md) makes the provider-neutral concept concrete
   against one cloud provider: the three-node topology, the Molecule delegated driver, the
   `staff_u` connection model, the out-of-band console and snapshot handling, and the
   headless session substrate.
4. [Metrics](metrics.md) fixes the exact computation, tool invocation, and pass threshold
   for each of the eight metrics the concept names.
5. [The harness README](harness/README.md) documents the committed cloud drivers under
   `harness/`.
6. This README is the index and the entry point.

## The harness

The provision-test-recycle flow runs through committed, shellcheck-clean drivers under
[`harness/`](harness/README.md): `bootstrap_infra.sh` (key, network, firewalls, control
node), `bake_base_snapshot.sh` (the desktop-like base snapshot managed nodes boot from),
`run_suite.sh` (per-topic `molecule test` from the control node, with a PASS/FAIL matrix),
`run_system.sh` (the cumulative system-tier scenario), and `teardown.sh`.

Cost policy: the control node, base snapshot, network, key, and firewalls are reusable
infrastructure and are kept between runs; managed nodes are transient and recycled per
scenario; full teardown is a manual, operator-initiated step.

## Per-run artifacts

Run artifacts live under `reports/`. The committed record is
[component-tier-first-run.md](reports/component-tier-first-run.md), the consolidated
findings log across the component-tier runs and the system tier, including the
security-scoring outputs named in [Metrics](metrics.md). The run-state model for an
in-flight run — a machine-readable ledger holding current state only, plus an append-only
audit log of every command, timestamp, and exit code — is prescribed in
[the test concept](test-concept.md).

## Scope boundary

The suite is defensive verification only: it confirms that controls are present and that
forbidden operations fail. There is no offensive or network-based testing, every check is
host-local, and recovery-procedure testing is out of scope — boot-survival is the
acceptance gate, while the recovery runbook
[Recover from boot failure](../docs/how-to/recover-from-boot-failure.md) stays a manual
operator task. The full boundary is stated in [the test concept](test-concept.md).
