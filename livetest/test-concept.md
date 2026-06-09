<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Live-test concept

This is the master test concept for verifying the hardening roles under `ansible/`
against ephemeral cloud virtual machines. It defines the scope, the test levels,
the quality characteristics under test, the entry and exit criteria, the product-risk
model, the metric catalogue, and the run-state model that makes a run restartable
after an interruption.

The concept is provider-neutral. It assumes a KVM-based cloud provider that offers
hourly or per-second billing, pre-boot snapshots, an out-of-band serial or VNC
console, and a private network between instances. The concrete provisioning
environment and its driver live in `test-environment.md`; the per-topic
cloud-testability classification and risk ranking live in `topic-test-matrix.md`;
exact metric computation lives in `metrics.md`.

The plan runs in three lifecycle phases. Phase 0 authors and lints these documents
locally, before any provider account exists. Phase 1 stands up an isolated provider
project with a scoped credential and a spending alert. Phase 2 provisions and runs,
under a provision-snapshot-test-destroy discipline that bounds cost and supports
restart.

## Relation to the documentation tree

Three existing artifacts define what is tested; the concept adds orchestration and
scoring on top of them, and nothing to the end-state definition itself.

- The Ansible roles under `ansible/roles/` are the system under test. The four
  Foundation roles and the 27 topic roles apply the hardened end state.
- Each role ships `files/probe.sh` (read-only state inventory) and `files/verify.sh`
  (computes expected versus observed and exits non-zero on drift). These are the
  executable test cases. The test basis and the test procedures already exist in the
  tree; this concept orchestrates them across real hosts.
- The Reference articles under `../docs/reference/` declare the expected end state.
  They are the test oracle. A topic's `verify.sh` is the machine encoding of its
  Reference article's `## Verification` section.

The guided application path that the scenarios automate is the operator tutorial
[Bootstrap a hardened host](../docs/tutorials/bootstrap-hardened-host.md); its
condensed task forms are [Apply the Foundation tier](../docs/how-to/apply-foundation.md)
and [Apply one Topic role](../docs/how-to/apply-topic.md).

## Scope

### In scope

- Application of the Foundation tier and the cloud-testable topic roles to ephemeral
  cloud virtual machines, at two test levels (component and system).
- Three quality characteristics: functional regression, control-presence, and
  control-effectiveness. See `## Quality characteristics under test`.
- Boot-survival of the cumulative hardened host after a real reboot.
- Security scoring of the hardened host against a pre-hardening baseline, using
  OpenSCAP, Lynis, and per-unit `systemd-analyze security` exposure.

### Out of scope

- Recovery-procedure testing. Deliberately inducing a boot failure to rehearse the
  recovery runbook is not a test objective. The recovery procedure is an operator
  task documented in [Recover from boot failure](../docs/how-to/recover-from-boot-failure.md).
  The objective here is the hardened end state and whether it survives a reboot, not
  disaster recovery.
- Offensive and network-based testing. There is no port scanning, no exploit or
  attack-chain construction, and no traffic aimed at the host from outside it. Every
  check is host-local. See `## Security boundaries`.
- Hardware-bound functional effects that a virtual machine cannot reproduce: real
  SATA-SMART over an ATA pass-through, dual-GPU handover, physical removable-media
  insertion, and graphical-boot rendering. For the affected topics the concept tests
  control-presence only; functional effectiveness is deferred off-cloud. The affected
  topics are enumerated in `topic-test-matrix.md`.
- Visual or pixel-level assertions about a rendered user interface. These are not a
  hardening control and are not part of the suite.

## Test basis and oracle

The test basis is the set of Reference articles plus each role's `defaults/main.yml`
and the verify-script contract recorded in the style guide. The oracle is the
role-shipped `verify.sh`, which exits `0` when observed state matches the declared
end state, `1` on drift, and `2` on invocation error.

A verify script is run in two SELinux contexts, and the test harness must run both:

- A plain login context (`staff_t`). Checks that read the policy store, the audit
  store, or the system journal report `SKIP … needs sysadm_t` here.
- A role-switched context (`sudo -r sysadm_r -t sysadm_t`). The `SKIP` lines flip to
  `OK`. A line that stays `SKIP` under the role switch indicates the switch did not
  take, not a clean result.

A single-context run under-tests, because the policy-store and audit checks never
execute. The `probe.sh` inventory is informational and feeds the pre-hardening
baseline; it never gates a result.

## Quality characteristics under test

The concept verifies three characteristics. All three are defensive: they confirm
that controls are present and that forbidden operations fail.

| Characteristic | Question answered | Method |
|---|---|---|
| Functional regression | Do the services still work after hardening? | Functional smoketests, diffed against a pre-hardening baseline so innocent platform failures are not counted as regressions. |
| Control-presence | Is the hardening actually applied? | `verify.sh` in both contexts: drop-ins merged (`systemctl cat`, `systemctl show`), CIL module loaded (`semodule -l`), `NoNewPrivileges` set, runtime domain correct; plus OpenSCAP rule results. |
| Control-effectiveness | Does the control actually deny the forbidden operation? | Negative tests: a confined or unprivileged subject attempts a forbidden operation; the test asserts the operation fails with `EACCES` or that the expected SELinux denial is recorded. Scored before and after hardening. |

The pre-hardening baseline that the functional-regression diff depends on is
described in [Establish a functional smoketest baseline](../docs/explanation/smoketest-baseline.md).

## Test levels and the two-tier scenario architecture

Two scenario tiers mirror the Foundation and Topic tier model of the tree, with a
third, session-effectiveness tier phased in after the system tier is green. The
harness is Molecule with a delegated driver that provisions real cloud virtual
machines; containers cannot exercise the SELinux-enforcing, PID-1, real-reboot
behaviour that the system under test depends on.

### Component tier

A per-role scenario lives in the role at `ansible/roles/<role>/molecule/default/`,
the conventional Molecule home for a single-role scenario.

- `prepare.yml` applies the Foundation tier in fixed order: `foundation_umask`,
  `foundation_sudo_roles`, `foundation_selinux_cil_bootstrap`,
  `foundation_audit_logging_baseline`. Applying `foundation_sudo_roles` changes the
  SELinux login mapping, so the harness resets the connection afterward to pick up the
  new context, the same way the tutorial requires a fresh login.
- `converge.yml` applies the single topic under test.
- Molecule then runs its idempotence check (a second converge that must report zero
  changed tasks), followed by `verify.sh` in both contexts.

`prepare.yml` makes the Foundation explicit rather than relying on each topic role's
`meta` dependencies alone, because a converge-only scenario on a host without the
Foundation layer would test a topic against an absent baseline. This is ISTQB
component testing: one role isolated against a known-good substrate.

### System tier

One cumulative virtual machine carries a central scenario at `ansible/molecule/system/`,
the Molecule-standard location for an integration scenario that spans multiple roles.

- The Foundation tier is applied in fixed order, then the cloud-testable topics are
  layered in bootstrap order, then the host performs a real reboot.
- Boot-survival is asserted: the host must return to a fully booted, service-complete
  state. A host that does not return is a test failure, recorded as a regression.
- The full security score is taken: OpenSCAP, Lynis, and per-unit
  `systemd-analyze security`, each compared against the pre-hardening baseline.

This is the only level at which cross-topic interaction and a real layered boot are
exercised. It is the operational acceptance test (ISTQB system and acceptance
testing). Not every topic runs here: session-dependent and hardware-gap topics are
handled per `topic-test-matrix.md`.

### Session-effectiveness tier

This tier is built after the system tier is green. It is fully automated and requires
no human interaction.

- A headless session substrate is brought up on the managed node: a virtual display
  (software-rendered), a session bus, and a lingering session for the `staff_u`-mapped
  user. No physical GPU and no operator-driven console are involved.
- The session-dependent topics are exercised for control-effectiveness: the harness
  launches the target application or process, reads `/proc/<pid>/attr/current` to
  confirm the SELinux domain transition, and inspects the audit store for AVC
  cleanliness or for the expected denial in a negative test.
- No pixel-level or visual assertion is made; the observable is kernel and audit
  state, not rendered output.

The session substrate is the highest-effort and highest-variance part of the harness,
so this tier sits behind a readiness gate and never blocks the daemon and boot
acceptance covered by the system tier.

## Regression selection

Re-test scope follows ISTQB impact analysis, which bounds the cost of any change.

- A change to a Foundation role runs the system tier, because the Foundation is the
  maximum blast radius and every topic depends on it.
- A change to a single topic runs that topic's component scenario.
- A change to the session substrate runs the session-effectiveness tier.

## Entry and exit criteria

### Entry criteria

- The role tree is present in the checkout and the Foundation order is resolvable.
- The provider is reachable, the project is isolated, and a spending alert is armed.
- The managed node is provisioned and a pre-hardening baseline is captured: the
  `probe.sh` inventory plus the functional smoketests, so innocent platform failures
  are separated from hardening-induced regressions.
- A pre-reboot snapshot is taken before any reboot that carries boot-failure risk.

### Exit criteria and pass/fail

A scenario passes when all of the following hold.

- Every `verify.sh` exits `0` in both the `staff_t` and the `sysadm_t` context.
- Molecule reports idempotence: the second converge changes zero tasks.
- Boot-survival is true, for the system tier.
- The OpenSCAP, Lynis, and `systemd-analyze` scores meet or exceed the pre-hardening
  baseline, with no regression.
- No unexpected AVC is recorded, and each negative test produces its expected denial.
- The functional smoketest delta stays within the baseline innocent-failure set.

A scenario fails on any verify drift (`exit 1`), idempotence violation, boot-survival
failure, score regression, unexpected denial, or a missing expected denial. A verify
invocation error (`exit 2`) is an environment defect: it is retried and is not scored
as drift.

## Product risk and prioritization

Topic selection and ordering follow risk-based testing. Each topic carries a product-
risk rank derived from likelihood and impact. The highest-impact class is the boot-
failure class: an init-time service that receives a `NoNewPrivileges` drop-in whose
target domain lacks a stock `nnp_transition` allow rule, which can prevent the host
from booting. Topics in this class run early and always in the system tier. The full
per-topic risk rank and cloud-testability class are tabulated in `topic-test-matrix.md`.

## Metrics

Each run emits the following metrics. The direction column states which way is better.
Exact computation, tool invocation, and thresholds live in `metrics.md`.

| Metric | Definition | Source | Direction |
|---|---|---|---|
| OpenSCAP score | Percentage of selected profile rules that pass | `oscap` with `scap-security-guide` | higher |
| Lynis hardening index | Aggregate hardening index | `lynis audit system` | higher |
| Unit exposure | Per-unit security exposure, 0 to 10, before and after | `systemd-analyze security` | lower |
| Idempotence rate | Share of scenarios whose second converge changes zero tasks | Molecule | higher |
| Coverage | Verify checks executed over declared end-state checks | Harness ledger | higher |
| Pass/fail rate | Passing scenarios over total scenarios | Harness ledger | higher |
| Boot-survival | Whether the cumulative host returns from a real reboot | System tier | binary pass |
| Regression delta | Observed failures minus baseline innocent failures | Baseline diff | lower |

## Test environment

The topology has three node roles, described provider-neutrally here and concretely in
`test-environment.md`.

- The operator workstation is a plain SSH terminal. It is neither a control node nor a
  managed node, and stays outside the blast radius.
- The control node is a cloud virtual machine that runs `ansible-playbook`, holds the
  inventory and keys, and acts as the bastion and jump host. It is deliberately not
  hardened, so it stays stable while the targets change underneath it.
- One or two managed nodes are the hardened targets. They carry boot-failure risk and
  are reachable only through the control node over the private network.

An out-of-band serial or VNC console on the managed nodes is mandatory. A
misconfiguration that breaks `sshd` or races a runtime path removes network login
entirely, and the console is then the only channel left. The runtime-path class of
break is described in [ReadWritePaths runtime race](../docs/explanation/readwritepaths-runtime-race.md).

## Run-state, restartability, and drift control

A run is a sequence of checkpointed steps per managed node: provision, snapshot,
converge, verify, score, destroy. A checkpoint is recorded after each step completes.
Two records are kept, deliberately separate.

- A run-state ledger is machine-readable, small, and holds current state only: the
  last clean checkpoint per node and per scenario. On restart after a remote
  interruption (a provider or network fault) or a local one (a host crash or a token
  limit), the driver reads the ledger and resumes from the last clean checkpoint
  instead of repeating completed work.
- An append-only audit log is chronological and holds every command, timestamp, exit
  code, and provider API call, for traceability. It is write-only during a run and is
  never replayed into the working context on restart.

The separation is the load-bearing part of restart discipline: a resumed run consumes
resolved current state from the ledger, not the full history from the audit log, so it
is not burdened with issues that were already settled before the interruption. Both
records live under `reports/` per run.

The pre-reboot snapshot is the rollback handle if a risky reboot does not return.
Rolling a snapshot back lets the run continue from a known-good checkpoint; it is an
operational action, not a scripted test case, which is consistent with recovery-
procedure testing being out of scope. Managed nodes are ephemeral: the destroy step
runs on completion and on abort, and a provider spending alert bounds exposure.

## Security boundaries

The concept is defensive verification only. Its test types are control-presence and
control-effectiveness, where control-effectiveness is a negative test that asserts a
forbidden operation fails or that an expected SELinux denial is logged. There is no
offensive penetration testing, no exploit or attack-chain construction, and no
development of malicious tooling.

The provider penetration-test approval regime is not triggered. Every check is
host-local: `oscap`, `systemctl show`, audit-store inspection, and local unprivileged
read attempts. There is no network attack traffic and no scanning of provider
infrastructure or of other tenants. Network-based testing from outside the host is out
of scope.

## Standards alignment

- ISO/IEC/IEEE 29119, notably part 3, frames the structure of the plan, the test
  design, and the run reports.
- The ISTQB test process and risk-based testing supply the level and type vocabulary
  and the impact-analysis regression rule. en-US ISTQB glossary terms are used
  throughout.
- CIS Benchmarks inform the control set that the OpenSCAP profile scores against.

## Referenced material

Sibling documents in this directory, authored separately, carry the detail this master
concept summarizes: `test-environment.md` for the concrete provider and the delegated
driver, `topic-test-matrix.md` for the per-topic cloud-testability and risk table,
`metrics.md` for metric computation, and the per-run artifacts under `reports/`.
