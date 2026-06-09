<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Metrics

This document fixes the exact computation, the tool invocation, and the pass
threshold for each metric summarised in the metric table of
[the test concept](test-concept.md). Every metric is emitted per run and recorded under
`reports/`, split between the run-state ledger and the append-only audit log as the
concept's run-state model prescribes. The suite overview and the place of this document
among the five is in `README.md`; the concrete tooling host is
[the test environment](test-environment.md).

## Baseline, direction, and recording

Six of the eight metrics are scored against a pre-hardening baseline captured at run
entry, before any role is applied. The baseline capture is the `probe.sh` inventory plus
the functional smoketests and the three security scores taken on the unhardened managed
node. Establishing it is described in
[Establish a functional smoketest baseline](../docs/explanation/smoketest-baseline.md).
Without the baseline, an innocent platform failure or a low stock score reads as a
hardening regression, which inverts the result.

Each metric is written twice. The current value lands in the machine-readable run-state
ledger, which a restarted run reads to resume from the last clean checkpoint. The raw
command, its exit code, and the captured output land in the append-only audit log for
traceability. The ledger holds the resolved value only; the audit log holds the history
and is never replayed into the working context on restart.

The direction column below repeats the concept's: *higher* means a larger value is
better, *lower* means a smaller value is better, *binary* means pass or fail.

## OpenSCAP score — higher

The fraction of the selected profile's rules that pass, as a percentage.

Computation: `score = passed / (passed + failed) * 100`, counting only rules that return
`pass` or `fail`. Rules that return `notapplicable`, `notchecked`, or `informational` are
excluded from both the numerator and the denominator, so a rule the virtual machine
cannot evaluate neither helps nor hurts the score. The `oscap`-reported default XCCDF
score is recorded alongside this explicit ratio; the explicit ratio is the metric of
record because its denominator is stated.

Tool invocation, against the Fedora datastream shipped by the `scap-security-guide`
package, evaluated with the `openscap-scanner` `oscap` tool:

```bash
# List the profiles the datastream offers, then pin one in the harness config.
oscap info /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml

# Evaluate. oscap exits 0 when all rules pass and 2 when any rule fails; both are
# expected outcomes, so the harness treats only exit code 1 (tool error) as a defect.
oscap xccdf eval \
  --profile "${OSCAP_PROFILE}" \
  --results-arf "reports/${RUN_ID}/oscap-arf.xml" \
  --report "reports/${RUN_ID}/oscap-report.html" \
  /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml || [[ $? -eq 2 ]]
```

`OSCAP_PROFILE` is a tunable selected from the `oscap info` output; the CIS-aligned or
OSPP profile present in the Fedora datastream is the intended choice, consistent with the
CIS Benchmark alignment stated in [the test concept](test-concept.md). The `passed` and
`failed` counts come from the result-rule entries in the ARF file.

Threshold: the hardened score must meet or exceed the pre-hardening baseline score. A
score below baseline is a regression and fails the run.

## Lynis hardening index — higher

The aggregate hardening index Lynis computes, an integer from 0 to 100.

Computation: read the `hardening_index=` field from the Lynis report data file. The index
is Lynis's own weighted aggregate of its tests; the suite does not recompute it, it
records it and diffs it against baseline. The `warning[]` and `suggestion[]` counts from
the same file are recorded as context, not as gates.

Tool invocation, from the `lynis` package, run non-interactively as root:

```bash
lynis audit system --quick --no-colors
# Machine-readable result, including: hardening_index=<0..100>
grep '^hardening_index=' /var/log/lynis-report.dat
```

Threshold: the hardened index must meet or exceed the baseline index taken on the same
image. A drop is a regression and fails the run.

## Unit exposure — lower

The per-unit security exposure that `systemd-analyze security` assigns, a number from
0.0 to 10.0, recorded before and after hardening for each unit a topic hardens.

Computation: for every hardened unit, record the exposure before applying the topic and
after. The metric passes when, for every hardened unit, the after value is less than or
equal to the before value; a unit whose exposure rose is a regression. The expected
direction is a clear drop, because the namespace and process-restriction drop-ins exist
to lower exposure; a flat or rising number signals that the drop-ins did not take effect.

Tool invocation:

```bash
# Whole-system overview, all units ranked by exposure.
systemd-analyze security --no-pager

# Single unit; the headline figure is in:
#   Overall exposure level for <unit>: <0.0..10.0> <PREDICATE>
systemd-analyze security "${UNIT}" --no-pager
```

Threshold: per hardened unit, after exposure no greater than before exposure. Any hardened
unit that ends with a higher exposure than it started fails the run.

## Idempotence rate — higher

The share of scenarios whose second converge changes zero tasks.

Computation: `rate = idempotent_scenarios / total_scenarios`, where a scenario is
idempotent when Molecule's idempotence action — a second converge that must report no
changed tasks — exits clean.

Tool invocation, per scenario:

```bash
# Within a scenario directory; exits non-zero if the second converge changes any task.
molecule idempotence
```

Threshold: the rate must be 1.0. A single non-idempotent scenario fails the run, because
a role that reports a change on re-application is not at a stable end state. This matches
the idempotence clause in the exit criteria of [the test concept](test-concept.md).

## Coverage — higher

The fraction of a topic's declared end-state checks that the cloud environment actually
exercised.

Computation: `coverage = executed_checks / declared_checks`. The declared checks are the
stable named lines a role's `verify.sh` ships — the machine encoding of the
`## Verification` section of the topic's Reference article, which is the oracle named in
[the test concept](test-concept.md). A check counts as executed when it reaches a real
`OK` or drift verdict in at least one of the two contexts; the expected
`SKIP … needs sysadm_t` line in the `staff_t` pass that flips to `OK` under the role
switch counts as executed, because it does run in the role-switched pass. A check that
cannot run at all on the environment — a liveness check for a daemon a virtual machine
does not host, a `runtime_domain` check with no live session — counts as not executed and
lowers coverage.

Coverage is therefore a measurement of how much of the declared end state the environment
proved, and the [topic test matrix](topic-test-matrix.md) class is the expected-coverage
map: `Full` topics are expected at full coverage, `Full (presence)` and `Session` topics
are expected below full until the session tier runs, and `HW-gap` topics are expected
below full on any virtual machine. Coverage is tracked against the class expectation
rather than gated at a flat 1.0, so an honestly-deferred check is not scored as a failure.

Tool invocation: the harness counts the named lines emitted across both `verify.sh`
passes and divides by the role's declared line set; there is no separate external tool.

Threshold: coverage must meet the expected coverage for the topic's matrix class. A
`Full` topic below full coverage indicates a check that should have run did not, and is
investigated; a `HW-gap` topic below full coverage is expected and is recorded, not
failed.

## Pass/fail rate — higher

The share of scenarios that pass over the scenarios run.

Computation: `rate = passing_scenarios / total_scenarios`. A scenario passes only when it
satisfies every exit-criterion clause in [the test concept](test-concept.md): every
`verify.sh` exits 0 in both contexts, idempotence holds, boot-survival holds for the
system tier, the three security scores meet or exceed baseline, no unexpected AVC is
recorded and each negative test produces its expected denial, and the functional
smoketest delta stays within the baseline innocent-failure set.

Tool invocation: the harness ledger aggregates the per-scenario verdicts; there is no
separate external tool.

Threshold: the rate must be 1.0 for the selected run scope. A single failing scenario
fails the run.

## Boot-survival — binary

Whether the cumulative hardened host returns from a real reboot to a fully booted,
service-complete state. Measured only at the system tier, which is the only level that
performs a real layered boot.

Computation: after the reboot, the harness must re-establish the connection within a
timeout, and `systemctl is-system-running` must report `running`. A `degraded` result is a
pass only when every degraded unit is already in the pre-approved baseline degraded set;
a degraded unit outside that set, or a host that never returns, is a boot-survival
failure recorded as a regression.

Tool invocation:

```bash
# Trigger the reboot, wait for the node to come back, then assert the system state.
# A host that does not return within the timeout is a boot-survival failure.
systemctl reboot
# (harness waits for reconnection, then on the node:)
systemctl is-system-running --wait
```

Threshold: binary pass. The host returns and `is-system-running` is `running`, or
`degraded` with every degraded unit in the baseline set. The pre-reboot snapshot from
[the test environment](test-environment.md) is the rollback handle when this fails;
rolling it back is an operational action, not a recovery test, because recovery-procedure
testing is out of scope.

## Regression delta — lower

The number of functional failures introduced by hardening, beyond the failures already
present before hardening.

Computation: `delta = observed_failures - baseline_innocent_failures`. The functional
smoketests are run on the hardened host and the failure count is taken; the count of
failures already present in the pre-hardening baseline — the innocent platform failures
such as a storage power-management capability the virtual hardware does not implement —
is subtracted. A delta of zero or less means hardening introduced no new functional
failure; a positive delta is a regression.

Tool invocation: the smoketest set is run twice over a run's life — once at entry for the
baseline, once after hardening — and the two failure sets are diffed. The diff, not the
raw post-hardening count, is the metric, which is the whole purpose of capturing the
baseline described in
[Establish a functional smoketest baseline](../docs/explanation/smoketest-baseline.md).

Threshold: the delta must be zero or negative. Any new failure not present in the baseline
is a regression and fails the run.

## Aggregation and the run verdict

A run's verdict is not an average of the eight metrics; it is the conjunction of the
threshold clauses above, which is the same conjunction the exit criteria state in
[the test concept](test-concept.md). A run passes only when the pass/fail rate is 1.0,
idempotence is 1.0, boot-survival holds at the system tier, the three security scores
hold at or above baseline, the regression delta is zero or negative, and coverage meets
each topic's class expectation. The OpenSCAP, Lynis, and unit-exposure numbers are also
reported as trend values across runs, so a slow erosion of a score that still clears
baseline is visible before it becomes a regression.
