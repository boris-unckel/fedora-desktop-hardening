<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Multi-stage privilege-drop and SystemCallFilter carve-outs

## The trap

A daemon that performs its own internal privilege drop after `ExecStart=` — calling some subset of `setgroups(2)`, `setresuid(2)` / `setresgid(2)` / `setuid(2)` / `setgid(2)` / `setreuid(2)` / `setregid(2)`, then `capset(2)` for fine-grained capability reduction, optionally followed by `setpriority(2)` or `sched_setscheduler(2)` for real-time-priority adjustment — hits a multi-layer denial wall when run under a systemd unit that combines an aggressive subtractive `SystemCallFilter=~@privileged @resources` group with a constrained `CapabilityBoundingSet=` and `NoNewPrivileges=yes`. The daemon either dies with `SIGSYS` (status `31/SYS`) when seccomp denies the syscall, or returns `EPERM` from the syscall when the kernel's capability check blocks the privilege change. The first failure mode is loud and lands an audit-subsystem record. The second is silent in the typical case: the daemon logs the `EPERM` to its own log channel, continues running with reduced privileges that do not match its design intent, and the privilege-drop invariant is broken without a unit-failure signal.

A single positive `SystemCallFilter=` line covering only the set-id family is not sufficient. The privilege drop is a multi-stage pipeline, and each stage faces its own subset of the three layers — seccomp, capability bounding set, and the `no_new_privs` permanence invariant. A correct mitigation is additive across all three layers and reflects the stage ordering of the daemon's drop sequence.

## Why it happens

Three kernel-level layers contribute, and the failure mode depends on which layer denies first.

**Layer A — the seccomp subtractive group.** The `~@privileged` group strips the privilege-related syscalls from the allowlist: `setgroups`, `setresuid`, `setresgid`, `capset`, `capget`, and the rest. The `~@resources` group strips the resource-control syscalls: `setpriority`, `sched_setscheduler`, and the rest. systemd's directive composition rule for `SystemCallFilter=` is multi-line additive — a positive line later in the unit re-adds syscalls that an earlier subtractive line stripped. Without a positive carve-out, the daemon's first privilege-drop syscall is denied at the seccomp layer, the kernel sends `SIGSYS`, and the kernel audit subsystem records a SECCOMP message naming the killed syscall.

**Layer B — capability bounding.** Even when the seccomp layer permits the syscall, the kernel's capability check denies the call with `EPERM` if the required capability is not present in the bounding set at the time of the call. The set-id family requires `CAP_SETUID` and `CAP_SETGID`; `capset(2)` requires `CAP_SETPCAP`. `NoNewPrivileges=yes` makes the bounding-set reduction permanent — a daemon that has already lost a capability cannot regain it later, regardless of which syscalls it can call. The capability layer typically does not kill the daemon; it returns `EPERM` from the syscall, and a daemon that does not check the return value continues running with the privilege drop only partially applied.

**Layer C — post-UID-switch syscalls.** After the daemon successfully calls the set-id family and the kernel switches its effective UID, subsequent syscalls face the seccomp subtractive group again. `capset(2)` is the typical offender: a daemon that uses a libcap-style fine-grained reduction calls `capset(2)` *after* the UID switch, and any `~@privileged` strip kills the daemon with `SIGSYS` from a non-root UID. The audit record's `uid=` field is then non-zero, distinguishing this stage from a Layer-A denial.

The three layers compose a denial wall whose surface depends on the daemon's drop sequence. A daemon that calls only the set-id family and never `capset(2)` exhibits Layers A and B; a daemon that uses libcap-style fine-grained reduction exhibits all three; a daemon that bumps real-time priority after the UID switch adds a Layer-C variant for `setpriority(2)` and `sched_setscheduler(2)`.

## How to detect it

The boot-time signal is a SECCOMP audit record collected by the kernel audit subsystem. The `uid=` field localises the failed drop-stage:

```text
type=SECCOMP msg=... auid=... uid=0 gid=0 ses=...
  comm="<daemon>" exe="..." sig=31 syscall=<n>
```

`uid=0 gid=0` indicates the killer fired before the privilege drop completed. Either the set-id family is blocked at Layer A, or the daemon retries after a Layer-B `EPERM` until seccomp kills it. `uid=N` for `N != 0` indicates the killer fired after the UID switch — the set-id family succeeded, and the killer is in Layer C (typically `capset(2)`, occasionally `setpriority(2)` or `sched_setscheduler(2)`).

The full diagnosis loop:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot
```

extracts the relevant SECCOMP records since boot. For each record, the operator reads `syscall=<n>`, `uid=`, `gid=`, and `comm=` and maps the syscall number to a name with `ausyscall <n>`. The pair (`syscall name`, `uid value`) localizes the failed drop-stage:

- a `set{groups,gid,uid,resgid,resuid,regid,reuid}` syscall with `uid=0` is a Layer-A denial of the privilege drop's first stage;
- a `capset` syscall with `uid=N` for `N != 0` is a Layer-C denial after the UID switch;
- a non-empty record set with no obvious match against the daemon's known drop sequence is a signal that the daemon has changed its drop pipeline (a package update, typically) and the carve-out needs revision.

The Layer-B `EPERM` failure mode does not produce a SECCOMP record. The diagnostic shape is instead a daemon log line such as `Operation not permitted` from a `setresuid` or `capset` call, with the unit still active (`systemctl is-active` returns `active`) and the live UID of the running PID not matching the daemon's intended steady state. The detector for this shape is a live UID and GID probe that compares the running PID's `/proc/<pid>/status` against the documented post-drop UID and GID.

## How to mitigate it

Three additive layers, applied in three separate directive lines.

**Mitigation A — positive `SystemCallFilter=` for the set-id family.** A second `SystemCallFilter=` line listing the seven members of the `set{groups,gid,uid,resgid,resuid,regid,reuid}` family is additive on top of the subtractive group. After the subtractive group has stripped the privilege-related syscalls from the allowlist, the positive line re-adds the seven members:

```ini
SystemCallFilter=setgroups setgid setuid setresgid setresuid setregid setreuid
```

**Mitigation B — additive `CapabilityBoundingSet=` line.** A second `CapabilityBoundingSet=` line listing `CAP_SETUID` and `CAP_SETGID` adds those two capabilities to the bounding set without removing any capability from the first capability-bounding line. This second line is required even if the seccomp layer permits the syscall, because the `no_new_privs` invariant makes capability reductions permanent:

```ini
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
```

**Mitigation C — positive `SystemCallFilter=` for `capset` and `capget`.** A third `SystemCallFilter=` line listing `capset` and `capget` is additive on top of both prior `SystemCallFilter=` lines and permits the post-UID-switch fine-grained capability reduction:

```ini
SystemCallFilter=capset capget
```

The composite of Mitigations A, B, and C is the minimum set for a daemon that performs a set-id-then-`capset` pipeline. A daemon that bumps real-time priority after the UID switch needs `setpriority` and `sched_setscheduler` carve-outs as well; both compose additively on a fourth `SystemCallFilter=` line or — for compactness — extend the third line.

Edge cases the mitigation does not cover:

- **Daemons that have a `User=` and `Group=` directive in the vendor unit.** systemd performs the privilege drop in PID 1's privileged context before `ExecStart=` runs, and the daemon's own `SystemCallFilter=` does not apply to the drop sequence. Such daemons do not exhibit this trap. The mitigation is *not* applicable: adding the carve-outs to a unit with `User=` and `Group=` is operator error, because the carve-outs are only meaningful when the daemon performs its own drop.
- **Daemons whose privilege drop adds calls beyond the set-id and `capset` family.** Some daemons call `prctl(PR_CAPBSET_DROP)`, `unshare(2)`, or `clone3(2)` as part of a more elaborate drop. These calls live in different syscall classes; the carve-out must be extended on a syscall-by-syscall basis after a `ausearch -m seccomp` reading.
- **Daemons that use libseccomp internally.** A daemon that imposes its own seccomp filter on top of systemd's `SystemCallFilter=` may strip syscalls again after the `execve(2)`. The systemd-level mitigation covers the systemd layer only; the daemon-internal seccomp layer is upstream-managed and is handled per-daemon when it interferes with the privilege-drop pipeline.

The trap is also not the same as the related NNP-transition trap, which fires at `execve(2)` time when the kernel's `init_t → <svc>_t : process2 nnp_transition` rule is missing. The two traps are orthogonal: a daemon can hit the NNP-transition denial at boot — failing to execute at all — without ever entering the privilege-drop pipeline, and a daemon can have a working transition rule but still hit the multi-stage privilege-drop denial inside `ExecStart=`. See [NNP and SELinux transition trap](./nnp-selinux-transition-trap.md) for the boundary distinction.

## See also

- [NNP and SELinux transition trap](./nnp-selinux-transition-trap.md) — The orthogonal trap class. The `no_new_privs` permanence invariant is shared with this trap (it is what makes the second `CapabilityBoundingSet=` line load-bearing under NNP), but the NNP-transition trap fires at `execve(2)` and the multi-stage privilege-drop trap fires inside `ExecStart=`.
- [The kill-0 cross-user EPERM trap](kill-0-cross-user-eperm.md) — A verify-discipline trap that compounds with the multi-stage privilege-drop class: a daemon whose post-drop steady-state UID is not the operator's UID is silently mis-classified as dead by a `kill -0 $pid` liveness probe run from a less-privileged shell, because the kernel returns `EPERM` rather than `ESRCH`. The `[ -d /proc/${main_pid} ]` form is ownership-independent and is the verify pattern used across the topic-tier articles.
