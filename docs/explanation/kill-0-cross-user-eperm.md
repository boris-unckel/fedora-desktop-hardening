<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# The kill-0 cross-user EPERM trap

## The trap

A verify-script that runs from one user identity and probes a process owned by a different identity using `kill(2)` with signal zero risks reaching the wrong conclusion about whether the target process is alive. The probe is shaped as a permission test against the kernel: signal zero performs no delivery, but the kernel still evaluates whether the caller would be permitted to send a real signal to the target. When the caller is not permitted, the kernel reports the failure of the permission probe rather than the existence of the process. A verify-shell whose uid does not match the daemon's post-drop uid sits exactly in that configuration, and the script collapses two distinct kernel errors into a single failure path.

The visible symptom is a misclassification at the shell layer. The shell form `kill -0 "$pid"` returns a single non-zero exit code regardless of which kernel error fired, and the common idiom `kill -0 "$pid" 2>/dev/null && echo alive || echo dead` interprets the non-zero exit as proof that the PID is gone. A live foreign-uid process is then reported as dead. A verify-script built on this idiom answers the question "did the kernel let me probe this PID?" but advertises the answer as "is this PID alive?" — and an operator who trusts the report believes the daemon is no longer running.

## Why it happens

POSIX requires `kill(2)` to return `-1` with `errno` set to `EPERM` when the caller is not permitted to send the requested signal to the target process, and to return `-1` with `errno` set to `ESRCH` only when no process matches the PID. The two error classes are distinct at the kernel boundary: `EPERM` reports a permission failure against an existing process, `ESRCH` reports the absence of any process at the PID. Signal-zero is a permission probe — no signal is delivered — but the permission check runs in full, so the kernel can return `EPERM` for a perfectly live process when the caller's identity does not authorize the signal.

The shell form `kill -0 "$pid"` reports both error classes as a single non-zero exit code, so the idiom `kill -0 "$pid" 2>/dev/null && echo alive || echo dead` cannot distinguish a live process the caller may not signal from a PID that no longer exists. The shell's `$?` carries one bit of information — success or failure — and the underlying `errno` distinction is discarded before the script can read it. A user-level confined shell, for example a `staff_t` login probing a root-owned or daemon-uid PID under the targeted policy, sits on the wrong side of the permission check and observes only the collapsed exit code.

The same trap surfaces in `pkill -0`, `pgrep --signal 0`, and any direct caller of the `kill(2)` C-library entry with signal number zero; tools that enumerate process state and tools that synchronize with descendant processes do not share the trap, because they do not depend on signal-permission.

## How to detect it

The structural signal is a contradiction between two views of the same daemon. A verify-script reports drift — the daemon is dead, the unit's `MainPID` is unreachable, the liveness check failed — at a moment when independent evidence shows the daemon is running. The independent evidence takes one of two shapes: a journal heartbeat written after the daemon's drop pipeline completes, or a live `/proc/<pid>/status` Uid/Gid pair that matches the documented post-drop steady state. When both views point at the same PID and only the verify-script disagrees, the trap is in play.

A minimal reproduction makes the collapse explicit:

```text
# probe shell uid: <probe-shell-uid>, daemon uid: 0 (or any uid != <probe-shell-uid>)
$ MAIN_PID=$(systemctl show -p MainPID --value some-unit.service)
$ ls -d /proc/"${MAIN_PID}"
/proc/12345
$ kill -0 "${MAIN_PID}" 2>/dev/null && echo alive || echo dead
dead
# kill(2) returned -1 with errno=EPERM (permission probe denied);
# the shell form collapsed EPERM and ESRCH into a single non-zero exit.
$ kill -0 "${MAIN_PID}"; echo "rc=$?"
bash: kill: (12345) - Operation not permitted
rc=1
# stderr distinguishes EPERM from ESRCH, but only when 2>/dev/null is removed;
# a verify-script that swallows stderr loses the signal entirely.
```

## How to mitigate it

The ownership-independent replacement is `[ -d /proc/$pid ]`, which tests whether the kernel exposes a process directory for the PID; the symmetric form `[ -e /proc/$pid ]` is equivalent for this purpose. The replacement does not depend on signal-permission semantics: the `/proc` directory entry for a live PID is visible to any caller that can read `/proc`, regardless of the process's owning uid. The verify-script's exit logic is then driven by directory visibility, not by a permission probe, and the false-negative path that produced the trap is closed.

When `proc` is mounted with `hidepid=1` or `hidepid=2`, `/proc/<pid>` visibility narrows to processes whose owner shares the reading uid's group via the `gid=` mount option; under that configuration the replacement idiom no longer distinguishes a dead PID from a hidden one, and the verify-script must invoke a more-privileged probe path. The mitigation under hidepid is escalation, not idiom extension: the verify-script either runs the liveness check from a more-privileged shell (for example, by transitioning to `sysadm_t` for the probe) or accepts that user-level probing of foreign-uid daemons is not possible on that host configuration.

Stronger evidence of identity and steady-state is available without leaving `/proc`. The files `/proc/<pid>/comm`, `/proc/<pid>/status`, and `/proc/<pid>/attr/current` are similarly ownership-independent under default `proc` mount options and provide the secondary anchors that distinguish a live, correctly-running daemon from a stale or PID-reused entry: `comm` confirms the executable name, `status` exposes the live Uid and Gid that should match the post-drop steady state, and `attr/current` exposes the SELinux process context. A verify-script that needs more than presence-or-absence pairs the directory check with one or more of these reads.

The trap is specific to signal-permission probes; it does not apply to enumeration-based liveness mechanisms or to in-process synchronization mechanisms — those have their own permission semantics, distinct from `kill(2)`-with-signal-zero. A `/proc` walk or a `ps -p` enumeration depends on `proc` visibility, not on signal-permission, and a parent-shell `wait` synchronizes with a descendant whose lifecycle the parent already controls. The replacement idioms in this Pattern apply where the trap applies; they do not retrofit the parent-shell mechanisms that already side-step it.

Edge cases the mitigation does not cover:

- A `proc` mount with `hidepid=2` and a `gid=` value that does not include the verify-shell's group: `/proc/<pid>` is not exposed at all, and both the `[ -d /proc/$pid ]` form and the secondary `/proc/<pid>/comm` probe return false negatives indistinguishable from a dead process. The mitigation in that case is to invoke the probe from a more-privileged shell — for example, by elevating to a role with broader `proc` visibility — not to extend the user-level probe.
- PIDs that have just exited but whose entry is still in the kernel's reaping window: `[ -d /proc/$pid ]` may return true for a fraction of a second after the process has exited but before the parent has reaped it. A verify-script that needs strict steady-state semantics combines the directory check with a `comm` and `status` read that confirms the expected daemon name and steady-state Uid/Gid.
- PID-reuse across a daemon restart: `[ -d /proc/$pid ]` confirms that some process exists at the PID, but not that it is the same process the verify-script started with. A verify-script that loops on a long-running probe must re-read the unit's `MainPID` from systemd between iterations rather than caching a PID.
- Container or PID-namespace boundaries: a verify-script running outside a container's PID namespace observes container-internal PIDs as ephemeral or invisible. The trap class itself does not change, but the `/proc/<pid>` form is not portable across PID-namespace boundaries; the mitigation is to invoke the probe inside the namespace, not to extend it.

## See also

- [Multi-stage privilege-drop and SystemCallFilter carve-outs](./phase-b-scf-privdrop.md) — A daemon that completes its multi-stage privilege drop runs at a non-root steady-state UID; a verify-script invoked from a less-privileged shell that uses `kill -0 "$pid"` against the resulting PID is silently mis-classified as failing, because the kernel returns `EPERM` rather than `ESRCH` for the cross-uid signal-permission probe.
