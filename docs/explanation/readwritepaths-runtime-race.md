<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# ReadWritePaths runtime race

## The trap

A service drop-in or vendor unit that combines `ProtectSystem=strict` (or any of the `Protect*` family that implies a private mount-namespace) with `ReadWritePaths=/run/<svc>` fails to boot with `status=226/NAMESPACE` on a host where the daemon creates its `/run/<svc>` directory in its own startup code path rather than letting systemd create it via `RuntimeDirectory=<svc>`. The kernel boot proceeds, systemd reaches the unit, systemd executes the NAMESPACE step (the bind-mount setup that gives the daemon its private mount-namespace) before the daemon's `ExecStart=` runs, and the bind-mount of `/run/<svc>` fails because the path does not yet exist on the fresh `/run/` tmpfs. systemd retries five times — the journal records `Start request repeated too quickly` after the fifth attempt — and gives up. For login-critical daemons, the cascade reaches a non-interactive system, and recovery requires a rescue-image chroot.

The trap is not a syntactic error. The drop-in passes `systemd-analyze verify`. A manual `systemctl restart <svc>` on the same unit succeeds because the directory persists from the previous lifecycle in `/run/` (the tmpfs is not cleared between unit restarts), so the bind-mount finds its source path and namespace setup completes. Restart-verify lies: the bug is detectable only on the next actual boot or on a deliberate `systemctl stop && rm -rf /run/<svc> && systemctl start` cycle. The runtime symptom on a fresh boot is a journal record of the form `Failed to set up mount namespacing: /run/<svc>: No such file or directory` plus `Failed at step NAMESPACE` plus `status=226/NAMESPACE`.

## Why it happens

systemd's NAMESPACE step is part of unit setup and runs before `ExecStart=`. When the unit declares `ProtectSystem=strict` (or any other `Protect*` directive that requires a private mount-namespace), systemd creates a fresh mount-namespace and bind-mounts the listed paths into it. The `ReadWritePaths=` list specifies bind-mount sources that must exist on the host filesystem at the moment of the call. If a path in the list does not exist, the bind-mount returns `ENOENT` and the namespace setup aborts with exit code 226, which corresponds to the NAMESPACE step in systemd's exit-code table.

Daemons that pre-date the systemd `RuntimeDirectory=` directive — or that maintain their own runtime-directory lifecycle for portability across init systems — create `/run/<svc>` in their own code, typically with a `mkdir(2)` early in startup. On a freshly booted host the directory does not exist yet, because systemd has not had a chance to spawn the daemon. On a running host that has been through one cycle of the daemon, the directory persists in `/run/` (which is a tmpfs but is not cleared between unit restarts), and the bind-mount succeeds. The two paths diverge: a manual `systemctl restart` works; a fresh boot fails.

The class is structural rather than incidental. The systemd documentation does not warn against the combination explicitly because both directives are valid in isolation; the trap is the boundary effect of how the kernel's bind-mount semantics interact with the daemon's own runtime-directory lifecycle. `systemd-analyze verify` does not surface it because the analyser checks unit syntax and directive interactions in the abstract, not the host filesystem state at boot time.

## How to detect it

Two pre-deploy checks plus one boot-time signal cover the class.

The pre-deploy check identifies whether the daemon's stock unit declares a runtime directory:

```bash
grep -E '^(RuntimeDirectory|StateDirectory|ConfigurationDirectory|LogsDirectory)=' \
  /usr/lib/systemd/system/<svc>.service
```

On a daemon whose runtime directory is systemd-managed, the output includes a `RuntimeDirectory=<svc>` line. On an affected daemon, the output does not include the line for the runtime path. The empty return for a path that the operator's drop-in lists in `ReadWritePaths=` is the unambiguous signal that the trap applies.

A secondary pre-deploy check confirms that the path actually exists on the running host. Directory persistence in `/run/` masks the trap at runtime; the check is what distinguishes a host that will boot cleanly from one that will not:

```bash
[ -d /run/<svc> ] && echo "exists (restart-verify will lie)" || echo "absent (boot-fail risk)"
```

The boot-time signal, when the trap fires, is the journal entry shape:

```text
<unit>: Failed to set up mount namespacing: /run/<svc>: No such file or directory
<unit>: Failed at step NAMESPACE spawning /usr/bin/<svc>: No such file or directory
systemd[1]: <unit>: Main process exited, code=exited, status=226/NAMESPACE
<unit>: Start request repeated too quickly
```

The first journal line names the missing path; that is the directory the operator's drop-in listed in `ReadWritePaths=` without a `-`-prefix.

## How to mitigate it

Two paths.

The **safe path** is a `-`-prefix on the affected `ReadWritePaths=` entry:

```ini
[Service]
ReadWritePaths=/etc/<svc> /var/lib/<svc> -/run/<svc>
```

Per `systemd.exec(5)`: paths in `ReadWritePaths=`, `ReadOnlyPaths=`, `InaccessiblePaths=`, `ExecPaths=`, and `NoExecPaths=` may be prefixed with `-`, in which case they are ignored when they do not exist. The boot-time bind-mount step skips the missing path, the namespace setup completes, the daemon starts, and the daemon creates its runtime directory in its own code path. On subsequent restarts the directory exists and the bind-mount succeeds normally. The mitigation is minimally invasive: it does not change the daemon's lifecycle behaviour, does not require a vendor-unit override, and survives package updates.

The **invasive path** is to add `RuntimeDirectory=<svc>` to the drop-in:

```ini
[Service]
RuntimeDirectory=<svc>
```

systemd then creates the directory before the NAMESPACE step, the original `ReadWritePaths=/run/<svc>` entry becomes redundant, and the trap does not surface. The trade-off is the default `RuntimeDirectoryPreserve=no`: systemd deletes the directory on unit stop, which changes the daemon's lifecycle assumption. Daemons that expect the directory to persist across stop/start cycles — the very daemons for which the bug surfaced — may not handle the deletion gracefully. The safe-path `-`-prefix is preferred unless the operator has explicitly verified that the daemon copes with the deletion.

**Restart-verify-lies invariant.** Neither mitigation can be validated by `systemctl restart`. The directory persists across restart, so the bind-mount succeeds in both fixed and broken configurations. The trap surfaces only on an actual reboot, or on a deliberate `systemctl stop && rm -rf /run/<svc> && systemctl start` cycle. A verify discipline that ships restart-only validation is structurally incomplete for daemons in this class.

Edge cases the mitigation does not cover:

- A daemon whose stock unit ships `RuntimeDirectory=<svc>` is not affected; systemd creates the directory before NAMESPACE and the bind-mount succeeds on the first boot. No mitigation is needed.
- A daemon whose drop-in does not include any `Protect*` directive that triggers a private mount-namespace (`ProtectSystem=full` instead of `ProtectSystem=strict`, or no `Protect*` directive at all, plus a bare `ReadWritePaths=`) does not create the namespace, the bind-mount step does not run, and the trap does not surface.
- A daemon that uses `StateDirectory=` plus `ReadWritePaths=/var/lib/<svc>` exhibits the same trap shape on `/var/lib/<svc>` if the daemon manages the state directory itself rather than deferring to systemd or to the package install. This case is rare; most daemons let systemd or the package manage the state directory.

## See also

- [NNP and SELinux transition trap](./nnp-selinux-transition-trap.md) — The sister boot-failure class. Both surface only on next boot, not on `systemctl restart`, and both pass `systemd-analyze verify` in the abstract; an operator who validates a drop-in by restart alone catches neither class.
- [UMASK and daemon readability](./umask-and-daemon-readability.md) — Another silent boundary trap where a daemon starts but does not function as intended; the trap shape is different but the diagnostic posture (per-property reads, journal correlation, and a reboot-rather-than-restart validation step) is similar.
