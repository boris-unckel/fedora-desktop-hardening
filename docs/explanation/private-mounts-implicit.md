<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# PrivateMounts implicit enable

## The trap

A daemon whose primary purpose is to install or expose mount points to the host — the class informally referred to as mount-manager daemons — depends on its `mount(2)` calls being visible in the host mount namespace. A service-level drop-in that sets any of the standard sandbox directives that imply `PrivateMounts=true` quietly disables that visibility. The daemon continues to issue `mount(2)`, the kernel returns success, the daemon's own state shows the mount as present, and any D-Bus or socket-API client that asks the daemon receives a "mounted" response. The host namespace, however, sees nothing. Tools that read `/proc/self/mountinfo` (`findmnt`, `mount`, file managers, the desktop volume monitor) report the mount as absent. A user who clicks the device in a file manager hits an "already mounted at … not accessible" error or a permissions failure on the directory the daemon claims it created.

The trap is silent for every observability surface that does not read the host mount namespace directly. Service status remains `active`. The service journal stays clean. The daemon's own state-export commands report success. A `systemd-analyze security` score reports the sandbox layer as effective. Only a side-by-side comparison of the daemon's view of its mounts against `findmnt` from a normal shell reveals the divergence.

## Why it happens

`systemd` enforces a service mount namespace whenever any directive in a configurable list is present in the unit's effective configuration. Per `systemd.exec(5)`, `PrivateMounts=true` is implied by — among others — `PrivateTmp=`, `ProtectSystem=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectKernelLogs=`, `ProtectKernelModules=`, `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`, `PrivateDevices=`, `PrivateNetwork=`, `PrivateUsers=`, `ReadWritePaths=`, `ReadOnlyPaths=`, `InaccessiblePaths=`, `NoExecPaths=`, `ExecPaths=`, `RuntimeDirectory=`, `StateDirectory=`, `BindPaths=`, `BindReadOnlyPaths=`, `MountAPIVFS=`, `MountImages=`, `RootImage=`, `TemporaryFileSystem=`, and `RestrictNamespaces=`. The exact list varies across `systemd` versions; the manual page on the running host is the authoritative reference.

When the implicit enable fires, `systemd` calls `unshare(CLONE_NEWNS)` before the service `ExecStart=` and marks the new namespace's root mount as `MS_SLAVE`. The daemon then runs in a private mount namespace that receives propagation events from the host but does not propagate events back. `mount(2)` calls inside the namespace succeed at the kernel level, and the resulting mount entry is visible to `/proc/<daemon-pid>/mountinfo`, but it never appears in the host's mount table.

`mount(8)`, `findmnt(8)`, and the desktop volume monitors all walk the host's `/proc/self/mountinfo`, not the daemon's. The disagreement that follows is structural: the daemon and the host are looking at two different namespaces, and no amount of D-Bus, socket, or status-API correctness on the daemon side reconciles them. A score-based hardening review that flags the sandbox layer as effective measures exactly the wrong invariant — the layer is doing what the directive promises, which is precisely why the daemon's intended function is broken.

The list of directives that do **not** imply `PrivateMounts=` and are therefore safe in a mount-manager profile is short: `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `SystemCallArchitectures=native`, `KeyringMode=private`, `RemoveIPC=yes`, `UMask=`, `IgnoreSIGPIPE=`. The post-process restrictions that target capabilities, syscalls, address families, and writable-executable memory — `NoNewPrivileges=`, `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, `CapabilityBoundingSet=`, `SystemCallFilter=` — also do not imply `PrivateMounts=`. A profile that combines these with an explicit `PrivateMounts=no` override hardens the daemon without disturbing mount visibility. `RestrictNamespaces=` is itself an implicit enabler and is therefore excluded from the safe list, even though it is sometimes treated as a process-internal restriction.

## How to detect it

Three observable signals, in order of how reliably they appear:

- The daemon's own state-export reports a mount as present, and a normal-shell `findmnt` does not show it. This is the canonical detection: it isolates the namespace divergence directly. The `findmnt` form `findmnt | grep <expected-mount-path>` returns the mount on a correctly configured host; on an affected host, the same command returns empty while the daemon insists the mount is in place.
- An `nsenter`-based comparison shows the same mount inside the daemon's namespace and absent outside. The diagnosis form is uniform across mount-manager daemons:

  ```text
  $ nsenter -t <daemon-pid> -m findmnt | grep <expected-mount-path>
  /<expected-mount-path>   /dev/<source>   <fstype>   <options>
  $ findmnt | grep <expected-mount-path>
  $
  ```

  Inside the daemon's namespace, the mount is present with the option set the daemon configured. Outside, the host sees nothing. This is the unambiguous proof; no other failure mode produces this exact disagreement.

- A user-visible failure when a desktop client (file manager, volume monitor) tries to operate on the mount. The error text varies — "Device is already mounted at <path>", "Unable to access <path>", a `Permission denied` on the destination directory — but the common shape is that the client receives the daemon's "mounted" assertion, attempts to enter the namespace via the host path, and fails because the host path does not exist or is not the mount point the daemon described.

A sanity check that confirms the implicit enable without naming a specific symptom path: read the effective `PrivateMounts=` value the daemon was launched with. Any value other than `no` on a mount-manager daemon's running unit indicates either an explicit `PrivateMounts=yes` (which is itself a misconfiguration for this class) or an implicit enable from one of the directives above.

```text
$ systemctl show -p PrivateMounts --value <unit>
yes
```

## How to mitigate it

Two parts compose the mitigation: an explicit `PrivateMounts=no` override that defends against later directive additions, and a process-level hardening profile that excludes every implicit enabler. The override pattern is uniform across mount-manager daemons:

```ini
[Service]
PrivateMounts=no
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
```

`PrivateMounts=no` set explicitly is a belt-and-suspenders measure: it is not strictly required when the drop-in contains no implicit enabler, but it ensures that a future directive added to the same unit does not silently flip the namespace mode. The other four directives are process-internal and do not affect mount propagation.

A second drop-in carries the post-process restrictions that the mount-manager class still benefits from:

```ini
[Service]
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service @mount
CapabilityBoundingSet=CAP_SYS_ADMIN
```

The `SystemCallFilter=` form is additive (`@system-service @mount`), not subtractive (`~@privileged`). The subtractive form blocks `mount(2)`, which lives in `@privileged`, and therefore disables the daemon's primary purpose. The capability set retains `CAP_SYS_ADMIN` because `mount(2)` requires it; daemons that perform additional kernel-IO operations may add capabilities such as `CAP_SYS_RAWIO` per their own per-class needs.

Edge cases the mitigation does not cover:

- A daemon that itself spawns short-lived helper processes via `fork`/`exec` with their own sandbox attributes (for example, a mount helper invoked through `/sbin/mount.<fstype>`). Those helpers run in the same namespace as the daemon, so the explicit `PrivateMounts=no` propagates correctly; the helper's own SELinux transition or capability requirements are a separate concern that this pattern does not address.
- A unit whose vendor file already sets `PrivateMounts=yes` deliberately — for example, a daemon that runs entirely inside a private mount namespace by design and does not need host visibility. This pattern does not apply to such units; the implicit-enable trap is, by definition, a problem only for mount-manager daemons.
- A `systemd` version whose implicit-enabler list adds or removes a directive relative to the list quoted above. The `systemd.exec(5)` manual page on the running host is authoritative; an operator who relies on the directive-by-directive list above and does not cross-check against the local manual page can miss a newly added enabler.
- A drop-in that uses `RestrictNamespaces=` to deny mount-namespace creation. `RestrictNamespaces=` is itself an implicit enabler; using it on a mount-manager daemon is doubly wrong (it both flips `PrivateMounts=` on and blocks the daemon's own ability to manage mount namespaces).

## See also

- [UMASK and daemon readability](./umask-and-daemon-readability.md) — A different class of silent-failure trap at the operator/daemon boundary, where a hardened operator UMASK produces files that a non-root daemon cannot read.
