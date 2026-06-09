<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# udisks2

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `udisks2.service` mount-manager unit on a Fedora 44 or later host. The end-state is a three-drop-in profile under `/etc/systemd/system/udisks2.service.d/` (a namespace-neutral baseline, an isolated `NoNewPrivileges=yes` layer, and a process-internal restrictions layer including a SATA-SMART capability carve-out), the absence of any custom SELinux module (stock policy already grants the `init_t → devicekit_disk_t : process2 nnp_transition` rule the NNP layer depends on), the verify discipline that confirms the directives took effect, the operator-observable mount-visibility invariant that distinguishes a correctly hardened daemon from one that has fallen into the implicit-mount-namespace trap, the pre-hardening baseline discipline for the SATA-SMART path, and a three-stage rollback posture that restores layers in reverse order of their security impact. This topic does not cover per-block-device `polkit` action rules (operator-policy surface that lives in a separate topic), `gvfs-udisks2-volume-monitor` and the GNOME virtual-filesystem stack (a separate user-application topic), `autofs`, `automount`, or `davfs2` (each a separate topic), the broader Linux SCSI generic IOCTL stack (the SMART carve-out is motivated below; the kernel mechanism lives in a Pattern article), package-removal decisions for the `udisks2-iscsi`, `udisks2-lvm2`, and `udisks2-btrfs` sub-packages (operator-policy outside this topic), and the `systemd-analyze security` score model (the topic states the directive end-state and the verify-output expected block; numeric score comparison is operator-policy outside this topic).

## End-state configuration

The end-state combines four layers: an identity layer described by the stock vendor unit (which the topic does not modify), a namespace-neutral baseline drop-in that hardens process-internal behavior without disturbing mount propagation, an isolated `NoNewPrivileges=yes` drop-in that carries the rollback granularity for the NNP layer alone, and a process-internal kernel-restrictions drop-in that carries the capability carve-out, the address-family restriction, the syscall filter, and the memory-write-execute lock. The four layers are described in subsections below.

### Service identity

The unit `udisks2.service` is shipped by the `udisks2` package. The stock vendor file at `/usr/lib/systemd/system/udisks2.service` carries the directives the topic does not modify:

| Property | Value |
|---|---|
| Unit | `udisks2.service` |
| Type | `dbus` |
| BusName | `org.freedesktop.UDisks2` |
| ExecStart | `/usr/libexec/udisks2/udisksd` |
| KillSignal | `SIGINT` |
| User / group | `root:root` |
| SELinux domain | `devicekit_disk_t` |

The SELinux type-transition `init_t → devicekit_disk_t` fires on the executable label `udisksd_exec_t` carried by `/usr/libexec/udisks2/udisksd`. The transition is part of stock targeted policy on Fedora 44 or later; this topic ships no policy override.

The vendor unit ships no `RuntimeDirectory=`, no `StateDirectory=`, no `ConfigurationDirectory=`, and no `LogsDirectory=` directive, and the topic adds none. As a consequence, no `ReadWritePaths=` entry on a daemon-self-managed runtime path is required, and the boot-time mount-namespace race that affects daemons whose drop-ins point `ReadWritePaths=` at a directory the daemon creates itself does not apply here.

The `udisks2` package ships the daemon. Three optional sub-packages add backend-specific capabilities:

| Package | Adds |
|---|---|
| `udisks2-iscsi` | iSCSI-target mediation through `open-iscsi`. |
| `udisks2-lvm2` | LVM2 volume-group introspection and mediation. |
| `udisks2-btrfs` | Btrfs-subvolume introspection and mediation. |

The optional sub-packages may be absent on a hardened host without affecting the core mount mediation. The role's preflight stage checks the core `udisks2` package only and reports the sub-packages as inventory rather than as required state.

### Three-drop-in profile

The hardening profile splits across three drop-in files under `/etc/systemd/system/udisks2.service.d/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-neutral baseline. |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (MDWE, address-family restriction, syscall filter, capability bounding set). |

The split is granular by intent. Removing `99-nnp.conf` on its own rolls back the NNP layer without touching the namespace-neutral baseline or the process-internal restrictions, allowing an operator to isolate an NNP-related symptom from the rest of the profile. The other two files carry the lower-risk and the higher-risk sandbox layers respectively, and rolling them back is sequenced in the "Verification" section under the rollback paragraph. The Recovery how-to documents the boot-failure variant; the recovery banner at the end of this article points there.

### `99-hardening.conf`

Path: `/etc/systemd/system/udisks2.service.d/99-hardening.conf`.

```ini
[Service]
PrivateMounts=no
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
ProtectHome=read-only
```

Directive notes:

- `PrivateMounts=no` is the explicit override that prevents implicit-enable from a later directive. The class trap and the implicit-enabler list are documented separately; see [PrivateMounts implicit enable](../../explanation/private-mounts-implicit.md).
- `LockPersonality=yes` denies `personality(2)` after start. No mount-namespace effect.
- `RestrictRealtime=yes` denies `SCHED_FIFO`, `SCHED_RR`, and `SCHED_DEADLINE`. The daemon does not need realtime scheduling.
- `RestrictSUIDSGID=yes` denies the `setuid` and `setgid` mode bits on files the daemon creates. It does not block `mount(2)` on filesystems whose contents include setuid binaries.
- `SystemCallArchitectures=native` denies non-native syscall ABIs. On a single-architecture host the directive has no functional effect; it is a defense-in-depth posture against future multi-architecture exposure.
- `ProtectHome=read-only` permits the daemon to read `~/.config/udisks2/` for per-user mount configuration. Read-only suffices; the daemon does not write into operator home directories. The directive is on the implicit-enabler list for `PrivateMounts=true`, but the explicit `PrivateMounts=no` above neutralises the implicit enable for this unit.

### `99-nnp.conf`

Path: `/etc/systemd/system/udisks2.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on all descendants. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child.

The directive is safe to apply to this unit without an SELinux policy extension. Stock targeted policy on Fedora 44 or later already grants the transition the kernel checks when `no_new_privs` is set on a process whose target SELinux domain differs from its source. The pre-test that confirms the rule is present is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t devicekit_disk_t \
  -c process2 -p nnp_transition
```

Expected output shape on a stock host:

```text
allow init_t devicekit_disk_t:process2 { nnp_transition };
```

A non-empty output with at least one allow rule of this shape confirms that the NNP layer is safe to deploy. If the rule is absent — a class of host that is not the configuration this topic targets but is mentioned for completeness — the symptom on the next boot is that `udisksd` fails the NNP transition under PID 1 and the unit fails to activate. Hosts where the pre-test fails fall into the Pattern [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

This topic ships no SELinux CIL module. Stock targeted policy is sufficient. A future drift in the stock policy that removes the `init_t → devicekit_disk_t : process2 nnp_transition` allow surfaces as a boot-failure post-NNP-deploy; the recovery path is the rollback sequence below and the Recovery how-to.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/udisks2.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service @mount
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RAWIO
```

Directive notes:

- `MemoryDenyWriteExecute=yes` refuses `mmap(2)` with `PROT_WRITE|PROT_EXEC` and `mprotect(2)` flips of writable pages to executable. The daemon does not JIT-compile or self-modify code.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` permits the two address families the daemon needs: `AF_UNIX` carries the D-Bus transport, and `AF_NETLINK` carries the kernel uevent channel that the daemon consumes for hot-plug events. All other families are denied. Adding `AF_INET` or `AF_INET6` is a regression for this unit; the daemon has no internet-network usage.
- `SystemCallFilter=@system-service @mount` is the additive form. The directive enumerates the syscall classes the daemon may issue. The subtractive form `~@privileged` would block `mount(2)` (which lives in `@privileged` per `systemd.exec(5)`) and disable the daemon's primary function. Daemons that exhibit a multi-stage privilege drop fall into a separate class — the [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) Pattern — and would require additional positive entries; this unit performs no such drop and the additive form `@system-service @mount` covers everything it issues.
- `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RAWIO` retains the two capabilities the daemon requires. `CAP_SYS_ADMIN` is required for `mount(2)`. `CAP_SYS_RAWIO` is the SATA-SMART carve-out: the kernel `SG_IO` ATA-pass-through path checks `capable(CAP_SYS_RAWIO)`, and a bounding set without it silently breaks SMART polling on SATA drives. The class mechanism, the NVMe-versus-SATA divergence, and the detection form are documented separately; see [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md). An NVMe-only host may drop `CAP_SYS_RAWIO` because the NVMe IOCTL path does not check that capability; the role keeps it in the default profile because mixed SATA/NVMe is the conservative assumption for a desktop host.

### File modes

All three drop-ins are written at mode `0644`, owner `root`, group `root`, with SELinux file type `systemd_unit_file_t`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/udisks2.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/udisks2.service.d/99-nnp.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/udisks2.service.d/99-process-restrict.conf` | `0644` | `root:root` | `systemd_unit_file_t` |

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_udisks2/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`udisks2`, `udisks2-iscsi`, `udisks2-lvm2`, `udisks2-btrfs` — the latter three may be absent), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the seven managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), and the live-state of the daemon's D-Bus interface via `udisksctl status`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_udisks2/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `PrivateMounts` | `no` |
| `CapabilityBoundingSet` | `cap_sys_admin cap_sys_rawio` |
| `RestrictAddressFamilies` | `AF_UNIX AF_NETLINK` |
| `SystemCallFilter` | length `> 200` bytes after expansion, contains anchor syscalls (`mount`, `umount2`, `read`, `write`, `openat`, `close`) |

Two sort-order conventions are load-bearing. `systemctl show -p CapabilityBoundingSet --value` returns capabilities in alphabetical lower-case form, so the expected value is `cap_sys_admin cap_sys_rawio` and any other order or any extra capability fails the check. `systemctl show -p RestrictAddressFamilies --value` returns the families in the source order they were written into the drop-in, so the expected value is `AF_UNIX AF_NETLINK` and a swap to `AF_NETLINK AF_UNIX` fails the check even though the two values are semantically equivalent.

The `SystemCallFilter` check is a length-plus-anchor form, not a class-name match. `systemctl show -p SystemCallFilter --value` returns the expanded syscall list rather than the class names that appear in the drop-in body. A check that compares the live value against the literal string `@system-service @mount` fails on every correctly configured host. The length threshold (`> 200` bytes) plus the presence of at least four of the anchor syscalls is the robust shape.

Liveness is checked through `[ -d /proc/${main_pid} ]`, never `kill -0 ${main_pid}`. From a `staff_t` shell, `kill -0` against a root-owned PID returns `EPERM` rather than `ESRCH`, and a verify script that reads the rc as "PID gone" reports a live daemon as dead. The `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `devicekit_disk_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`.

The AVC-clean assertion is the property that, on a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(devicekit_disk_t|nnp_transition|udisksd)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

Expected verify output on a correctly applied host, run from `staff_t`:

```text
OK   pkg_udisks2                    installed
OK   unit_udisks2                   active
OK   liveness                       pid=<pid>
OK   NoNewPrivileges                yes
OK   MemoryDenyWriteExecute         yes
OK   PrivateMounts                  no
OK   CapabilityBoundingSet          cap_sys_admin cap_sys_rawio
OK   RestrictAddressFamilies        AF_UNIX AF_NETLINK
OK   SystemCallFilter               length=<n> anchors=mount,umount2,read,write,openat,close
OK   selinux_domain                 devicekit_disk_t
SKIP avc_clean                      needs sysadm_t
```

Re-run as `sudo -r sysadm_r -t sysadm_t bash files/verify.sh`, the `SKIP` line becomes:

```text
OK   avc_clean                      0 hits
```

### Mount visibility invariant

The operator-observable functional invariant is that every mount the daemon installs is visible in the host mount namespace. The verification path does not require a removable-media device:

- `findmnt | grep -E '/run/media|udisks'` lists currently visible auto-mounts in the host namespace. On a host with no removable media attached, this returns nothing, which is also a correct state.
- When a removable-media device is attached and the desktop file manager triggers an auto-mount, `findmnt` lists the mount within one journal-poll cycle.

When a daemon reports a mount via D-Bus but the host namespace does not see it, the symptom indicates that `PrivateMounts=true` is in effect against the explicit `PrivateMounts=no` override (or that the override was omitted). The diagnostic command:

```bash
sudo -r sysadm_r -t sysadm_t nsenter -t "$(pgrep -x udisksd)" -m findmnt \
  | grep /run/media
```

If this command lists the mount and `findmnt` (without `nsenter`) does not, the unit is in the implicit-private-mount state. The class mechanism is documented in [PrivateMounts implicit enable](../../explanation/private-mounts-implicit.md).

### Pre-hardening baseline for SATA-SMART

Before deploying the three-drop-in profile, capture the baseline value of:

```bash
sudo -r sysadm_r -t sysadm_t journalctl -u udisks2.service -b 0 \
  | grep -ciE 'sgio|housekeeping|operation not permitted'
```

On a stock host with one or more SATA drives, the baseline is typically `0`. Post-deploy, the same query must still return `0`. A non-zero result post-deploy with a zero baseline indicates a missing `CAP_SYS_RAWIO` carve-out. The class mechanism, the NVMe-versus-SATA divergence, and the additive cap-set mitigation are documented in [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md). NVMe-only hosts may skip this baseline; SATA and mixed hosts record it.

The role's modify stage is idempotent. The three drop-in files are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. A daemon-reload handler runs on file change; a service-restart handler runs on file change. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is three-stage. **Stage 1**: remove `99-nnp.conf`, run `systemctl daemon-reload`, and `systemctl restart udisks2.service`. The NNP layer alone is reverted; the namespace-neutral baseline and the process-internal restrictions remain in effect. **Stage 2**: in addition to Stage 1, remove `99-process-restrict.conf`. The process-internal restrictions are reverted; only the namespace-neutral baseline remains. **Stage 3**: in addition to Stages 1 and 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor unit. The recovery how-to covers the boot-failure variant of the rollback; this Reference does not inline boot-failure recovery.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [PrivateMounts implicit enable](../../explanation/private-mounts-implicit.md) — Why `PrivateMounts=no` is set explicitly in `99-hardening.conf` even though no explicit implicit-enabler appears in the same file: `ProtectHome=read-only` is on the enabler list, and a future directive added to the same unit could silently flip the namespace mode without the override.
- [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md) — Why `CapabilityBoundingSet=` includes `CAP_SYS_RAWIO` alongside `CAP_SYS_ADMIN`: the kernel `SG_IO` ATA-pass-through path checks `capable(CAP_SYS_RAWIO)`, and a bounding set without it silently disables SATA-SMART polling while leaving mount and query functions intact.
