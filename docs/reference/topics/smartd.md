<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# smartd

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `smartd.service` SATA-SMART-polling daemon on a Fedora 44 or later host. The end-state is a four-artefact deploy profile under `/etc/systemd/system/smartd.service.d/` and `/usr/local/share/selinux/`: a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` drop-in, a process-internal kernel-restrictions drop-in that carries the SATA-SMART `CAP_SYS_RAWIO` carve-out, and a topic-owned SELinux CIL module that enables the `init_t → fsdaemon_t : process2 nnp_transition` rule that stock targeted policy does not ship for this domain. The end-state also includes the verify discipline that confirms each layer, the AVC-clean assertion, the pre-hardening SATA-SMART baseline discipline, and a three-stage rollback posture. This topic does not cover the `smartctl(8)` command-line client (operator-policy surface), the `/etc/smartmontools/smartd.conf` content (mail-notification, polling-interval, per-disk `DEVICESCAN` directives — operator-policy outside this topic), the broader Linux SCSI generic IOCTL stack (the SMART carve-out is motivated below; the kernel mechanism lives in a Pattern article), or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines four shipping artefacts: a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` drop-in, a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's domain, and a process-internal kernel-restrictions drop-in that carries the capability bounding set, the address-family restriction, and the syscall filter. Subsections below describe each artefact in turn.

### Service identity

The unit `smartd.service` is shipped by the `smartmontools` package. The stock vendor file at `/usr/lib/systemd/system/smartd.service` carries the directives this topic does not modify:

| Property | Value |
|---|---|
| Unit | `smartd.service` |
| Type | `notify` |
| ExecStart | `/usr/bin/smartd` |
| User / group | `root:root` |
| SELinux domain | `fsdaemon_t` |

The SELinux type-transition `init_t → fsdaemon_t` fires on the executable label `fsdaemon_exec_t` carried by the binary. On Fedora 44 or later, the binary lives at `/usr/bin/smartd`; `/usr/sbin/smartd` is a compatibility symlink that resolves to the same inode.

The vendor unit ships no `RuntimeDirectory=`, no `StateDirectory=`, no `ConfigurationDirectory=`, and no `LogsDirectory=` directive, and this topic adds none. As a consequence, no `ReadWritePaths=` entry on a daemon-self-managed runtime path is required, and the boot-time mount-namespace race that affects daemons whose drop-ins point `ReadWritePaths=` at a directory the daemon creates itself does not apply here.

The `smartmontools` package ships the daemon and the `smartctl(8)` command-line client. The role's preflight stage checks the package presence; the role does not interact with `smartctl(8)` invocations or with `/etc/smartmontools/smartd.conf` content.

### Four-artefact deploy profile

The hardening profile splits across three drop-in INI files under `/etc/systemd/system/smartd.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-default baseline (Protect* suite plus process-internal hardening). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (MDWE, address-family restriction, additive plus subtractive syscall filter, capability bounding set with the SATA-SMART carve-out). |
| `nnp_smartd.cil` | Topic-owned SELinux module that grants `init_t → fsdaemon_t : process2 nnp_transition`. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. The other two drop-ins carry the lower-risk and the higher-risk sandbox layers respectively, and rolling them back is sequenced in the rollback paragraph at the end of the article.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart (manual, package-triggered, or system reboot) hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/smartd.service.d/99-hardening.conf`.

```ini
[Service]
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
PrivateTmp=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
```

Directive notes:

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. The daemon writes to none of these paths.
- `ProtectHome=yes` — operator home directories are inaccessible. The daemon does not consume per-user configuration.
- `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes` — the sysctl interfaces, the kernel-module IOCTL paths, and the kernel-log devices are denied. The daemon reads device-level data from block devices, not kernel-level tunables.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only. The daemon does not adjust resource limits.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. The daemon does not coordinate temporary state with other processes.
- `ProtectClock=yes`, `ProtectHostname=yes` — `settimeofday(2)`, `adjtimex(2)`, and the hostname interfaces are denied.
- `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `SystemCallArchitectures=native` — process-internal restrictions; no namespace effect.

`PrivateMounts=no` is **not** set on this unit. The daemon is not a mount-manager; it issues no `mount(2)` calls. The implicit `PrivateMounts=true` enable that the `Protect*` family carries has no operator-visible effect here because the daemon's primary work runs entirely against block devices through `ioctl(2)`. The boundary marker keeps this topic distinct from the mount-manager-class trap.

### `99-nnp.conf`

Path: `/etc/systemd/system/smartd.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → fsdaemon_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t fsdaemon_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### `nnp_smartd.cil`

Path: `/usr/local/share/selinux/nnp_smartd.cil`.

```cil
(allow init_t fsdaemon_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_smartd.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_smartd` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts, see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### `99-process-restrict.conf`

Path: `/etc/systemd/system/smartd.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
CapabilityBoundingSet=CAP_SYS_RAWIO CAP_SYS_ADMIN
```

Directive notes:

- `MemoryDenyWriteExecute=yes` refuses `mmap(2)` with `PROT_WRITE|PROT_EXEC` and writable-to-executable `mprotect(2)` flips. The daemon does not JIT-compile or self-modify code.
- `RestrictAddressFamilies=AF_UNIX` permits `AF_UNIX` only. The daemon uses `AF_UNIX` for the `Type=notify` socket transport. It does not consume the kernel uevent stream and therefore does not need `AF_NETLINK`. Adding `AF_NETLINK` here is a regression for this unit; the surface gain is zero.
- `SystemCallFilter=@system-service` (additive baseline) plus `SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock` (subtractive narrowing). systemd composes successive `SystemCallFilter=` directives multiplicatively: the additive line establishes the daemon-class envelope, and the subtractive line strips classes the daemon does not need. `@mount` is dropped because the daemon is not a mount-manager. `@raw-io` is dropped because the SCSI-generic IOCTL path the daemon uses for SATA-SMART rides on `ioctl(2)` from `@system-service`, not on the `@raw-io` syscall class — the two are orthogonal, as documented in [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md). The daemon performs no multi-stage privilege drop, so the additive plus subtractive form covers everything it issues; the multi-stage-drop class falls under the [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) Pattern.
- `CapabilityBoundingSet=CAP_SYS_RAWIO CAP_SYS_ADMIN` retains the two capabilities the daemon requires. `CAP_SYS_RAWIO` is the SATA-SMART carve-out: the kernel `SG_IO` ATA-pass-through path checks `capable(CAP_SYS_RAWIO)`, and a bounding set without it silently breaks SMART polling on SATA drives. `CAP_SYS_ADMIN` is retained for the daemon's broader IO-control needs even though the daemon does not call `mount(2)`. The class mechanism, the NVMe-versus-SATA divergence, and the additive cap-set mitigation are documented in [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md). An NVMe-only host may drop `CAP_SYS_RAWIO` per the same logic; the role keeps it in the default profile because mixed SATA/NVMe is the conservative assumption.

### File modes

All four shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/smartd.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/smartd.service.d/99-nnp.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/smartd.service.d/99-process-restrict.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/usr/local/share/selinux/nnp_smartd.cil` | `0644` | `root:root` | `usr_t` |

Targeted policy on Fedora 44 defines a `fsdaemon_unit_file_t` type, but `file_contexts` carries no path pattern that assigns it: no entry matches `/usr/lib/systemd/system/smartd*`, so the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency resolves to nothing more specific than the generic rule. The expected type for the drop-in directory and for every file inside it is therefore the `systemd_unit_file_t` they inherit at creation, and `matchpathcon` confirms it. No `type_transition` to a `*_unit_file_t` exists for PID 1.

The role runs `restorecon -F -v -R` on the drop-in directory anyway. The call is a no-op on the type, but `-F` normalises the SELinux user field, which otherwise keeps the identity of whoever applied the role and stays invisible to the type-only comparison of `restorecon -n`. The step also remains correct if a future policy release adds a mapping for this path. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_smartd/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`smartmontools`), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, and the `semodule -l | grep nnp_smartd` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_smartd/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `CapabilityBoundingSet` | `cap_sys_admin cap_sys_rawio` |
| `RestrictAddressFamilies` | `AF_UNIX` |
| `SystemCallFilter` | length `> 200` bytes after expansion, contains anchor syscalls (`read`, `write`, `openat`, `close`, `ioctl`, `fstat`) |
| Live SELinux domain | `fsdaemon_t` |
| `semodule -l | grep nnp_smartd` | one line (sysadm_t-gated) |

Two normalisation conventions are load-bearing. `systemctl show -p CapabilityBoundingSet --value` returns capabilities in alphabetical lower-case form, so the expected string is `cap_sys_admin cap_sys_rawio` and any other order or any extra capability fails the check. `RestrictAddressFamilies=AF_UNIX` carries a single value, so no source-order question arises.

The `SystemCallFilter` check is a length-plus-anchor form, not a class-name match. `systemctl show -p SystemCallFilter --value` returns the expanded syscall list rather than the class names that appear in the drop-in body. The length threshold (`> 200` bytes) plus the presence of the anchor syscalls is the robust shape. The anchor list deliberately omits `mount` and `umount2`: this unit's filter strips `@mount` in the subtractive line, and an anchor that asserts `mount` presence false-flags a correctly hardened unit.

Liveness is checked through `[ -d /proc/${main_pid} ]`, never `kill -0 ${main_pid}`. From a `staff_t` shell, `kill -0` against a root-owned PID returns `EPERM` rather than `ESRCH`, and a verify script that reads the rc as "PID gone" reports a live daemon as dead. The `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `fsdaemon_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `semodule -l | grep nnp_smartd` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(fsdaemon_t|nnp_transition|smartd)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Pre-hardening baseline for SATA-SMART

Before deploying the four-artefact profile, capture the baseline value of:

```bash
sudo -r sysadm_r -t sysadm_t journalctl -u smartd.service -b 0 \
  | grep -ciE 'sgio|housekeeping|operation not permitted'
```

On a stock host with one or more SATA drives in healthy condition, the baseline is typically `0`. Post-deploy, the same query must still return `0`. A non-zero result post-deploy with a zero baseline indicates a missing `CAP_SYS_RAWIO` carve-out. The class mechanism, the NVMe-versus-SATA divergence, and the additive cap-set mitigation are documented in [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md). NVMe-only hosts may skip this baseline; SATA and mixed hosts record it.

The role's modify stage is idempotent. The four shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, and `restart` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is three-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_smartd`, then `systemctl daemon-reload` and `systemctl restart smartd.service`. The NNP layer alone is reverted; the namespace-default baseline and the process-internal restrictions remain. **Stage 2**: in addition to Stage 1, remove `99-process-restrict.conf`. The process-internal restrictions are reverted; the namespace-default baseline remains. **Stage 3**: in addition to Stages 1 and 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback; this Reference does not inline boot-failure recovery.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → fsdaemon_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/smartd` at next boot under `no_new_privs`.
- [Storage SMART and CAP_SYS_RAWIO](../../explanation/storage-smart-rawio.md) — Why `CapabilityBoundingSet=` includes `CAP_SYS_RAWIO` alongside `CAP_SYS_ADMIN`: the kernel `SG_IO` ATA-pass-through path checks `capable(CAP_SYS_RAWIO)`, and a bounding set without it silently disables SATA-SMART polling while leaving the daemon's primary process active.
