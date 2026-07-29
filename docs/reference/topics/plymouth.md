<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# plymouth-start

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of `plymouth-start.service` on a Fedora 44 or later host. The end-state is a four-artefact deploy profile: three drop-in INI files under `/etc/systemd/system/plymouth-start.service.d/` (a topic-owned filesystem-and-process-isolation drop-in that adds seventeen directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a paired drop-in carrying the three NNP-companion process-internal-restriction directives) plus one topic-owned SELinux CIL module under `/usr/local/share/selinux/` that lifts the `init_t → plymouthd_t : process2 nnp_transition` denial that stock targeted policy carries for this domain. The end-state also includes the verify discipline (per-property reads, post-exit unit-state assertion in lieu of live-PID liveness, AVC-clean assertion, CIL module-presence check), a dual-class splash smoketest (`plymouth-quit-wait.service` boot-completion drift class plus operator-only visual splash), the pre-hardening splash baseline, and a three-stage rollback posture. This topic does not cover `/etc/plymouth/plymouthd.conf` content, the theme content under `/usr/share/plymouth/themes/`, the kernel cmdline plymouth flags (`splash`, `quiet`, `plymouth.enable=`), the companion units `plymouth-quit.service`, `plymouth-quit-wait.service`, and `plymouth-read-write.service` beyond the boot-completion smoketest anchor on `plymouth-quit-wait.service`, the daemon-internal DRM-IOCTL or KD-mode-set sequences beyond the byte-exact capability rationale, the `SystemCallFilter=` iteration history, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines four shipping artefacts: three drop-in INI files split for rollback granularity (filesystem-and-process-isolation surface, isolated NNP layer, NNP-companion process-internal-restriction surface) and one topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's main domain. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates what the F44 stock vendor unit already carries and what the topic therefore does not modify.

### Service identity

The unit `plymouth-start.service` is shipped by the `plymouth` package and is the boot-splash renderer on a Fedora 44 host. The stock vendor file at `/usr/lib/systemd/system/plymouth-start.service` carries the directives this topic does not modify. The daemon binary is installed at `/usr/bin/plymouthd`; stock targeted policy on Fedora 44 ships the file-context mapping `/usr/bin/plymouthd → plymouthd_exec_t`, and the SELinux type-transition `init_t → plymouthd_t` fires on `plymouthd_exec_t` carried by that binary path. A Fedora 44 host carries a global `/usr/sbin → /usr/bin` path equivalency that rewrites every `/usr/sbin/<binary>` lookup before the file-context table is consulted; an operator-side reference to `/usr/sbin/plymouthd` therefore resolves to the generic `bin_t` rather than to `plymouthd_exec_t`. All role-internal references use `/usr/bin/plymouthd`, and the role's preflight stage validates the mapping with a `matchpathcon /usr/bin/plymouthd` fail-fast. The class mechanism, the detection scan, and the mitigation form are documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

| Property | Value |
|---|---|
| Unit | `plymouth-start.service` |
| Type | `forking` |
| ExecStart | `/usr/bin/plymouthd --mode=boot --pid-file=/run/plymouth/pid --attach-to-session` |
| User / group | not set on the unit (daemon runs as root throughout its short lifecycle) |
| Daemon binary | `/usr/bin/plymouthd` |
| SELinux domain | `plymouthd_t` |
| Drop-in file SELinux type | `systemd_unit_file_t` (no mapped subtype; directory identical) |
| Runtime directory | `/run/plymouth/` (daemon-self-managed; no `RuntimeDirectory=` in stock unit) |

The vendor unit ships **no** `User=`, **no** `Group=`, **no** `RuntimeDirectory=`, and **no** `StateDirectory=`. The daemon manages its own runtime path under `/run/plymouth/` (its own pid-file, its own socket).

> plymouth-start runs once during the early-boot sequence and exits when the splash hand-off to `plymouth-quit.service` completes; the unit's apply path is therefore the next reboot, not `systemctl restart`, and the role's deploy ordering reflects this — drop-ins and the CIL module are pushed and labelled but no in-place restart of `plymouth-start.service` is attempted.

> The companion units `plymouth-quit.service`, `plymouth-quit-wait.service`, and `plymouth-read-write.service` are sub-second oneshots that the role does not configure; their hardening surface is outside this topic's scope, and the role uses `plymouth-quit-wait.service` only as a passive boot-completion smoketest anchor in the verify discipline.

The F44 stock vendor unit ships no sandbox layer. The operational directives it already carries are:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `Type=forking` | the daemon double-forks at startup; systemd tracks the post-fork pid |
| `ExecStart=/usr/bin/plymouthd --mode=boot --pid-file=/run/plymouth/pid --attach-to-session` | renderer startup; pid-file under daemon-managed `/run/plymouth/`, attaches to the boot session |
| `Wants=systemd-ask-password-plymouth.path systemd-vconsole-setup.service` | weak ordering against the splash-time password agent and the console setup |
| `After=systemd-vconsole-setup.service systemd-udev-trigger.service systemd-udevd.service` | runs after the console and udev are ready |
| `Before=systemd-ask-password-plymouth.service` | runs before the splash-time password agent |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope. The table also implicitly states what the F44 stock unit does not ship — every `Protect*=`, `Restrict*=`, `Private*=`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `LockPersonality=`, `NoNewPrivileges=`, `CapabilityBoundingSet=`, `User=`, `Group=`, `UMask=`, `ProcSubset=`, `ReadWritePaths=`, `RuntimeDirectory=`, and `StateDirectory=` directive is absent from the vendor unit. The absence is the entirety of what the topic-owned hardening surface fills.

The `plymouth` package ships the daemon binary `/usr/bin/plymouthd`, the systemd unit files for the four `plymouth-*` units (`plymouth-start.service`, `plymouth-quit.service`, `plymouth-quit-wait.service`, `plymouth-read-write.service`), the configuration directory `/etc/plymouth/` with `plymouthd.conf` selecting the active theme, the theme directory `/usr/share/plymouth/themes/`, and the runtime directory layout under `/var/lib/plymouth/` and `/var/spool/plymouth/`. Companion packages ship additional themes (`plymouth-theme-*`) and the scripted-theme plugin family (`plymouth-plugin-*`). The role's preflight stage checks `plymouth` package presence; the role does not interact with `/etc/plymouth/plymouthd.conf` content (theme selection is operator-policy), with `/usr/share/plymouth/themes/` content (theme content is package- or operator-policy), or with the kernel cmdline (`splash`, `quiet`, `plymouth.enable=` are operator-policy).

### Four-artefact deploy profile

The hardening profile splits across three drop-in INI files under `/etc/systemd/system/plymouth-start.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Filesystem-and-process-isolation surface (the seventeen directives below). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only; isolated for Stage-1 rollback granularity. |
| `99-process-restrict.conf` | NNP-companion process-internal-restriction surface (`MemoryDenyWriteExecute=`, `SystemCallFilter=`, `CapabilityBoundingSet=`); paired with `99-nnp.conf` for Stage-2 rollback granularity. |
| `nnp_plymouth.cil` | Topic-owned SELinux module that grants the `init_t → plymouthd_t : process2 nnp_transition` allow rule. |

The split is granular by intent. Removing `99-nnp.conf` reverts only the NNP layer; removing `99-nnp.conf` plus `99-process-restrict.conf` reverts the entire NNP-and-process-internal-restriction surface; additionally removing `99-hardening.conf` reverts the unit to the stock vendor configuration. The CIL module is harmless on its own (no drop-in claims `NoNewPrivileges=yes` after a Stage-1 rollback), but the documented Stage-1 rollback unloads it atomically with the NNP drop-in for symmetry.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push.

### `99-hardening.conf`

Path: `/etc/systemd/system/plymouth-start.service.d/99-hardening.conf`.

```ini
[Service]
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateTmp=yes
ReadWritePaths=-/run/plymouth /var/lib/plymouth /var/spool/plymouth
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
```

The drop-in carries the seventeen-directive filesystem-and-process-isolation surface that the F44 stock vendor unit does not ship. plymouth-start renders the boot splash at PID 1 spawn time and exits when the splash hand-off completes; the daemon does not consume a network stack, does not load kernel modules, does not touch the cgroup tree, and does not adjust the system clock. The directives group into four effect classes.

**Kernel-surface protections.** `ProtectKernelTunables=yes` denies writes to `/proc/sys/*` and to the related sysctl knobs. `ProtectKernelModules=yes` denies `init_module(2)`, `finit_module(2)`, and `delete_module(2)`. `ProtectKernelLogs=yes` denies access to `/dev/kmsg` and the `syslog(2)` system call. `ProtectControlGroups=yes` mounts the cgroup pseudo-filesystem read-only inside the unit's view. `ProtectClock=yes` denies `settimeofday(2)` and `adjtimex(2)`. `ProtectHostname=yes` denies `sethostname(2)`. The splash renderer touches none of the tunable, module, cgroup, clock, or hostname surfaces. It does call `syslog(2)` — via the `klogctl` libc wrapper, on every splash show through `ply_show_new_kernel_messages` — to render kernel boot messages; `ProtectKernelLogs=yes` reduces that call to `EPERM`, which plymouth tolerates by skipping the message render. The `syslog(2)` call must, however, still be permitted by the syscall filter, or the daemon is SIGSYS-killed at boot before the `EPERM` is ever returned. The syscall-filter re-add that prevents that kill is documented under `99-process-restrict.conf`.

**Filesystem-isolation and namespace-restriction surface.** `ProtectSystem=strict` mounts the entire system hierarchy read-only inside the unit's view, with `ReadWritePaths=` re-opening a whitelist. `ProtectHome=yes` denies the unit's view of operator home directories. `PrivateTmp=yes` gives the unit a private `/tmp` and `/var/tmp`. `LockPersonality=yes` denies `personality(2)` (no execution-domain switch). `RestrictRealtime=yes` denies the `SCHED_FIFO` and `SCHED_RR` scheduling classes. `RestrictSUIDSGID=yes` denies the creation of files with the SUID or SGID bits set. `RestrictNamespaces=yes` denies `unshare(2)` and `setns(2)`. `SystemCallArchitectures=native` denies non-native syscall ABIs (the 32-bit personality on x86_64).

**Network-stack scope.**

> plymouthd does not consume an IP stack — splash hand-off to `plymouth-quit.service` runs over an AF_UNIX socket — so `PrivateNetwork=yes` removes the unit's IP-stack visibility entirely and `RestrictAddressFamilies=AF_UNIX` narrows the kernel address-family allow-list to AF_UNIX only.

**Runtime-path scope.**

> The leading `-` on `-/run/plymouth` is mandatory: plymouthd creates `/run/plymouth/` and the pid-file inside it during its own startup, before the unit's mount-namespace setup completes, and the `-`-prefix tells systemd to tolerate the race between mount-namespace setup and daemon-internal directory creation; the class mechanism is documented in [`readwritepaths-runtime-race`](../../explanation/readwritepaths-runtime-race.md).

The two state-and-spool paths `/var/lib/plymouth` and `/var/spool/plymouth` ship in the package install and are present from the first boot, so the bare (un-prefixed) form is correct for them.

### `99-nnp.conf`

Path: `/etc/systemd/system/plymouth-start.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon process and on every descendant of that process. plymouth-start does not exec helper binaries beyond the daemon's own short-lived process tree, so the bit applies to the daemon's own process and to its splash-rendering children.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → plymouthd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t plymouthd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty (no allow rule). The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. plymouth-start runs in the early-boot sequence as a PID 1 spawn, so a missing CIL extension under `NoNewPrivileges=yes` fails the kernel NNP-transition check at boot and the boot splash never renders. This topic ships the extension as a topic-owned CIL module described two subsections below. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/plymouth-start.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
SystemCallFilter=syslog
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_TTY_CONFIG CAP_CHOWN
```

The drop-in carries the three NNP-companion process-internal-restriction directives. They are paired with `99-nnp.conf` because each of them composes with the `no_new_privs` bit at exec time: the syscall filter is enforced as part of the process credentials that `no_new_privs` locks in, the memory-execute restriction interacts with the same kernel exec path, and the capability-bounding-set narrowing is permanent under `NoNewPrivileges=yes`. The directive groups split into three effect classes.

**Memory-execute restriction.** `MemoryDenyWriteExecute=yes` denies `mmap(PROT_WRITE | PROT_EXEC)` and any `mprotect()` upgrade to `PROT_EXEC` on a writable mapping. The splash renderer does not JIT.

**Syscall-class restriction.**

> The `SystemCallFilter=` directive uses the **subtractive form** (`@system-service` baseline minus eleven privileged subclasses), which is appropriate for plymouth-start because the unit does not run a multi-stage privilege-drop sequence inside the daemon — the splash renderer runs as root throughout its short lifecycle and exits when the splash hand-off completes.
>
> The third line, `SystemCallFilter=syslog`, is a **positive re-add** of one syscall the subtractive baseline does not cover. plymouthd calls `klogctl` (the `syslog(2)` syscall) on every splash show, through `ply_show_new_kernel_messages`, to render kernel boot messages. `syslog` is not a member of `@system-service` and is not a member of any of the eleven subtracted subclasses, so the default-deny allow-list silently excludes it; without the re-add the daemon is SIGSYS-killed at boot (`status=31/SYS`, core-dump) the first time it reaches the splash render. Because `syslog` is absent from every subtracted class, the positive add carries no precedence conflict with the `~` line — the merged effective filter simply gains the one syscall. The companion `ProtectKernelLogs=yes` in `99-hardening.conf` still gates the actual ring-buffer read down to `EPERM`; the re-add only prevents the seccomp kill, it does not grant kernel-log access.

**Capability-bounding-set scope.**

> The three capabilities in `CapabilityBoundingSet=` map to specific operations of the splash renderer: `CAP_SYS_ADMIN` for DRM-IOCTLs against `/dev/dri/card*` (mode-set, framebuffer mapping), `CAP_SYS_TTY_CONFIG` for KD-mode and KD-keyboard-mode IOCTLs (`KDSETMODE`, `KDSKBMODE`) against the console TTY, and `CAP_CHOWN` for ownership adjustment of files under `/run/plymouth/` during splash hand-off; the subtractive form drops the remaining thirty-five Stock capabilities.

### `nnp_plymouth.cil`

Path: `/usr/local/share/selinux/nnp_plymouth.cil`.

```cil
(allow init_t plymouthd_t (process2 (nnp_transition)))
```

The single rule lifts the kernel NNP-transition denial for the daemon's main domain. The rule is loaded as a topic-owned CIL module to keep this topic's deploy and rollback footprint atomic at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_plymouth` and removes only this topic's policy extension. Appending the rule to a shared multi-service CIL module would couple this topic's deploy and rollback to the deploy and rollback of every other service that shares the module; topic-tier discipline rules out that coupling.

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_plymouth.cil` from a `sysadm_r/sysadm_t` role-switch. Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). The base kernel-NNP-transition mechanism for the boot-time `init_t → plymouthd_t` rule is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All four shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

Targeted policy on Fedora 44 defines a `plymouthd_unit_file_t` type, but `file_contexts` carries no path pattern that assigns it: no entry matches `/usr/lib/systemd/system/plymouth*`, so the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency resolves to nothing more specific than the generic rule. The expected type for the drop-in directory and for every file inside it is therefore the `systemd_unit_file_t` they inherit at creation, and `matchpathcon` confirms it. No `type_transition` to a `*_unit_file_t` exists for PID 1.

The role runs `restorecon -F -v -R` on the drop-in directory anyway. The call is a no-op on the type, but `-F` normalises the SELinux user field, which otherwise keeps the identity of whoever applied the role and stays invisible to the type-only comparison of `restorecon -n`. The step also remains correct if a future policy release adds a mapping for this path. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/plymouth-start.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/plymouth-start.service.d/99-nnp.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/plymouth-start.service.d/99-process-restrict.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/usr/local/share/selinux/nnp_plymouth.cil` | `0644` | `root:root` | `usr_t` |

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_plymouth/files/probe.sh
```

The probe reports state without judging it. plymouth-start settles into `active (exited)` after a graphical splash hand-off, or lingers as `active (running)` on a host with no display-manager hand-off (a headless server, where `plymouth-quit` runs with `--retain-splash` and nothing takes the splash over); the probe does not rely on a live SELinux-domain read off `/proc/<MainPID>/attr/current` in either case. It enumerates package presence (`rpm -q plymouth`), unit liveness (`systemctl is-active plymouth-start.service` and `systemctl show -p ActiveState --value plymouth-start.service`, expected `active` with `SubState` `exited` or `running` and `Result=success` after a clean boot), the merged unit body filtered for the three drop-in filenames and the directives this topic configures, and the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls — one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions. The properties the probe reads are `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `PrivateTmp`, `ReadWritePaths`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`, `SystemCallArchitectures`, `PrivateNetwork`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute`, `SystemCallFilter`, `CapabilityBoundingSet`, `Type`, and `Result`. The probe also reports the SELinux-domain inference via the static type-transition `sesearch -T -s init_t -t plymouthd_exec_t -c process` (the live-PID form is not applicable because the unit has exited), the `matchpathcon /usr/bin/plymouthd` mapping for the binary fcontext, and the `plymouth-quit-wait.service` post-boot status (`systemctl show -p ActiveState/SubState/Result --value plymouth-quit-wait.service`, expected `active`/`exited`/`success` as a passive boot-completion smoketest anchor). The `semodule -l | grep nnp_plymouth` lookup that confirms the CIL module is loaded is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_plymouth/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `Type` | `forking` |
| `ActiveState` | `active` |
| `SubState` | `exited` or `running` (set; environment-dependent — see note) |
| `Result` | `success` |
| `NoNewPrivileges` | `yes` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `yes` |
| `ProtectKernelTunables` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectControlGroups` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectHostname` | `yes` |
| `PrivateTmp` | `yes` |
| `ReadWritePaths` | substrings `/run/plymouth`, `/var/lib/plymouth`, `/var/spool/plymouth` all present |
| `LockPersonality` | `yes` |
| `RestrictRealtime` | `yes` |
| `RestrictSUIDSGID` | `yes` |
| `RestrictNamespaces` | `yes` |
| `SystemCallArchitectures` | `native` |
| `PrivateNetwork` | `yes` |
| `RestrictAddressFamilies` | `AF_UNIX` (single-element exact match) |
| `MemoryDenyWriteExecute` | `yes` |
| `SystemCallFilter` (expanded property output) | at least four of `read`, `write`, `openat`, `close`, `mmap`, `brk`, `exit_group`, `rt_sigaction` present |
| `SystemCallFilter` (class tokens read from `systemctl cat`) | all twelve of `@system-service`, `~@privileged`, `~@resources`, `~@debug`, `~@mount`, `~@cpu-emulation`, `~@obsolete`, `~@raw-io`, `~@reboot`, `~@swap`, `~@module`, `~@clock` present |
| `SystemCallFilter` (syslog re-add) | `syslog` present in the expanded effective filter |
| `CapabilityBoundingSet` | three-set exact match `CAP_SYS_ADMIN CAP_SYS_TTY_CONFIG CAP_CHOWN` |
| `plymouth-quit-wait.service` `ActiveState` / `SubState` / `Result` | `active` / `exited` / `success` |
| `semodule -l \| grep -w nnp_plymouth` | one line (sysadm_t-gated) |

The leading `-` on `-/run/plymouth` is consumed by systemd at parse time and is not part of the runtime-property output; the verify script therefore does not assert the prefix and asserts the three substrings only. For `RestrictAddressFamilies`, presence of any other family is drift and absence of `AF_UNIX` is drift. For `CapabilityBoundingSet`, presence of any other capability is drift and absence of any of the three is drift. For `SystemCallFilter`, the property output is the alphabetical syscall list, so the verify script asserts at least four of the eight `@system-service` anchor syscalls in the expanded form and reads `systemctl cat plymouth-start.service` separately to grep-match the literal class tokens (the subtractive form `@system-service` plus the eleven `~@*` subclasses).

Every other systemd directive is left at its stock default; the verify script does not assert values for `PrivateDevices`, `PrivateUsers`, `ProtectProc`, `ProcSubset`, `UMask`, `User`, `Group`, `RuntimeDirectory`, or `StateDirectory`. None of those directives are part of the topic-owned surface, and asserting them would mistake the absence of a topic-owned setting for drift.

plymouth-start settles into `active (exited)` after a graphical splash hand-off, or lingers as `active (running)` on a headless host with no display-manager hand-off, so a `MainPID` may or may not exist at verify time. The verify script therefore checks unit state (`ActiveState=active`, `SubState` is `exited` **or** `running`, `Result=success`) rather than PID liveness; the live-domain read off `/proc/<MainPID>/attr/current` is not applicable to this unit and is replaced by the static type-transition probe `sesearch -T -s init_t -t plymouthd_exec_t -c process` plus the `matchpathcon /usr/bin/plymouthd` mapping check.

> **SubState note.** `SubState` is asserted as a set (`exited` or `running`), not a single value, because the observed steady state depends on the boot environment. On a graphical desktop the display manager performs the splash hand-off and `plymouth-quit` brings plymouthd down, so the unit settles into `active (exited)`. On a headless host the live test observed plymouthd still running after both `plymouth-quit` and `plymouth-quit-wait` had completed (`exited`/`success`), leaving the unit `active (running)` — most plausibly because `plymouth-quit` runs with `--retain-splash` and, with no display manager to take the splash over, the daemon stays up. The precise trigger is environment-specific and is not security-relevant: the live test confirmed both states carry `ActiveState=active`, `Result=success`, a clean boot journal, and zero AVCs, so both are healthy and only `failed`/`dead` is drift. The `syslog` re-add row is the live-test-confirmed fix for the boot-time SIGSYS kill described under `99-process-restrict.conf`.

The role's modify stage is idempotent. The four shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, and `restorecon` handlers each fire only on a change to their notifying task. There is **no** `restart plymouth-start.service` handler — plymouth-start is at-boot-only and has already completed by the time the role finishes deploying. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

> The role's apply path is `daemon-reload` plus the next reboot, not `systemctl restart plymouth-start.service`; plymouth-start runs once during the early-boot sequence and the splash hand-off has already completed by the time the role finishes deploying, so the deploy lands in the live unit-state on the subsequent boot only.

The rollback posture is three-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_plymouth`, then `systemctl daemon-reload` and reboot. The NNP layer alone is reverted; the filesystem-and-process-isolation surface and the NNP-companion process-internal-restriction surface remain. **Stage 2**: in addition to Stage 1, remove `99-process-restrict.conf`. The entire NNP-and-process-internal-restriction surface is reverted; the filesystem-and-process-isolation surface remains. **Stage 3**: in addition to Stage 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. Each rollback stage is followed by `systemctl daemon-reload` and a reboot — the apply-path caveat above applies symmetrically to rollback. The recovery how-to covers the boot-failure variant of the rollback. plymouth-start is boot-critical: a misconfigured CIL module or a `NoNewPrivileges=yes` deploy without the matching CIL extension causes the boot splash to fail at next boot.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(plymouthd_t|plymouthd_exec_t|nnp_transition|plymouth)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Splash smoketest

The post-deploy splash validation uses two complementary checks. The drift-class anchor is the `plymouth-quit-wait.service` boot-completion check: after a clean boot the unit reports `ActiveState=active`, `SubState=exited`, `Result=success`, indicating that the splash hand-off completed and the plymouth dependency chain settled. The verify script asserts this anchor; any deviation is drift and signals that the splash hand-off hung or the dependency chain broke. The visual splash itself (the renderer's logo plus spinner during boot, the clean transition to the login screen) is not journal-traceable; the verify script states the expected visual outcome but does not assert it. The visual check is an operator-side responsibility on the next reboot after deploy.

The pre-hardening splash baseline is the operator-side companion to the post-deploy smoketest. Before deploying the four-artefact profile, capture:

```bash
systemctl is-active plymouth-start.service
systemctl show -p ActiveState,SubState,Result --value plymouth-start.service
systemctl show -p ActiveState,SubState,Result --value plymouth-quit-wait.service
journalctl -u plymouth-start.service -b 0 --no-pager | tail -10
journalctl -b 0 -p err -u plymouth-start.service --no-pager | tail -20
```

On a stock host, `is-active` returns `active` after boot (the unit is `active (exited)` because `Type=forking` settles to exited after the daemon forks), `plymouth-quit-wait.service` reports `active`/`exited`/`success`, the journal tail shows a single startup line per boot, and the error-stream tail is empty. A non-empty error stream signals a pre-existing plymouth issue (a broken theme, a DRM-driver mismatch on the host) that the operator should investigate before deploying the role; post-deploy errors would otherwise be misattributed to the hardening surface. The role's preflight stage runs the same recon and reports the outcome non-fatally.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → plymouthd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/plymouthd` at next boot under `no_new_privs` and prevent the boot splash from rendering.
- [ReadWritePaths runtime race](../../explanation/readwritepaths-runtime-race.md) — Why the leading `-` on `-/run/plymouth` is mandatory: plymouthd creates `/run/plymouth/` in its own startup code path before systemd's mount-namespace setup completes, and the `-`-prefix tells systemd to tolerate the missing path at bind-mount time.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — Why the role's preflight stage validates the daemon binary's fcontext mapping with a `matchpathcon /usr/bin/plymouthd` fail-fast: a stock `file_contexts` entry written against `/usr/sbin/plymouthd` would never match on a Fedora 44 host because the global `/usr/sbin → /usr/bin` path equivalency rewrites the lookup before the table is consulted.
