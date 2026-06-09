<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# thermald

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `thermald.service` CPU thermal-management daemon on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/thermald.service.d/`: a namespace-default baseline drop-in that establishes the `Protect*` family plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, and `SystemCallArchitectures=`; an isolated `NoNewPrivileges=yes` drop-in; and a process-internal kernel-restriction drop-in carrying `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, an additive plus subtractive `SystemCallFilter=` pair, and an empty `CapabilityBoundingSet=` that drops all stock-allowed capabilities. The end-state also includes the platform-conditional Soll-state (a host whose CPU exposes a Dynamic Platform and Thermal Framework table reaches `active(running)` with the daemon under `init_t`; a host without that platform table reaches `inactive(dead)` after the binary's clean self-detected exit), the verify discipline (per-property reads, platform-symmetric `ActiveState`/`SubState`/`Result` assertion, AVC-clean and SECCOMP-clean assertions, fcontext and stock-policy boundary assertions), and a three-stage rollback posture. This topic does not cover the operator-side `/etc/thermald/thermal-conf.xml` configuration surface, the Dynamic Platform and Thermal Framework table contents and platform-vendor-specific thermal policies, the per-CPU model-specific-register layout, the `/dev/cpu/*/msr` character-device interface itself, the kernel `intel_pstate` or `amd_pstate` driver layer, the `mcelog.service` companion daemon (out of scope under operator policy because its `ConditionPathExists=` skips on hosts without the relevant ACPI table), or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: three drop-in INI files under `/etc/systemd/system/thermald.service.d/`. The three drop-ins layer the namespace-default baseline, the `NoNewPrivileges=yes` switch, and the process-internal kernel restrictions in separate files so the rollback surface splits layer-by-layer. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates the directives the F44 stock vendor unit ships and does not ship and that fixes the structural property that distinguishes this topic from the sibling hardware-class topics: thermald has no service-specific SELinux subtype in stock targeted policy, runs in `init_t`, and consequently ships no topic-owned CIL module.

### Service identity

The unit `thermald.service` is shipped by the `thermald` package. The stock vendor file at `/usr/lib/systemd/system/thermald.service` is sparse:

| Property | Value |
|---|---|
| Unit | `thermald.service` |
| Type | `dbus` |
| ExecStart | `/usr/bin/thermald --no-daemon --dbus-enable --adaptive` |
| Initial daemon UID / GID | `0` / `0` (no `User=` directive in the vendor unit) |
| Steady-state UID / GID | `0` / `0` (no internal privilege drop) |
| SELinux runtime domain | `init_t` |

The `ExecStart=` line carries no leading `-` (dash) prefix; a non-zero exit of the binary is reported to systemd as a failed unit start unless the binary's own exit-status convention treats the exit as success. The `--adaptive` argument is the vendor-shipped form on Fedora 44; a future package update that changes the argument set requires a manifest revision. The stock vendor unit ships **no** `RuntimeDirectory=`, `StateDirectory=`, `ConfigurationDirectory=`, `LogsDirectory=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, or any other sandbox directive. The hardening surface is therefore entirely operator-side: the namespace-default baseline drop-in, the isolated NNP drop-in, and the process-internal kernel-restriction drop-in are the topic's full contribution. The unit ships no `ReadWritePaths=` directive in any artefact this topic deploys, and the topic does not introduce one; the boot-time runtime-path race that affects daemons that self-create directories under `/run/<svc>/` does not apply to this unit.

The single most distinguishing structural property of this topic is that thermald has **no** service-specific SELinux subtype in stock targeted policy on Fedora 44 or later. `seinfo --type` does not list `thermald_t` or `thermald_exec_t`; `matchpathcon /usr/bin/thermald` resolves to `bin_t`, the generic executable label. The kernel ships no `type_transition init_t bin_t : process <domain>` rule for thermald, so the `execve(2)` of `/usr/bin/thermald` from PID 1 does not transition the daemon out of `init_t` — the daemon runs in `init_t` (an identity transition from PID 1) for its entire lifetime. This single structural fact cascades into the topic's design:

- The deploy profile ships **three** drop-in INI files (and not four). There is no fourth topic-owned SELinux CIL module because the kernel's NNP-transition constraint has no source-target distinction to evaluate when the source and target domain are both `init_t`; an identity transition has no allow-rule prerequisite. The empty preflight `sesearch` result that motivates a CIL extension on sibling hardware-class topics has no analogue here.
- The role ships no `community.general.sefcontext` mitigation; with no service-specific subtype to assert, the F44 sbin/bin-equivalency rewrite has no `<daemon>_exec_t` mapping for it to disrupt.
- The verify discipline asserts the absence of `thermald_t` and `thermald_exec_t` in the running policy and the `bin_t` mapping for `/usr/bin/thermald`. A future stock-policy update introducing one of these types is drift requiring a manifest revision (the topic would then need to add a topic-owned CIL module and the corresponding cross-link, analogous to the sibling hardware-class topics).

The platform-conditional Soll-state is the second distinguishing property of this topic, and it is symmetric: there are two well-defined Soll states, not one.

- On a host whose CPU exposes a Dynamic Platform and Thermal Framework table — predominantly Intel Core, Xeon, and Atom-class hosts — the `thermald --adaptive` binary loads the platform thermal tables and runs as a long-lived dbus daemon. The Soll state is `ActiveState=active`, `SubState=running`, `Result=success`, with the daemon under `init_t` and `MainPID > 0`.
- On a host without that platform table — including all current AMD Ryzen, EPYC, and Threadripper-class hosts — the binary detects the missing platform support, emits one journal line of the form `Unsupported cpu model or platform`, exits with status `0` (`SUCCESS`), and the service ends in `ActiveState=inactive`, `SubState=dead`, `Result=success`. The systemd `Condition*=` checks (if any are inherited from the unit) pass on both classes; the platform split is the binary's own self-detection, not a `Condition*=` directive in the unit.

The verify discipline below accepts either Soll state and does not assert a single `ActiveState`. The cosmetic deployment rationale that motivates rolling the three-artefact profile out on every host regardless of CPU class is documented near the recovery-posture note at the end of §"Verification".

The `thermald` package ships the daemon binary at `/usr/bin/thermald`, the systemd unit file at `/usr/lib/systemd/system/thermald.service`, the dbus service activation file at `/usr/share/dbus-1/system-services/org.freedesktop.thermald.service`, the system-bus policy file at `/usr/share/dbus-1/system.d/thermald.conf`, the operator configuration file at `/etc/thermald/thermal-conf.xml` (sample), and the platform thermal-table data files under `/usr/share/thermald/`. Stock targeted policy ships **no** `thermald_t` domain, **no** `thermald_exec_t` file context, and **no** `thermald_unit_file_t` file context — the absence of all three is consistent with the runtime `init_t` domain and the generic `systemd_unit_file_t` label on `/usr/lib/systemd/system/thermald.service`. The role's preflight stage asserts package presence; the role does not interact with `/etc/thermald/thermal-conf.xml` (operator-policy outside this topic) and does not read the platform thermal-table data files.

### Three-artefact deploy profile

The hardening profile splits across three drop-in INI files under `/etc/systemd/system/thermald.service.d/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-default baseline (`Protect*` family, `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `SystemCallArchitectures=`). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (`MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, additive plus subtractive `SystemCallFilter=` pair, empty `CapabilityBoundingSet=`). |

Three drop-ins, no fourth artefact. Unlike the sibling hardware-class topics, this topic ships **no** topic-owned SELinux CIL module; the reason is the structural property of this unit stated under §"Service identity" above and elaborated under §"`99-nnp.conf`" below. The three-INI granularity splits the rollback surface so an operator can revert layer-by-layer without losing the underlying baseline. Removing `99-process-restrict.conf` alone reverts the kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE) while leaving NNP and the namespace-default baseline in effect. Removing `99-nnp.conf` in addition reverts NNP. Removing `99-hardening.conf` in addition reverts the namespace-default baseline. The three-stage rollback documented under §"Verification" atomizes the layer-by-layer reverts.

There is no deploy ordering invariant of the form "load CIL before drop-in" because no CIL module ships. The role's `tasks/main.yml` orders the three drop-in pushes, the `restorecon` handler, and the daemon-reload-and-restart handler in the natural sequence; no `meta: flush_handlers` synchronization between a CIL-load step and the drop-in step is required.

### `99-hardening.conf`

Path: `/etc/systemd/system/thermald.service.d/99-hardening.conf`.

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

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. thermald reads `/etc/thermald/thermal-conf.xml` and the platform thermal tables exposed under `/sys/firmware/acpi/tables/`; both are read paths, no write access required.
- `ProtectHome=yes` — operator home directories are inaccessible. The daemon does not consume per-user configuration.
- `ProtectKernelTunables=yes` / `ProtectKernelModules=yes` / `ProtectKernelLogs=yes` — the sysctl interface, the kernel-module IOCTL paths, and the kernel-log devices are denied. thermald reads thermal sensors and CPU model-specific registers via the `/dev/cpu/*/msr` character devices and `/sys/class/thermal/*/temp` sysfs entries; none of the protected-kernel surfaces are touched.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only. thermald does not adjust resource limits.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. thermald does not coordinate temporary state with other processes.
- `ProtectClock=yes` / `ProtectHostname=yes` — `settimeofday(2)` / `adjtimex(2)` and the hostname interfaces are denied.
- `LockPersonality=yes` — `personality(2)` is denied.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` policies are denied.
- `RestrictSUIDSGID=yes` — SUID and SGID file creation is denied.
- `SystemCallArchitectures=native` — the 32-bit personality on x86_64 is denied.

The baseline does **not** include `PrivateMounts=no`. thermald is not a mount-manager daemon; the implicit `PrivateMounts=true` enable that the `Protect*` directives carry has no operator-visible effect for this unit because thermald issues no `mount(2)` calls. The boundary is stated here once as a fact about this profile.

The baseline does **not** include `PrivateDevices=yes`. `PrivateDevices=yes` would mask `/dev/cpu/*/msr` and break the daemon's only privileged read path on hosts where the daemon runs steady-state; the directive is deliberately omitted (default `no`).

### `99-nnp.conf`

Path: `/etc/systemd/system/thermald.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child. The kernel also enforces the invariant that capability reductions made under `no_new_privs` are **permanent** for the daemon's lifetime — once the `CapabilityBoundingSet=` is constrained, the daemon cannot regain a dropped capability even if it possesses the syscalls to do so. For this unit the practical consequence of the permanence invariant is mild: the deploy profile drops the bounding set to empty in `99-process-restrict.conf`, and the binary in `--adaptive` mode does not need to regain any capability post-init.

This topic does **not** ship a topic-owned CIL module and the role does **not** run a `sesearch -A -s init_t -t <svc>_t -c process2 -p nnp_transition` pre-test. The reason is structural and follows from §"Service identity" above: stock targeted policy on Fedora 44 has no `thermald_t` domain, the binary at `/usr/bin/thermald` carries the generic `bin_t` label, and the kernel's lack of a `type_transition init_t bin_t : process <domain>` rule for thermald means the daemon runs in `init_t` (identity transition from PID 1). The kernel's NNP-transition constraint applies to **distinct** source and target domains; an identity transition from `init_t` to `init_t` has no source-target distinction to evaluate, so the kernel allows the `execve(2)` under `no_new_privs` without consulting a `process2 / nnp_transition` allow rule. This is the load-bearing reason this topic ships no fourth deploy artefact.

The deploy ordering is correspondingly simpler than the sibling hardware-class topics. Without a CIL module to load, there is no "load CIL before drop-in" sequencing requirement. The role's `tasks/main.yml` orders the three drop-in pushes, the `restorecon` handler, and the daemon-reload-and-restart handler in the natural sequence; no `meta: flush_handlers` synchronization is needed.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/thermald.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
CapabilityBoundingSet=
```

Directive notes:

- `MemoryDenyWriteExecute=yes` — the daemon cannot create executable-and-writable memory mappings. thermald has no JIT or self-modifying-code path and tolerates MDWE without functional regression.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` — only Unix-domain sockets and Netlink are reachable. `AF_UNIX` covers systemd manager IPC and the system-bus dbus socket (the binary's `--dbus-enable` mode publishes its API on the system bus); `AF_NETLINK` covers audit-event posting and uevent reception. thermald has no IP-stack requirement.
- `SystemCallFilter=@system-service` — the broad allowlist seed.
- `SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock` — the subtractive group strips eleven syscall classes from the allowlist.
- `CapabilityBoundingSet=` (empty) — the daemon's capability bounding set is reduced to the empty set, dropping all stock-allowed capabilities. On a host where the daemon runs steady-state, the empty bounding set is the strongest reduction available and is sufficient because thermald reads model-specific registers and sysfs thermal sensors via file-mode access (the daemon runs as root, so the open of `/dev/cpu/*/msr` succeeds on file mode `0600 root:root` alone, without `CAP_SYS_RAWIO`). On a host where the binary exits cleanly before exercising any capability-gated syscall, the bounding-set reduction is observationally cosmetic for that platform class — neither protective in operation nor harmful in absence.

systemd's `SystemCallFilter=` directive is multi-line additive, but this unit ships exactly two lines: the seed allowlist `@system-service` and the subtractive group `~@privileged …`. The absence of additive privilege-drop carve-out lines (the `set{groups,resuid,resgid,reuid,regid,uid,gid}` family or `capset` / `capget`) is intentional and structural: thermald performs no internal privilege drop. On hosts where the daemon runs steady-state, it runs as `uid=0` from `ExecStart=` to process exit; on hosts where the binary exits cleanly after self-detection, it runs as `uid=0` for the brief window between `execve(2)` and `exit(0)`. In neither case does the daemon call `setresuid(2)`, `capset(2)`, or any other privilege-pipeline syscall. The boundary marker that places this topic on the negative side of the multi-stage privilege-drop pattern is summarised in §"Related patterns" below.

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/thermald.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/thermald.service.d/99-nnp.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/thermald.service.d/99-process-restrict.conf` | `0644` | `root:root` | `systemd_unit_file_t` |

Stock targeted policy on Fedora 44 ships **no** service-specific subtype for thermald drop-ins, consistent with the absence of a `thermald_t` runtime domain. The drop-in files carry the generic `systemd_unit_file_t` label that `init_t → systemd_unit_file_t : file create` resolves to. The role's `restorecon` after `ansible.builtin.copy` is what triggers the relabel from the install-time default to the generic unit-file type.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_thermald/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`thermald`), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the `matchpathcon /usr/bin/thermald` mapping (expected `bin_t` on a stock host — surfacing the structural fact that motivates the no-CIL design), the daemon journal for context, and the platform-conditional live-process probes. On a host where thermald is `active(running)`: the live SELinux domain via `awk -F: '{print $3}' /proc/<MainPID>/attr/current` (expected `init_t`) and the live UID and GID via `awk '/^Uid:|^Gid:/{print}' /proc/<MainPID>/status` (expected `0 / 0`). On a host where thermald is `inactive(dead)`: `MainPID` is reported as `0` and the `/proc/<MainPID>/*` probes are skipped with a `SKIP — service inactive (Soll on hosts without DPTF)` note. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_thermald/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `Type` | `dbus` |
| `Result` | `success` (both Soll states) |
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `CapabilityBoundingSet` (whitespace-stripped, lowercased) | empty string |
| `RestrictAddressFamilies` (source-order, not sorted) | `AF_UNIX AF_NETLINK` |
| `SystemCallFilter` length-plus-anchor | observed `--value` length `>= 1500` bytes; substrings `epoll_wait`, `recvfrom` both present |
| `SystemCallArchitectures` | `native` |
| `ProtectSystem` | `full` |
| `matchpathcon /usr/bin/thermald` | resolves to `bin_t` |
| `seinfo --type \| grep -wE 'thermald_t\|thermald_exec_t'` | empty |
| Live SELinux domain (DPTF-bearing host) | `init_t` |
| Live UID / GID (DPTF-bearing host) | `0` / `0` (root throughout — no privilege drop) |

Three normalisation conventions are load-bearing. `systemctl show -p CapabilityBoundingSet --value` returns the empty string when the bounding set is empty; the verify script lowercases and whitespace-strips the observed value before comparing against the empty-string expected value, so a single non-empty capability appearing in the resolved output is drift. `systemctl show -p RestrictAddressFamilies --value` preserves the source order of the drop-in directive (the directive is a positive whitelist whose semantics are order-independent, but the property output is order-preserving), so the verify script compares the observed value against the source-order hardcoded value `AF_UNIX AF_NETLINK`. `systemctl show -p SystemCallFilter --value` returns the fully resolved filter as a multi-thousand-byte string; the verify script checks the observed value with a length-plus-anchor pair — length `>= 1500` bytes (a conservative lower bound that catches a truncated or empty result) plus the presence of the literal substrings `epoll_wait` and `recvfrom` (the two anchor the `@system-service` group expansion and are stable across systemd versions on Fedora 44). The verify script does **not** anchor on `setgroups`, `setuid`, or `capset` — those tokens are intentionally absent because the unit ships no additive privilege-drop carve-out.

The platform-symmetric `ActiveState`/`SubState`/`Result` set accepts either of two well-defined Soll states. The verify script branches on `MainPID`: a value greater than `0` selects the DPTF-bearing branch (`ActiveState=active`, `SubState=running`, `Result=success`), and a value of `0` selects the DPTF-less branch (`ActiveState=inactive`, `SubState=dead`, `Result=success`). On the DPTF-bearing branch, liveness is checked through `[ -d /proc/${main_pid} ]` (ownership-independent — see [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md)); the live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected literal `init_t` (not `unconfined_service_t`, not `thermald_t`); the live UID and GID are both expected to be `0`. On the DPTF-less branch, the `/proc/<MainPID>/*` probes are skipped, and the journal must contain at least one line matching `Unsupported cpu model|Unsupported platform` since boot — the binary's signature exit reason on hosts without the platform table. A host whose state is neither of the two — for example, `ActiveState=failed` with non-zero `Result` — is drift and is reported by the verify script as `FAIL`.

The verify script also asserts the stock-policy boundary directly: `seinfo --type` does not list `thermald_t` or `thermald_exec_t`, and `matchpathcon /usr/bin/thermald` resolves to `bin_t`. A future stock-policy update that introduces one of these types or rewrites the `matchpathcon` mapping is drift requiring a manifest revision (the topic would then need to add a topic-owned CIL module and the corresponding cross-link, analogous to the sibling hardware-class topics). The check runs from `staff_t` without escalation. The verify script does **not** run `semodule -l | grep nnp_thermald` — no such module ships.

### AVC and SECCOMP posture

On a correctly applied host, the role-switched queries return zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot \
  | grep -E '(thermald|nnp_transition)'
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot \
  | grep 'comm="thermald"'
```

The verify script runs both filters and treats any hit as drift. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md). The AVC-clean assertion catches an SELinux-side regression — for example, a future stock-policy update that introduces a `thermald_t` subtype that the topic's three-INI profile is not aligned with. The SECCOMP-clean assertion catches a `SystemCallFilter=`-induced kill on a DPTF-bearing host where the daemon runs steady-state. On a DPTF-less host the SECCOMP-clean assertion is trivially satisfied because the binary exits before any SCF-evaluated syscall after the seed-allowed `execve(2)`.

The role's modify stage is idempotent. The three shipping artefacts (the three drop-in INI files) are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `daemon-reload`, `restart thermald`, and `restorecon thermald` handlers each fire only on a change to their notifying task. There is no `semodule install` handler (no CIL artefact ships) and no `community.general.sefcontext` task (no F44 sbin/bin-equivalency mitigation needed because thermald has no service-specific domain to assert). The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is three-stage. **Stage 1**: remove `99-process-restrict.conf` and run `daemon-reload && restart`: `rm /etc/systemd/system/thermald.service.d/99-process-restrict.conf && systemctl daemon-reload && systemctl restart thermald.service`. The kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE) are reverted; the namespace-default baseline and NNP remain in effect. On a DPTF-less host the restart re-runs the binary's exit-with-`Unsupported cpu model` path; on a DPTF-bearing host the daemon resumes under the relaxed restrictions. **Stage 2**: in addition to Stage 1, remove `99-nnp.conf`: `rm /etc/systemd/system/thermald.service.d/99-nnp.conf && systemctl daemon-reload && systemctl restart thermald.service`. The NNP layer is reverted. The namespace-default baseline remains. There is **no** SELinux unload step in this stage — unlike the sibling hardware-class topics, this topic ships no topic-owned CIL module to unload, so Stage 2 here is correspondingly simpler. **Stage 3**: in addition to Stages 1 and 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration (which ships nothing). The boot-failure risk for this topic is structurally low: without an NNP-transition allow-rule prerequisite and without a CIL extension, the canonical NNP-side boot-failure cascade does not apply. The most likely failure mode is a daemon-side regression on a DPTF-bearing host where the empty bounding set or the subtractive seccomp group surfaces a sandbox bug; in that case Stage 1 is the corresponding rollback.

The three-artefact profile is deployed on every host regardless of CPU class for portability and operator-fleet uniformity reasons. A host that is CPU-replaced or VM-cloned to a DPTF-bearing baseline activates the daemon at next boot, and the drop-ins take effect without a separate deploy step. The deploy is operator-fleet hygiene; an empty bounding set with an inactive daemon is observationally indistinguishable from no drop-in deployed, so the cosmetic deploy is neither a regression of the empty bounding set nor an active confinement on the DPTF-less host class. The recovery how-to covers the boot-failure variant.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) — The class of trap covered there does **not** apply to this unit. thermald runs as `uid=0` whenever the binary is alive — on hosts where the daemon runs steady-state as a long-lived process, on hosts where the binary exits cleanly for the brief window between `execve(2)` and `exit(0)`. It performs no `setgroups(2)`, no `setresuid(2)`, no `capset(2)`. Because no internal privilege drop is performed, the `99-process-restrict.conf` here ships only the seed `@system-service` allowlist plus the subtractive group, with no additive privilege-drop carve-out lines and an empty `CapabilityBoundingSet=`. This unit is the second canonical example of the negative-case boundary the Pattern names — daemons that do not exhibit the trap because they never perform an internal drop.
