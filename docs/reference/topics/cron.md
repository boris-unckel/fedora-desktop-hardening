<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# cron

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `crond.service` deferred-job-execution daemon shipped by the `cronie` package on a Fedora 44 or later host. The end-state ships a four-artefact deploy profile under `/etc/systemd/system/crond.service.d/` and `/usr/local/share/selinux/`: a Phase-A namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` layer drop-in, a process-internal kernel-restriction drop-in that carries the cronjob-user-switch privilege-drop carve-out (one positive `SystemCallFilter=` carve-out plus a three-cap `CapabilityBoundingSet=`), and a topic-owned SELinux CIL module that enables both the boot-failure-class `init_t → crond_t` and the confinement-leak-class `crond_t → system_cronjob_t` `process2 nnp_transition` rules. The end-state also includes the verify discipline (per-property reads, alphabetical capability sort, source-order address-family check, length-plus-anchor `SystemCallFilter` check, `[ -d /proc/${main_pid} ]` liveness, AVC-clean and SECCOMP-clean assertions, `matchpathcon` fcontext assertion, cronjob spawn-domain assertion via a one-minute test cronjob), a three-stage rollback posture, and the conservative `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` choice tied to cron's payload-launcher data-path shape. This topic does **not** cover `/etc/crontab`, the operator-policy directories `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`, the access-control files `/etc/cron.allow` and `/etc/cron.deny`, the per-user crontab spool content under `/var/spool/cron/<user>/`, the `EnvironmentFile=/etc/sysconfig/crond` content, the `/etc/anacrontab` file, the `cronie-anacron` and `cronie-noanacron` companion subpackages, the `crontab(1)` user-space tooling beyond the in-role test cronjob smoketest, the `aide-check.service` systemd-timer (a separate unit unrelated to cron), the kernel `CONFIG_CGROUP_PIDS` cgroup constraint, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state ships **four** artefacts: three drop-in INI files under `/etc/systemd/system/crond.service.d/` plus one CIL module under `/usr/local/share/selinux/`. The three-drop-in granularity splits the rollback surface so an operator can revert layer-by-layer without losing the underlying baseline; removing `99-process-restrict.conf` alone reverts the kernel-level process restrictions while leaving NNP and the namespace-default baseline in force, removing `99-nnp.conf` in addition reverts NNP, and removing `99-hardening.conf` in addition reverts the namespace-default baseline. The CIL module is the last lever (it is harmless on its own once the NNP drop-in is gone). The three-stage rollback documented under §"Idempotence and rollback" atomises the layer-by-layer reverts.

### Service identity

The unit `crond.service` is shipped by the `cronie` package. The stock vendor file at `/usr/lib/systemd/system/crond.service` is sparse:

| Property | Value |
|---|---|
| Unit | `crond.service` |
| Type | `simple` |
| ExecStart | `/usr/sbin/crond -n $CRONDARGS` |
| EnvironmentFile | `/etc/sysconfig/crond` (operator-policy; not modified by this role) |
| Initial daemon UID / GID | `0` / `0` (no `User=` directive in the vendor unit) |
| Steady-state UID / GID | `0` / `0` (cronjob spawn forks per-job processes that drop to the per-job UID at execve) |
| SELinux runtime domain | `crond_t` |

The SELinux type-transition `init_t → crond_t` fires on the executable label `crond_exec_t` carried by the daemon binary. On Fedora 44 or later the `cronie` package places the binary at `/usr/sbin/crond`; the F44 `/usr/sbin → /usr/bin` global path equivalency rewrites the lookup target so `matchpathcon /usr/sbin/crond` resolves via the canonical `/usr/bin/crond` entry. The role's preflight runs both `matchpathcon` calls and requires `crond_exec_t` from at least one of the two as fail-fast. The class mechanism — why the equivalency rewrites the lookup target before the file-context table is consulted, and why the canonical-side label is the one the kernel's type-transition relies on — is documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

The vendor unit ships **no** `RuntimeDirectory=`, `StateDirectory=`, `ConfigurationDirectory=`, `LogsDirectory=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, or any other sandbox directive. The Phase-A baseline is therefore an operator-side full namespace-default suite, not an incremental layer on top of an upstream-hardened unit. The hardening surface consists entirely of the four artefacts this topic deploys. This topic ships **no** `ReadWritePaths=` directive in any artefact; cron has no daemon-self-managed runtime path under unit-own management, the per-user crontab spool lives under `/var/spool/cron/` (which is below `/var` and remains writable under `ProtectSystem=full`), and the `ProtectSystem=full`-not-`strict` choice is the load-bearing decision that keeps the runtime-race surface absent from this profile.

The `cronie` package ships the daemon binary at `/usr/sbin/crond` (with `/usr/bin/crond` as the post-merge canonical path under the F44 equivalency), the systemd unit file at `/usr/lib/systemd/system/crond.service`, the systemd environment file template at `/etc/sysconfig/crond`, the system crontab template at `/etc/crontab`, the operator-policy drop-in directories `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`, the per-user crontab spool directory `/var/spool/cron/`, the `crontab(1)` user-space tooling, and the SELinux file-context entries that map `/usr/bin/crond` to `crond_exec_t`. The companion subpackage `cronie-anacron` ships `anacron(8)` and `/etc/anacrontab`; `cronie-noanacron` is the conflicting subpackage that ships an empty `/etc/cron.daily/0anacron` to prevent anacron-style spool catch-up. The role's preflight stage asserts `cronie` package presence and `crontab` tooling availability; the role does **not** modify `/etc/crontab`, the operator-policy directories under `/etc/cron.{d,hourly,daily,weekly,monthly}/`, the access-control files `/etc/cron.allow` and `/etc/cron.deny`, the per-user spool content under `/var/spool/cron/`, the `EnvironmentFile` at `/etc/sysconfig/crond`, or the `anacrontab` file. Cronjob policy is operator-policy outside this topic.

### Four-artefact deploy profile

The end-state ships three drop-in INI files under `/etc/systemd/system/crond.service.d/` (mode `0644 root:root`, label `crond_unit_file_t`) plus one CIL module under `/usr/local/share/selinux/` (mode `0644 root:root`, label `usr_t`):

| File | Layer |
|---|---|
| `99-hardening.conf` | Phase-A namespace-default baseline (`Protect*` family + `PrivateTmp=` + `LockPersonality=` + `RestrictRealtime=` + `RestrictSUIDSGID=` + `SystemCallArchitectures=`). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only; isolated for granular rollback. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (MDWE, address-family restriction, additive plus subtractive `SystemCallFilter=` pair, one positive `SystemCallFilter=` carve-out for the cronjob-user-switch privilege-drop, three-cap `CapabilityBoundingSet=`). |
| `nnp_crond.cil` | Topic-owned SELinux CIL module with two allow rules (boot-failure class plus confinement-leak class), loaded at priority 400. |

Stock targeted policy on Fedora 44 does map a service-specialised type for these files: `file_contexts` carries `/usr/lib/systemd/system/crond.*` → `crond_unit_file_t`, and the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency extends it to the drop-in path. The drop-in *directory* keeps the generic `systemd_unit_file_t`, because the mapping entry is qualified with `--` and therefore matches regular files only.

### `99-hardening.conf`

Path: `/etc/systemd/system/crond.service.d/99-hardening.conf`.

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

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. crond reads its operator configuration under `/etc/cron.d/`, `/etc/crontab`, and the per-user spool at `/var/spool/cron/<user>/`; the value `full` (rather than `strict`) leaves `/var` and `/run` writable so cronjob payloads can land their per-job state and so crond's own inotify-watched spool path remains accessible without an explicit carve-out. Tightening to `strict` would require an explicit `ReadWritePaths=/var/spool/cron` and `ReadWritePaths=/run` carve-out and would surface the runtime-race trap class on the `/run` carve-out; the topic deliberately stays at `full` to keep the runtime-race surface absent from this profile.
- `ProtectHome=yes` — operator home directories are inaccessible to the daemon process itself. Cronjob payloads that need to read or write a home directory run **after** the daemon spawns the per-job process tree via the cronjob-user-switch path; the spawned child re-enters its own mount namespace at execve time and the parent's `ProtectHome=yes` does not propagate to the child's view of `/home`.
- `ProtectKernelTunables=yes` / `ProtectKernelModules=yes` / `ProtectKernelLogs=yes` — sysctl interfaces, the kernel-module IOCTL paths, and the kernel-log devices are denied. crond reads spool files and writes mail output to `sendmail(1)`; neither path requires the protected-kernel surfaces. Cronjob payloads that legitimately interact with kernel tunables (rare in operator-policy practice) re-enter their own mount namespace at execve; the parent daemon's restriction is structurally separate.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only for the daemon. crond does not adjust resource limits.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. Cronjob payloads that need to share `/tmp` state with other operator-side processes run under their own user UID after the privilege drop and re-enter the host `/tmp` view at execve.
- `ProtectClock=yes` / `ProtectHostname=yes` — `settimeofday(2)`, `adjtimex(2)`, and the hostname interfaces are denied.
- `LockPersonality=yes` — `personality(2)` is denied.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` policies are denied.
- `RestrictSUIDSGID=yes` — SUID and SGID file creation is denied. Cronjob payloads invoked by crond inherit the directive's effect; an operator-policy cronjob that creates SUID files would surface drift here, which is stated as a known boundary.
- `SystemCallArchitectures=native` — the 32-bit personality on x86_64 is denied.

The Phase-A baseline does **not** include `PrivateMounts=no`. crond is not a mount-manager daemon; the implicit `PrivateMounts=true` enable that the `Protect*` directives carry has no operator-visible effect for this unit because crond issues no `mount(2)` calls. The Phase-A baseline does **not** include `PrivateDevices=yes`. Cronjob payloads frequently touch `/dev` device nodes (the package-default `mlocate updatedb` cronjob reads `/dev/null`, operator-policy cronjobs may write `/dev/log` for syslog forwarding); `PrivateDevices=yes` would mask the device set in a way that is not safely default for an arbitrary cronjob population. The directive is deliberately omitted (default `no`).

### `99-nnp.conf`

Path: `/etc/systemd/system/crond.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

Descendants inherit the `no_new_privs` bit. NNP also has the kernel-level invariant that capability reductions are **permanent** for the daemon's lifetime — once the `CapabilityBoundingSet=` is constrained, the daemon cannot regain a dropped capability even if it possesses the syscalls to do so. This invariant is the load-bearing reason the cronjob-user-switch carve-out under §"`99-process-restrict.conf`" requires both the `CapabilityBoundingSet=CAP_SETUID CAP_SETGID …` line and the `SystemCallFilter=set{groups,gid,uid,resgid,resuid,regid,reuid}` line: the capability layer must permit `CAP_SETUID`/`CAP_SETGID` so the cronjob-user-switch succeeds, and the syscall-filter layer must permit the syscall family that performs the switch.

The boot-failure-class SELinux pre-test confirms the negative posture for stock policy:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t crond_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty (no allow rule). The empty return motivates rule 1 of the topic-owned CIL module described under §"`nnp_crond.cil`". The class mechanism — the kernel-level NNP-transition constraint that the rule satisfies — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The confinement-leak-class SELinux pre-test confirms the negative posture for the inter-domain class:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s crond_t -t system_cronjob_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty (no allow rule). The empty return motivates rule 2 of the topic-owned CIL module. The class mechanism — why an existing `type_transition` rule from a daemon domain to a child domain requires a `process2 nnp_transition` companion under NNP, and what the operator observes on a host where the companion rule is absent — is documented in [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md).

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/crond.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
SystemCallFilter=setgroups setgid setuid setresgid setresuid setregid setreuid
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
```

Directive notes:

- `MemoryDenyWriteExecute=yes` — the daemon cannot create executable-and-writable memory mappings. crond is a C daemon with no JIT, no Python interpreter, and no self-modifying-code path; MDWE is tolerated without functional regression. Cronjob payloads that legitimately require executable-and-writable mappings (for example, a JIT-using cronjob runtime) would surface drift; per-cronjob analysis is the operator's path through such a case.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` — Unix-domain sockets, IPv4, IPv6, and Netlink are reachable. `AF_UNIX` covers systemd manager IPC and `sendmail(1)` invocation; `AF_INET` and `AF_INET6` cover cronjob payloads with legitimate IP-stack requirements (operator-policy cronjobs that send mail via a remote SMTP relay or fetch state via HTTP would, and the conservative choice is to permit them); `AF_NETLINK` covers audit-event posting and uevent reception. The four-family set is broader than the typical hardware-class daemon's two-family set because cron's data-path shape is fundamentally different: cron is a payload-launcher whose job set is operator-defined, while a fixed-loop daemon has no third-party-payload requirement. The choice is stated as a positive design decision tied to cron's payload-launcher shape, not as a target for a future incremental tightening pass.
- `SystemCallFilter=@system-service` — the broad allowlist seed.
- `SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock` — the subtractive group strips eleven syscall classes from the allowlist.
- `SystemCallFilter=setgroups setgid setuid setresgid setresuid setregid setreuid` — the additive privilege-drop carve-out: after the subtractive group above strips the privilege-related syscalls from the allowlist, this positive line re-adds the seven members of the `set{groups,gid,uid,resgid,resuid,regid,reuid}` family that the daemon's cronjob-user-switch fork-and-exec path calls. systemd's directive composition rules treat a later positive `SystemCallFilter=` as additive on top of the subtractive group.
- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH` — three capabilities. `CAP_SETUID` and `CAP_SETGID` are required because the NNP invariant makes capability reductions permanent: without the two capabilities in the bounding set at daemon start, the kernel denies the cronjob-user-switch call with `EPERM` even though the syscall-filter layer permits the syscall. `CAP_DAC_READ_SEARCH` is the third capability and is cron-specific: the daemon reads the per-user crontab spool under `/var/spool/cron/<user>/` (mode `0600`, owner `<user>`, group `<user>`) before forking the cronjob; without `CAP_DAC_READ_SEARCH` the read fails with `EACCES` for any crontab not owned by `root`. The bounding set deliberately **excludes** `CAP_DAC_OVERRIDE` (which would also permit DAC-bypassing writes) and **excludes** `CAP_FOWNER`, `CAP_CHOWN`, `CAP_FSETID`, `CAP_SETPCAP` (none of which are part of the cronjob-spawn data path). The bounding-set choice is therefore the minimum set that keeps the package-default cronjob-spawn pipeline functional while denying the broader DAC-bypass that `CAP_DAC_OVERRIDE` would grant.

systemd's `SystemCallFilter=` directive is multi-line additive — the order is "seed allowlist (`@system-service`) → subtractive group (`~@privileged …`) → positive carve-out". This topic ships **one** positive carve-out line because cron's privilege-drop is a single fork-and-exec at cronjob-spawn time rather than a multi-stage in-process drop pipeline. The class mechanism — the kernel constraint that drives the layering, the EPERM-vs-SIGSYS distinction between capability-layer and syscall-filter-layer denials, and the audit-record uid-fingerprint that pinpoints which drop-stage failed — is documented in [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md).

### `nnp_crond.cil`

Path: `/usr/local/share/selinux/nnp_crond.cil`. Loaded at priority 400 via `semodule -X 400 -i nnp_crond.cil`.

```cil
(allow init_t crond_t (process2 (nnp_transition)))
(allow crond_t system_cronjob_t (process2 (nnp_transition)))
```

The module ships two allow rules in a single file. **Rule 1** addresses the boot-failure class: stock targeted policy on Fedora 44 ships no `allow init_t crond_t : process2 nnp_transition` rule, so the `NoNewPrivileges=yes` drop-in fails the kernel-level NNP-transition constraint at next boot without the rule in place. **Rule 2** addresses the confinement-leak class: stock targeted policy ships the type-transition `type_transition crond_t cron_spool_t : process system_cronjob_t` (so `run-parts` invocations and per-user cronjobs end up in `system_cronjob_t`) but does **not** ship the `process2 nnp_transition` companion rule that NNP requires. Without rule 2, cronjob processes under NNP stay confined as `crond_t` — the type-transition is denied silently, the cronjob still runs, but the SELinux confinement intended by the stock policy does not take effect, and the audit log accumulates `nnp_transition`-denial AVCs for the inter-domain class.

The module is topic-owned rather than appended to a shared module. Topic-tier discipline isolates the role's deploy and rollback footprint: the rollback step `semodule -X 400 -r nnp_crond` removes only this topic's extension; no other topic's CIL module is touched. Priority 400 places the extension above stock targeted policy (which ships at priority 100) but below any operator-side high-priority overrides.

The two rules are loaded in a single `semodule -X 400 -i` call. The class mechanism for rule 1 is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md); the class mechanism for rule 2 is documented in [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md).

### File modes

The four shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/crond.service.d/` | `0755` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/crond.service.d/99-hardening.conf` | `0644` | `root:root` | `crond_unit_file_t` |
| `/etc/systemd/system/crond.service.d/99-nnp.conf` | `0644` | `root:root` | `crond_unit_file_t` |
| `/etc/systemd/system/crond.service.d/99-process-restrict.conf` | `0644` | `root:root` | `crond_unit_file_t` |
| `/usr/local/share/selinux/nnp_crond.cil` | `0644` | `root:root` | `usr_t` |

Nothing assigns `crond_unit_file_t` at creation time: a file written into the drop-in directory inherits that directory's `systemd_unit_file_t`, and the role's `restorecon -F -v -R` on the drop-in directory is what moves it to the mapped type. The `-R` covers the directory itself, which this role creates and which no other step revisits; the `-F` additionally resets the SELinux user field, which a type-only comparison such as `restorecon -n` never reports. The role's preflight `matchpathcon` gate checks the daemon binary (`/usr/bin/crond` → `crond_exec_t`), not the drop-ins; the drop-in contexts are asserted by the role's verify stage. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_cron/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`cronie`), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `matchpathcon` mappings for `/usr/sbin/crond` and `/usr/bin/crond` (informational; reports both labels for the F44 sbin/bin-merge cross-check), and the daemon journal for context. The properties surveyed include `NoNewPrivileges`, `MemoryDenyWriteExecute`, `ProtectSystem`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `PrivateTmp`, `ProtectClock`, `ProtectHostname`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `SystemCallArchitectures`, `RestrictAddressFamilies`, `CapabilityBoundingSet`, `SystemCallFilter`, and `MainPID`. The CIL-module-presence check (`semodule -l | grep nnp_crond`) is gated behind a `sysadm_t` domain check and reports `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_cron/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `ProtectSystem` | `full` |
| `ProtectHome` | `yes` |
| `ProtectKernelTunables` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectControlGroups` | `yes` |
| `PrivateTmp` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectHostname` | `yes` |
| `LockPersonality` | `yes` |
| `RestrictRealtime` | `yes` |
| `RestrictSUIDSGID` | `yes` |
| `SystemCallArchitectures` | `native` |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6 AF_NETLINK` (source-order four-element multiset; whitespace normalised, source order preserved) |
| `CapabilityBoundingSet` | `cap_dac_read_search cap_setgid cap_setuid` (alphabetically sorted; the live property reports the bounding set sorted) |
| `SystemCallFilter` | length-plus-anchor: live value length exceeds 200 bytes **and** contains `@system-service`, `~@privileged`, `setresuid`, `setgroups` |
| Live SELinux domain | `crond_t` |
| Cronjob-spawn domain | `system_cronjob_t` (third colon-separated field of the test cronjob's `/proc/self/attr/current` read) |
| `matchpathcon /usr/sbin/crond` or `matchpathcon /usr/bin/crond` | at least one resolves to `crond_exec_t` (either-or fail-fast) |
| `semodule -l | grep nnp_crond` | one line (sysadm_t-gated; `SKIP` from staff_t) |

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The `SystemCallFilter` check is a length-plus-anchor assertion rather than a byte-exact comparison. The seed `@system-service` group expands to several hundred syscalls and the expanded form depends on the systemd version's group definition (upstream-managed and outside topic scope); the verify script asserts that the live value's length exceeds 200 bytes and contains four substring anchors (`@system-service` for the positive seed, `~@privileged` for the subtractive group, `setresuid` and `setgroups` for the additive carve-out).

The cronjob-spawn domain assertion is the live confirmation that rule 2 of the CIL module is in effect. The verify script writes a one-minute test cronjob at `/etc/cron.d/diataxis-verify-test` (mode `0644 root:root`, content `* * * * * root /usr/bin/cat /proc/self/attr/current > /run/diataxis-verify-cron.out 2>/dev/null`), waits up to 90 seconds for the next minute boundary plus a small slack, reads `/run/diataxis-verify-cron.out`, and asserts the content's third colon-separated field is `system_cronjob_t`. A live read of `system_cronjob_t` confirms rule 2 is in effect; a live read of `crond_t` is drift signalling the inter-domain CIL rule is missing or did not take effect. The verify script removes the test cronjob and the output file at end-of-run regardless of outcome.

The `matchpathcon` boundary is asserted as either-or: at least one of `matchpathcon /usr/sbin/crond` and `matchpathcon /usr/bin/crond` resolves to `crond_exec_t`. The F44 equivalency rewrites the lookup target so the canonical-side path is the one the SELinux type-transition relies on; if **neither** path resolves to `crond_exec_t`, the verify reports drift and exits non-zero.

The verify script does **not** assert `EXPECTED_PRIVATE_DEVICES`, `EXPECTED_PRIVATE_MOUNTS`, `EXPECTED_PROC_SUBSET`, `EXPECTED_PROTECT_PROC`, `EXPECTED_RESTRICT_NAMESPACES`, `EXPECTED_USER`, or `EXPECTED_GROUP`. None of these directives are part of the topic-owned surface; presence of any of these `EXPECTED_*` constants in `verify.sh` is drift against the present end-state.

### AVC and SECCOMP posture

On a correctly applied host, the role-switched queries return zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(crond_t|crond_exec_t|crond_log_t|cron_spool_t|system_cronjob_t|nnp_transition)'
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot \
  | grep -E '(comm="crond"|exe="/usr/sbin/crond"|exe="/usr/bin/crond")'
```

The verify script runs both filters and treats any hit as drift. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md). A SECCOMP hit on a correctly applied host would point to a syscall that the cronjob-user-switch path or the cronjob-spawn fork-and-exec attempted and that the subtractive `~@privileged @resources` group stripped from the allowlist; the audit-record `uid=` field's value pinpoints which drop-stage the kill landed on.

### Pre-hardening recon

Before deploying the four artefacts, the operator runs:

```bash
systemctl is-active crond.service
systemctl show crond.service -p MainPID --value
sudo -r sysadm_r -t sysadm_t journalctl -b 0 -p err -u crond.service \
  --no-pager | tail -20
sudo -r sysadm_r -t sysadm_t journalctl -b 0 -u crond.service \
  --no-pager | grep -iE '(STARTUP|inotify|cron-mailer)' | tail -20
```

On a stock host with crond active, `is-active` returns `active`, `MainPID` returns a non-zero PID, the error stream is empty (a non-empty error stream signals a pre-existing crond issue that the operator should investigate before deploying the role; post-deploy errors would otherwise be misattributed to the hardening surface), and the journalctl tail captures the package-default startup signature including the `STARTUP` line and the `running with inotify support` line. The role's preflight stage runs the same recon and reports the outcome non-fatally.

### Idempotence and rollback

The role's modify stage is idempotent. The three drop-in INI files and the CIL source are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `restorecon`, `daemon-reload`, and `restart crond` handlers each fire only on a change to the notifying task. The `meta: flush_handlers` after the CIL source push enforces the load-before-deploy invariant for `99-nnp.conf`: the CIL module is installed before the NNP drop-in is dropped in. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The unit ships no `RefuseManualStop=` directive, so the `systemctl restart crond.service` apply path is structurally available; reboot is **not** required for the drop-ins to take effect on the running daemon (per-process directives such as `NoNewPrivileges=` and `CapabilityBoundingSet=` apply at the next service start, which the role triggers via the `restart crond` handler). The two-rule CIL module is loaded by `semodule -X 400 -i` and takes effect immediately for SELinux policy lookups; the inter-domain `crond_t → system_cronjob_t : process2 nnp_transition` allow rule applies to the next cronjob spawn after the load.

The rollback posture is three-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension:

```bash
rm /etc/systemd/system/crond.service.d/99-nnp.conf
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r nnp_crond
systemctl daemon-reload
systemctl restart crond.service
```

Reverts only the NNP layer plus its enabling SELinux extension. The Phase-A baseline and the process-internal kernel restrictions remain. **Stage 2**: in addition to Stage 1, remove `99-process-restrict.conf` and `systemctl daemon-reload && systemctl restart crond.service`. The unit reverts to the Phase-A namespace-default baseline. **Stage 3**: in addition to Stage 2, remove `99-hardening.conf` and `systemctl daemon-reload && systemctl restart crond.service`. The unit reverts entirely to the stock vendor configuration.

cron is the host's authoritative deferred-job-execution daemon; a misconfigured CIL module (for example, a wrong target-domain in a manual edit) or a `NoNewPrivileges=yes` deploy without the matching CIL extension causes crond to fail at boot, which leaves the host without scheduled-job execution until the next successful boot. The recovery how-to is the operator's path through that failure mode.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Stock targeted policy ships no `allow init_t crond_t : process2 nnp_transition` rule. Without rule 1 of the topic-owned CIL module, the `NoNewPrivileges=yes` drop-in fails the kernel-level NNP-transition constraint at next boot.
- [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md) — Stock targeted policy ships the `type_transition crond_t cron_spool_t : process system_cronjob_t` rule but no `process2 nnp_transition` companion rule. Without rule 2 of the topic-owned CIL module, cronjob processes under NNP stay confined as `crond_t` rather than transitioning into `system_cronjob_t`. cron is one of the canonical service anchors for this Pattern.
- [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) — The cronjob-user-switch fork-and-exec path is a single-stage privilege-drop instance of the class. The positive `SystemCallFilter=` carve-out plus the `CAP_SETUID`/`CAP_SETGID` capability addition implement the layered solution the Pattern documents.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — The `cronie` package installs the binary at `/usr/sbin/crond` and the F44 `/usr/sbin → /usr/bin` global path equivalency rewrites the lookup target before the file-context table is consulted. The role's preflight runs both `matchpathcon` calls and requires `crond_exec_t` from at least one as fail-fast.
