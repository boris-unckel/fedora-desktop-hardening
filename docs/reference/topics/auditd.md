<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# auditd

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of `auditd.service` on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/auditd.service.d/` and `/usr/local/share/selinux/`: a topic-owned hardening drop-in that adds six directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned single-rule SELinux CIL module that lifts the `init_t → auditd_t : process2 nnp_transition` denial that stock targeted policy carries for this domain. The end-state also includes the verify discipline (per-property reads, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion, audit-control and `DAEMON_START` smoketests, CIL module-presence check), the pre-hardening audit-stream baseline, an apply-path constraint that is structurally reboot-only because the stock vendor unit ships `RefuseManualStop=yes`, and a two-stage rollback posture. This topic does not cover `/etc/audit/auditd.conf` content, the audit-rule policy under `/etc/audit/rules.d/`, the audit-dispatch configuration under `/etc/audit/plugins.d/`, the `audit-rules.service` companion unit, the `audit-libs` companion package, the audit-tooling user-space (`auditctl` invocations beyond the smoketest, `ausearch` invocations beyond the AVC-posture filter and `DAEMON_START` smoketest, `aureport`, `aulast`, `aulastlog`, `ausyscall`, `autrace`), the `audit=0`/`audit=off` kernel-command-line boot-time-disable mechanism beyond the boundary-table row that names it, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: a topic-owned hardening drop-in that carries six directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned single-rule SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's main domain. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates what the F44 stock vendor unit already carries and what the topic therefore does not modify.

### Service identity

The unit `auditd.service` is shipped by the `audit` package and is the host's authoritative security-event log producer. The daemon binary is installed at `/usr/bin/auditd`. auditd runs as `root` throughout and performs no privilege drop. The unit is gated by two `ConditionKernelCommandLine=` clauses that prevent it from starting when the kernel command line carries `audit=0` or `audit=off`. The vendor unit ships no `RuntimeDirectory=`, no `StateDirectory=`, and no `LogsDirectory=`; auditd writes to `/var/log/audit/` (created by package install, owned `root:root`, SELinux type `auditd_log_t`) and to `/run/audit/` (created by the package's tmpfiles fragment at boot, before the unit's `ExecStart=` runs). Because the unit ships no `ReadWritePaths=` and `/run/audit/` is created by the package's tmpfiles fragment outside the unit's own management, the runtime path is not a self-managed runtime path of the unit.

| Property | Value |
|---|---|
| Unit | `auditd.service` |
| Type | `forking` |
| ExecStart | `/usr/bin/auditd` |
| User / group | `root` (no privilege drop) |
| PIDFile | `/run/audit/auditd.pid` |
| SELinux domain | `auditd_t` |
| Drop-in directory SELinux type | `auditd_unit_file_t` |
| Audit log directory | `/var/log/audit/` (`auditd_log_t`) |
| Runtime directory | `/run/audit/` (package-tmpfiles-created) |

The Fedora 44 audit package installs the daemon binary at `/usr/bin/auditd`. A Fedora 44 host carries a global `/usr/sbin → /usr/bin` path equivalency that rewrites every `/usr/sbin/<binary>` lookup before the file-context table is consulted; the F44 `/usr/sbin → /usr/bin` equivalency rewrites the lookup, and the role validates the mapping with a `matchpathcon` fail-fast against both `/usr/sbin/auditd` and `/usr/bin/auditd` (either path resolving to `auditd_exec_t` is sufficient). The class mechanism, the detection scan, and the mitigation form are documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

The F44 stock vendor unit ships a partial sandbox layer: three sandbox directives are already set by upstream and the topic-owned hardening surface explicitly does not restate them. The full set of stock directives this topic does not modify:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `Type=forking` | the daemon double-forks; systemd reads the `PIDFile=` for tracking |
| `PIDFile=/run/audit/auditd.pid` | systemd locates the daemon process via this file |
| `Restart=on-failure` | systemd restarts the unit on a non-clean exit |
| `RestartPreventExitStatus=2 4 6` | the documented intentional-exit codes are not restart-triggers |
| `RefuseManualStop=yes` | `systemctl stop auditd` and `systemctl restart auditd` are refused |
| `MemoryDenyWriteExecute=true` | upstream-shipped; the topic-owned profile does **not** restate this directive |
| `LockPersonality=true` | upstream-shipped; the topic-owned profile does **not** restate this directive |
| `RestrictRealtime=true` | upstream-shipped; the topic-owned profile does **not** restate this directive |
| `ConditionKernelCommandLine=!audit=0` and `!audit=off` | the unit does not start when the kernel command line disables auditing |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope. The table also implicitly states what the F44 stock unit does not ship — every other `Protect*=`, `Restrict*=` (other than `RestrictRealtime=`), `Private*=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `RestrictAddressFamilies=`, `NoNewPrivileges=`, `CapabilityBoundingSet=`, `User=`, `Group=`, `RuntimeDirectory=`, `StateDirectory=`, and `LogsDirectory=` directive is absent from the vendor unit. The absence is what the topic-owned hardening surface partially fills.

auditd is the daemon that produces the audit stream consumed by the four-tool diagnosis loop documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md); the verify discipline below applies the same loop against auditd's own audit stream.

The `audit` package ships the daemon binary `/usr/bin/auditd`, the systemd unit file at `/usr/lib/systemd/system/auditd.service`, the audit-rules unit at `/usr/lib/systemd/system/audit-rules.service`, the tmpfiles fragment that creates `/run/audit/` at boot, the audit-rules directory `/etc/audit/rules.d/`, the legacy audit configuration file `/etc/audit/auditd.conf`, the audit-dispatch configuration at `/etc/audit/plugins.d/`, and the user-space tooling (`auditctl`, `ausearch`, `aureport`, `aulast`, `aulastlog`, `ausyscall`, `autrace`). The companion `audit-libs` package ships the shared libraries used by the tooling and by other audit-aware applications. The role's preflight checks `audit` package presence and `auditctl` tooling availability; the role does not modify `/etc/audit/auditd.conf`, the rules under `/etc/audit/rules.d/`, the dispatch configuration at `/etc/audit/plugins.d/`, or the `audit-rules.service` unit. Audit-rule policy is operator-policy outside this topic.

### Three-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/auditd.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Topic-owned hardening surface (the six directives below). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_auditd.cil` | Topic-owned single-rule SELinux module that grants the `init_t → auditd_t : process2 nnp_transition` rule. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the topic-owned hardening surface as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push.

### `99-hardening.conf`

Path: `/etc/systemd/system/auditd.service.d/99-hardening.conf`.

```ini
[Service]
ProtectClock=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
SystemCallArchitectures=native
RestrictNamespaces=yes
PrivateDevices=yes
```

The drop-in carries the six-directive hardening surface that the F44 stock vendor unit does not ship. auditd is the host's kernel-audit-stream consumer (it reads via the netlink audit family) and the authoritative security-event log producer; continuity of the daemon is required for forensic and compliance purposes, so the topic-owned surface is conservative by design. Per-directive effect:

- `ProtectClock=yes` — denies `settimeofday(2)` and `adjtimex(2)` from auditd. The daemon does not write the host clock; clock-related syscalls are not part of its data path.
- `ProtectKernelModules=yes` — denies `init_module(2)`, `finit_module(2)`, and `delete_module(2)`. auditd does not load or unload kernel modules; it consumes events emitted by modules already loaded.
- `ProtectControlGroups=yes` — mounts the cgroup pseudo-filesystem read-only inside the unit's mount namespace. auditd does not write cgroup paths.
- `SystemCallArchitectures=native` — denies non-native syscall ABIs (the 32-bit personality on x86_64). auditd is built native-only; the directive eliminates the 32-bit syscall surface as a confused-deputy class.
- `RestrictNamespaces=yes` — denies `unshare(2)` and `setns(2)` and the namespace-creation flags of `clone(2)`. auditd does not create namespaces.
- `PrivateDevices=yes` — reduces the unit's `/dev` view to a minimal device set. auditd reads the kernel audit stream via the netlink audit family; it does not access `/dev` device nodes, so the minimal set is not a functional regression for this daemon.

`ProtectKernelLogs=yes` is **not** part of the topic-owned hardening surface; auditd reads the kernel audit buffer via the netlink audit family, and `ProtectKernelLogs=yes` would deny access to `/dev/kmsg` and the `syslog(2)` system call in a way that overlaps the kernel-log subsystem auditd's own data path depends on.

`MemoryDenyWriteExecute=`, `LockPersonality=`, and `RestrictRealtime=` are **not** restated by this drop-in because the F44 stock vendor unit already ships them; restating them in the topic-owned profile would erroneously claim topic-owned authorship of three directives whose authorship sits with upstream. The boundary table in the service-identity subsection enumerates the three upstream-shipped directives.

The profile does not include `ProtectSystem=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectHostname=`, `PrivateTmp=`, `ProcSubset=`, `ProtectProc=`, `RestrictAddressFamilies=`, `RestrictSUIDSGID=`, `UMask=`, `CapabilityBoundingSet=`, `SystemCallFilter=`, `User=`, or `Group=` directives. Extending the surface to those classes is operator-policy outside this topic and is not validated by the verify discipline this topic ships.

auditd runs as `root` throughout and performs no privilege drop, so the privilege-drop class that elsewhere requires a topic-owned SCF profile (see [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md)) does not apply to this daemon.

### `99-nnp.conf`

Path: `/etc/systemd/system/auditd.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon process, and the bit is inherited on every descendant exec. auditd does not exec helper binaries on its event-consumption path, so the inherited bit has no descendant-side functional consequence.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → auditd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture for the main domain is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t auditd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned single-rule CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_auditd.cil`

Path: `/usr/local/share/selinux/nnp_auditd.cil`.

```cil
(allow init_t auditd_t (process2 (nnp_transition)))
```

The single rule lifts the kernel NNP-transition denial for the daemon's main domain. auditd does not spawn helper subdomains on its event-consumption path; the single `init_t → auditd_t` rule is sufficient and no inter-domain helper rule ships in this module. The rule is loaded as a topic-owned CIL module rather than appended to a shared multi-service module to keep this topic's deploy and rollback footprint atomic at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_auditd` and removes only this topic's policy extension. Appending the rule to a shared module would couple this topic's deploy and rollback to the deploy and rollback of every other service that shares the module; topic-tier discipline rules out that coupling.

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_auditd.cil` from a `sysadm_r/sysadm_t` role-switch. Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). The kernel-NNP-transition mechanism the rule lifts is the same class documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

The drop-in directory `/etc/systemd/system/auditd.service.d/` and the two drop-in files inside it carry the SELinux type `auditd_unit_file_t` — a service-specialised `*_unit_file_t` type that stock targeted policy on Fedora 44 ships for auditd. This is anomalous compared to most topics in this tree: only auditd and cups carry a service-specialised `*_unit_file_t` type for the drop-in directory; `udisks2`, `smartd`, `NetworkManager`, `chronyd`, `dbus-broker`, and `avahi-daemon` all use the generic `systemd_unit_file_t`. The role pushes the drop-in files via `ansible.builtin.copy` invoked under `become_flags: "-r sysadm_r -t sysadm_t"` so that the install-time SELinux context lands on `auditd_unit_file_t` directly; a `restorecon` handler is wired anyway as a defence-in-depth reflex and is a no-op on a correctly installed file. The role's preflight stage runs `matchpathcon /etc/systemd/system/auditd.service.d/99-hardening.conf` and asserts the result resolves to `auditd_unit_file_t` as a fail-fast gate before the install task runs.

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/auditd.service.d/99-hardening.conf` | `0644` | `root:root` | `auditd_unit_file_t` |
| `/etc/systemd/system/auditd.service.d/99-nnp.conf` | `0644` | `root:root` | `auditd_unit_file_t` |
| `/usr/local/share/selinux/nnp_auditd.cil` | `0644` | `root:root` | `usr_t` |

### Apply path

auditd's stock vendor unit ships `RefuseManualStop=yes`, which makes the `systemctl restart auditd` path structurally unavailable: a restart is internally a stop-then-start sequence, and the stop step is refused with the message _'auditd.service may be requested by dependency only (it is configured to refuse manual start/stop)'_. Drop-in changes therefore cannot be activated by a restart of the running unit; the role's apply path is to push the artefacts and then prompt the operator for a reboot. Until reboot the configured drop-ins are present on disk and visible in `systemctl cat auditd.service` but not effective in the running daemon.

The role's `tasks/main.yml` ends with an Ansible `pause:` task that prompts the operator to reboot. The role does not issue `systemctl restart auditd` (the call would fail and could mask a separate apply-stage error). The role does issue `systemctl daemon-reload` after drop-in changes — `daemon-reload` is not refused by `RefuseManualStop=yes` and updates the merged-unit cache so that `systemctl cat auditd.service` reflects the new drop-ins immediately.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side and audit-control checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_auditd/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`audit`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `matchpathcon` mapping for both `/usr/sbin/auditd` and `/usr/bin/auditd`, an audit-control smoketest (`auditctl -s`) that runs under `sudo -r sysadm_r -t sysadm_t` and reports the kernel-audit `enabled`/`pid`/`backlog` status fields on a healthy host (and `SKIP needs sysadm_t` from a `staff_t` shell because the audit-control netlink interface requires privileged access), and the `semodule -l | grep nnp_auditd` lookup that confirms the CIL module is loaded (also `sysadm_t`-gated; reports `SKIP needs sysadm_t` from `staff_t`). The probe also reports the three upstream-shipped directives `MemoryDenyWriteExecute`, `LockPersonality`, and `RestrictRealtime` as informational baseline; their values are read but not asserted as topic-owned drift targets. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_auditd/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectControlGroups` | `yes` |
| `SystemCallArchitectures` | `native` |
| `RestrictNamespaces` | `yes` |
| `PrivateDevices` | `yes` |
| Live SELinux domain | `auditd_t` |
| `auditctl -s` `enabled` field | non-zero (sysadm_t-gated) |
| `ausearch -m DAEMON_START -ts boot` | one or more records (sysadm_t-gated) |
| `semodule -l \| grep nnp_auditd` | one line (sysadm_t-gated) |

Every other systemd directive is left at its stock default; the verify script does not assert values for `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `ProcSubset`, `ProtectProc`, `RestrictAddressFamilies`, `RestrictSUIDSGID`, `ProtectKernelTunables`, `ProtectHostname`, `UMask`, `CapabilityBoundingSet`, `SystemCallFilter`, or `ReadWritePaths`. None of those directives are part of the topic-owned surface, and asserting them would mistake the absence of a topic-owned setting for drift. The script also does not assert values for `ProtectKernelLogs`, `MemoryDenyWriteExecute`, `LockPersonality`, or `RestrictRealtime` — `ProtectKernelLogs` is deliberately excluded by the topic design (documented above), and the other three are upstream-shipped: their values are read and reported as informational only, with no topic-owned expected value.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `auditd_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The audit-control smoketest invokes `auditctl -s` under `sudo -r sysadm_r -t sysadm_t` and asserts exit `0` plus a non-zero `enabled` field in the output (`enabled 1` for the running configuration, `enabled 2` for kernel-locked configurations). The init-completion smoketest invokes `ausearch -m DAEMON_START -ts boot` under the same role-switch and asserts one or more records since boot — the `DAEMON_START` record is the canonical signal that auditd initialised the kernel-audit stream after boot. The `semodule -l | grep nnp_auditd` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

The role's modify stage is idempotent. Two drop-in INI files are pushed via `ansible.builtin.copy` invoked under `become_flags: "-r sysadm_r -t sysadm_t"` so that the install-time SELinux context lands on `auditd_unit_file_t` directly. The CIL module file is pushed via `ansible.builtin.copy` and notifies the `semodule install` handler on change. The `semodule install`, `daemon-reload`, and `restorecon` handlers each fire only on a change to their notifying task; no `restart` handler exists. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee. Drop-in changes are activated only by reboot; the role pushes the artefacts, runs `daemon-reload`, and then prompts the operator for a reboot. Apply-on-running-daemon is structurally unavailable for this Topic.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_auditd`, then `systemctl daemon-reload`; the NNP layer alone is reverted, the topic-owned hardening surface remains, and a reboot is required for the rollback to take effect. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`; the unit reverts entirely to the stock vendor configuration, and a reboot is required. The recovery how-to covers the boot-failure variant of the rollback. auditd is the host's authoritative security-event log producer; a misconfigured CIL module or a `NoNewPrivileges=yes` deploy without the matching CIL extension causes auditd to fail at boot, which leaves the host without audit-stream coverage until the next successful boot, and the recovery how-to is the operator's path through that failure mode.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(auditd_t|auditd_exec_t|auditd_log_t|auditd_etc_t|nnp_transition)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md) reads its records from this daemon's audit stream; the AVC-posture check above is therefore the diagnosis loop applied recursively against auditd's own records.

### Audit-stream smoketest

The post-deploy smoketest uses three audit-control checks that all run under `sudo -r sysadm_r -t sysadm_t` and report `SKIP needs sysadm_t` from a `staff_t` shell:

```bash
auditctl -s
auditctl -l
ausearch -m DAEMON_START -ts boot
```

`auditctl -s` exits `0` with stdout containing `enabled 1` (or `enabled 2` for kernel-locked configurations) plus a non-empty `pid` field matching the unit's `MainPID`. Failure on this is drift. `auditctl -l` exits `0`; an empty stdout is acceptable on a host without operator-installed audit rules, and a non-empty stdout lists the operator-installed rule set as informational — the smoketest does not assert any specific rule set is loaded because audit-rule policy is operator-policy outside this topic. `ausearch -m DAEMON_START -ts boot` exits `0` with stdout containing one or more `DAEMON_START` records since boot; an empty stdout is drift. The smoketest is functional, not a hardening assertion; it catches regressions where one of the six topic-owned hardening directives would silently break the daemon's audit-control or event-consumption path.

The pre-hardening audit-stream baseline is the operator-side companion to the post-deploy smoketest. Before deploying the three-artefact profile, capture:

```bash
systemctl is-active auditd.service
sudo -r sysadm_r -t sysadm_t auditctl -s
sudo -r sysadm_r -t sysadm_t auditctl -l
sudo -r sysadm_r -t sysadm_t ausearch -m DAEMON_START -ts boot
journalctl -b 0 -p err -u auditd.service --no-pager | tail -20
```

On a stock host with auditd active, `is-active` returns `active`, `auditctl -s` reports `enabled 1` (or `enabled 2` for kernel-locked configurations) plus the daemon's `pid`, `auditctl -l` lists the operator-installed rules (may be empty on a host without operator policy), `ausearch -m DAEMON_START` returns at least one record since boot, and the `journalctl` tail is empty. A non-empty error stream signals a pre-existing auditd issue that the operator should investigate before deploying the role; post-deploy errors would otherwise be misattributed to the hardening surface. The role's preflight stage runs the same recon and reports the outcome non-fatally.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → auditd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/auditd` at next boot under `no_new_privs`.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — Why the daemon binary at `/usr/bin/auditd` is matched through the global `/usr/sbin → /usr/bin` path equivalency before the file-context table is consulted, and why the role validates the mapping with a `matchpathcon` fail-fast against both `/usr/sbin/auditd` and `/usr/bin/auditd`.
