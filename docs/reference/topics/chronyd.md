<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# chronyd

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `chronyd.service` NTS-client time daemon on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/chronyd.service.d/` and `/usr/local/share/selinux/`: a topic-owned hardening drop-in that adds the four directives the F44 stock vendor unit does not already ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that enables the `init_t → chronyd_t : process2 nnp_transition` rule that stock targeted policy does not ship for this domain. The end-state assumes an NTS-client-only chrony configuration: no command-port bind, no NTP server-mode, no broadcast-server mode, no raw-socket measurement, no kernel routing-table manipulation. The end-state also includes the verify discipline (per-property reads, four-capability-absence assertion, port-123-bind absence assertion, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion), the NTS-client smoketest, the pre-hardening NTS-client sanity baseline, and a two-stage rollback posture. This topic does not cover `/etc/sysconfig/chronyd` content (the chrony-internal seccomp filter is upstream-managed operator-policy outside this topic), `/etc/chrony.conf` content (the NTS-client-only assumption is a boundary marker, not a configuration target), the chrony-internal seccomp filter mechanism, NTP-server-mode chrony deployments, the `chrony-doc` subpackage, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: a topic-owned hardening drop-in that carries the four directives the F44 stock vendor unit does not already ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's domain. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates the directives the F44 stock vendor unit already carries and the topic therefore does not modify.

### Service identity

The unit `chronyd.service` is shipped by the `chrony` package. The stock vendor file at `/usr/lib/systemd/system/chronyd.service` carries the directives this topic does not modify:

| Property | Value |
|---|---|
| Unit | `chronyd.service` |
| Type | `forking` |
| ExecStart | `/usr/sbin/chronyd $OPTIONS` |
| User / group | `chrony:chrony` |
| SELinux domain | `chronyd_t` |

The SELinux type-transition `init_t → chronyd_t` fires on the executable label `chronyd_exec_t` carried by the binary at `/usr/sbin/chronyd`. The `chrony` package ships the daemon binary, the `chronyc` client, the systemd unit file, and the default `/etc/chrony.conf`. The `chrony-doc` subpackage is operator-policy. The role's preflight stage checks the `chrony` package presence; the role does not interact with `/etc/chrony.conf` content or with `/etc/sysconfig/chronyd` content. The daemon performs an internal privilege drop after startup, leaving the long-running process running as the system user `chrony`.

The vendor unit ships `RuntimeDirectory=chrony` and `StateDirectory=chrony`. As a consequence, `/run/chrony` and `/var/lib/chrony` exist before the daemon's `ExecStart=` runs, and no boot-time mount-namespace race on a self-managed runtime path applies to this unit.

The F44 stock vendor unit is best-in-class hardened. The directives it already carries — and which the topic therefore does not duplicate — are:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `ProtectSystem=strict` | `/usr`, `/boot`, `/efi`, `/etc`, `/var` read-only |
| `RuntimeDirectory=chrony` | `/run/chrony` created before NAMESPACE step |
| `StateDirectory=chrony` | `/var/lib/chrony` created before NAMESPACE step |
| `ConfigurationDirectory=chrony` | `/etc/chrony` created at install time |
| `ProtectHome=yes` | operator home directories denied |
| `ProtectKernelTunables=yes` | `/proc/sys/*` writes denied |
| `ProtectKernelModules=yes` | `init_module(2)` denied |
| `ProtectKernelLogs=yes` | kernel log devices denied |
| `ProtectControlGroups=yes` | cgroup pseudo-fs read-only |
| `ProtectClock=yes` | `settimeofday(2)` / `adjtimex(2)` denied for non-clock-paths |
| `ProtectHostname=yes` | hostname denied |
| `PrivateTmp=yes` | private `/tmp` and `/var/tmp` |
| `RestrictNamespaces=yes` | `unshare(2)`, `setns(2)` denied |
| `RestrictRealtime=yes` | `SCHED_FIFO`/`SCHED_RR` denied |
| `RestrictSUIDSGID=yes` | SUID/SGID file creation denied |
| `LockPersonality=yes` | `personality(2)` denied |
| `MemoryDenyWriteExecute=yes` | `mmap` write+exec denied |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | three address families only |
| `SystemCallFilter=@system-service` | broad `@system-service` allowlist |
| `DeviceAllow=char-rtc r`, `char-pp r`, `char-pps r` | clock-related devices only |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope.

### Three-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/chronyd.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Topic-owned hardening surface (capability bounding-set reduction, `ProcSubset=pid`, `UMask=0027`, `SystemCallArchitectures=native`). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_chronyd.cil` | Topic-owned SELinux module that grants `init_t → chronyd_t : process2 nnp_transition`. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the topic-owned hardening surface as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/chronyd.service.d/99-hardening.conf`.

```ini
[Service]
CapabilityBoundingSet=~CAP_NET_ADMIN ~CAP_NET_BIND_SERVICE ~CAP_NET_BROADCAST ~CAP_NET_RAW
ProcSubset=pid
UMask=0027
SystemCallArchitectures=native
```

The drop-in adds only the four directives the F44 stock vendor unit does not already ship. The conservative shape follows from the boundary table in §"Service identity": the stock unit is best-in-class hardened, so the topic-owned hardening surface is restricted to a small additive set rather than a parallel sandbox stack. The topic does **not** layer a topic-side `SystemCallFilter=`, `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, `RestrictNamespaces=`, `LockPersonality=`, `Protect*=`, `Private*=`, or `DeviceAllow=` directive: stock already ships them, and overlaying them would either re-state stock policy or contradict it.

Directive notes:

- `CapabilityBoundingSet=~CAP_NET_ADMIN ~CAP_NET_BIND_SERVICE ~CAP_NET_BROADCAST ~CAP_NET_RAW` — drops the four network-related capabilities. The end-state assumes an NTS-client-only chrony configuration: no `chrony.conf` directive binds port 123 (no `bindcmdaddress` for the command port; no `port` directive for NTP server-mode), no broadcast-server mode, no raw-socket ICMP measurement, no kernel routing-table manipulation. Removing any of the four capabilities breaks a specific server-mode subsystem; server-mode chrony configurations are operator-policy outside this topic. The role's preflight stage runs a non-fatal sanity check (`ss -lnu` plus a `chrony.conf` recon) to flag a misalignment between the deployed end-state and the actual chrony configuration on the host.
- `ProcSubset=pid` — restricts the `/proc` view to per-process entries; `/proc/sys` and other-process entries are hidden. The daemon does not read sysctl values at runtime.
- `UMask=0027` — files the daemon creates default to mode `0640`, directories to `0750`. Consistent with the operator UMASK established in [UMASK 0027](../foundation/umask.md).
- `SystemCallArchitectures=native` — denies non-native syscall ABIs (the 32-bit personality on x86_64).

The chrony-internal seccomp filter is a separate, upstream-managed layer, and the topic states the boundary explicitly. The `/etc/sysconfig/chronyd` `OPTIONS="-F 2"` setting activates chrony's own internal seccomp filter on top of systemd's `SystemCallFilter=`; the Topic does not modify `/etc/sysconfig/chronyd` and treats the chrony-internal-seccomp layer as upstream-managed operator-policy outside this Topic.

chrony's stock `SystemCallFilter=@system-service` plus the `OPTIONS="-F 2"` chrony-internal seccomp layer provide the privilege-drop class coverage that elsewhere requires a topic-owned SCF profile (see [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md)).

### `99-nnp.conf`

Path: `/etc/systemd/system/chronyd.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child. A future operator-policy chrony helper pipeline would inherit the bit; on a stock NTS-client deployment, the daemon spawns no helpers.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → chronyd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t chronyd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_chronyd.cil`

Path: `/usr/local/share/selinux/nnp_chronyd.cil`.

```cil
(allow init_t chronyd_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_chronyd.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_chronyd` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts, see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/chronyd.service.d/99-hardening.conf` | `0644` | `root:root` | `chronyd_unit_file_t` |
| `/etc/systemd/system/chronyd.service.d/99-nnp.conf` | `0644` | `root:root` | `chronyd_unit_file_t` |
| `/usr/local/share/selinux/nnp_chronyd.cil` | `0644` | `root:root` | `usr_t` |

Stock targeted policy on Fedora 44 or later carries a type-transition `init_t → chronyd_unit_file_t : file create` for files under `/etc/systemd/system/chronyd.service.d/`. The role's `restorecon` after `ansible.builtin.copy` is what triggers the relabel from the install-time default (typically `staff_u:object_r:systemd_unit_file_t` when the operator drops the file from a `staff_t` shell) to the unit-specific type. Without the relabel the merged unit still runs because systemd reads merged units regardless of label, but `ls -lZ` shows the wrong type and a future audit flags it.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_chronyd/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`chrony`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `chronyc tracking` NTS-client smoketest output, the `ss -lnu | grep ':123'` port-bind recon, and the `semodule -l | grep nnp_chronyd` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_chronyd/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `CapabilityBoundingSet` | none of `cap_net_admin`, `cap_net_bind_service`, `cap_net_broadcast`, `cap_net_raw` present |
| `ProcSubset` | `pid` |
| `UMask` | `0027` (decimal `23` form returned by `systemctl show` is normalised to the octal form before comparison) |
| `SystemCallArchitectures` | `native` |
| Live SELinux domain | `chronyd_t` |
| `ss -lnu \| grep ':123'` | empty output (no port-123 bind) |
| `chronyc tracking` | exit `0`, output contains a non-empty `Reference ID` line |
| `semodule -l \| grep nnp_chronyd` | one line (sysadm_t-gated) |

Two normalisation conventions are load-bearing. `systemctl show -p UMask --value` returns the umask as a decimal integer (`23` for octal `0027`); the verify script normalises both observed and expected to the octal form before comparison. `systemctl show -p CapabilityBoundingSet --value` returns the resolved bounding set as a whitespace-separated lower-case capability list; the verify script asserts the four-capability-absence as a positive check on the absence of `cap_net_admin`, `cap_net_bind_service`, `cap_net_broadcast`, and `cap_net_raw` in that list. A full positive enumeration of the expected bounding set is policy-dependent (the residual capability set varies across `chrony` package versions), so the four-capability-absence is the topic's claim.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `chronyd_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The port-123-bind absence is checked via `ss -lnu | grep ':123'`; on an NTS-client-only deployment the grep returns no line, and a non-empty result is drift for this topic's NTS-client-only end-state. The `chronyc tracking` check is read-only and works from `staff_t` without escalation; it is the primary functional smoketest. The `semodule -l | grep nnp_chronyd` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(chronyd_t|nnp_transition|chronyd)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### NTS-client smoketest

The post-deploy smoketest uses the public chrony state stack:

```bash
chronyc tracking
chronyc -N sources
chronyc ntpdata
```

On a correctly hardened host with a working NTS upstream, `chronyc tracking` returns exit `0` with a `Reference ID` line that identifies the upstream peer and a `System time` line that bounds the local clock offset. `chronyc -N sources` returns at least one source in state `^*` (selected primary) or `^+` (combined). `chronyc ntpdata` returns a non-empty NTS-key state line. The smoketest is functional, not a hardening assertion; it catches regressions where the four-capability drop or `ProcSubset=pid` would silently break an NTS-client subsystem (rare on the F44 chrony NTS-client path, which uses none of the dropped capabilities and reads no `/proc/sys` at runtime, but the smoketest is the operator's signal). The role captures the same `chronyc tracking` baseline in the preflight stage and the post-deploy state is compared against the captured baseline.

The pre-hardening NTS-client sanity baseline is the operator-side companion to the post-deploy smoketest. Before deploying the three-artefact profile, capture:

```bash
chronyc tracking
ss -lnu | grep ':123' || echo "no port-123 bind (NTS-client-only confirmed)"
grep -E '^(allow|deny|bindcmdaddress|port )' /etc/chrony.conf || echo "no server-mode directives"
```

On a stock NTS-client host, `chronyc tracking` returns a populated state and the two grep commands print the `(NTS-client-only confirmed)` and `no server-mode directives` lines. A `bindcmdaddress` entry, a `port` entry, an `allow` entry, or a `deny` entry signals a server-mode chrony configuration; the role's preflight stage runs the same recon and reports the outcome non-fatally — a misalignment is an operator-policy decision, not a fail-fast (the role does not refuse to deploy on a server-mode host, but the deployed `CapabilityBoundingSet=` will break server-mode features).

The role's modify stage is idempotent. The three shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_chronyd`, then `systemctl daemon-reload` and `systemctl restart chronyd.service`. The NNP layer alone is reverted; the topic-owned hardening surface remains. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback. chronyd's stock vendor unit ships `RuntimeDirectory=chrony` and `StateDirectory=chrony`, so the boot-failure class on a self-managed runtime path does not apply to this unit; a misconfigured CIL module (a wrong target-domain in a manual edit, for example) can still cause an NNP-denial cascade, and the Recovery-Pointer banner below is the operator's path through that variant.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → chronyd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/sbin/chronyd` at next boot under `no_new_privs`.
