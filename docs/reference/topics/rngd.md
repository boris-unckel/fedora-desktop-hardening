<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# rngd

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `rngd.service` hardware-RNG entropy-gathering daemon on a Fedora 44 or later host. The end-state is a five-artefact deploy profile under `/etc/systemd/system/rngd.service.d/` and `/usr/local/share/selinux/`: a namespace-default baseline drop-in that establishes the `Protect*` family plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, and `SystemCallArchitectures=`; an isolated `NoNewPrivileges=yes` drop-in; a process-internal kernel-restriction drop-in that carries `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, an additive plus subtractive `SystemCallFilter=` pair, three additive `SystemCallFilter=` lines for the multi-stage privilege-drop carve-out, and a two-line `CapabilityBoundingSet=` for the `/dev/hwrng` open plus the privilege-drop carve-out; and a topic-owned SELinux CIL module that grants the `init_t → rngd_t : process2 nnp_transition` rule that stock targeted policy does not ship for this domain. The end-state also includes the verify discipline (per-property reads, alphabetical capability-sort, source-order address-family check, length-plus-anchor `SystemCallFilter=` check, `[ -d /proc/${main_pid} ]` liveness, live UID and GID probe of the `daemon` steady-state, AVC-clean and SECCOMP-clean assertions, `matchpathcon` fcontext assertion), the entropy-pool smoketest, the pre-hardening entropy-pool sanity baseline, and a three-stage rollback posture. This topic does not cover `/etc/sysconfig/rngd` content (the `-D daemon:daemon` privilege-drop instruction and the entropy-source disable list `-x pkcs11 -x nist -x qrypt -x namedpipe -x jitter` are operator-policy outside this topic), the kernel `hw_random` driver layer, the `rdrand` CPU instruction availability, jitter-entropy operator-policy decisions, the `rng-tools` companion utilities (`cuse`, `rngtest`), or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines five shipping artefacts: three drop-in INI files under `/etc/systemd/system/rngd.service.d/` and one CIL module under `/usr/local/share/selinux/`. The three drop-ins layer the namespace-default baseline, the `NoNewPrivileges=yes` switch, and the process-internal kernel restrictions in separate files so the rollback surface splits layer-by-layer. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates the directives the F44 stock vendor unit ships and does not ship.

### Service identity

The unit `rngd.service` is shipped by the `rng-tools` package. The stock vendor file at `/usr/lib/systemd/system/rngd.service` is sparse:

| Property | Value |
|---|---|
| Unit | `rngd.service` |
| Type | `simple` |
| ExecStart | `/usr/sbin/rngd -f $RNGD_ARGS` |
| EnvironmentFile | `/etc/sysconfig/rngd` |
| ConditionVirtualization | `!container` |
| ConditionKernelCommandLine | `!fips=1` |
| Initial daemon UID / GID | `0` / `0` (no `User=` directive in the vendor unit) |
| Steady-state UID / GID | `2` / `2` (`daemon:daemon`, after the daemon's internal privilege drop under `-D daemon:daemon`) |
| SELinux domain | `rngd_t` |

The SELinux type-transition `init_t → rngd_t` fires on the executable label `rngd_exec_t` carried by the daemon binary. On Fedora 44 or later the `rng-tools` package places the binary at `/usr/bin/rngd`; `/usr/sbin/rngd` is a compatibility symlink that resolves to `/usr/bin/rngd`. Stock targeted policy ships an fcontext mapping that resolves `/usr/bin/rngd` to `rngd_exec_t`; `matchpathcon /usr/bin/rngd` returns `rngd_exec_t` on a stock host, so the F44 sbin-bin equivalency does not surface drift for this unit and the role's preflight stage validates the mapping with a `matchpathcon` check that fails fast on a `bin_t` mapping. The role does not ship a `community.general.sefcontext` mitigation for this binary.

The vendor unit ships **no** `RuntimeDirectory=`, `StateDirectory=`, `ConfigurationDirectory=`, `LogsDirectory=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, or any other sandbox directive. The hardening surface is therefore entirely operator-side: the namespace-default baseline drop-in, the isolated NNP drop-in, the process-internal kernel-restriction drop-in, and the topic-owned CIL module are the topic's full contribution. The operator-side surface is the topic's responsibility; no upstream-shipped sandbox directive is duplicated or contradicted.

The `rng-tools` package ships the daemon binary `/usr/bin/rngd` with the `/usr/sbin/rngd` compatibility symlink, the systemd unit file, the SELinux service-specific subtype set (`rngd_t`, `rngd_exec_t`, `rngd_unit_file_t` shipped by stock targeted policy at priority 100), and the default `/etc/sysconfig/rngd` containing the `-D daemon:daemon` privilege-drop instruction and the entropy-source disable list `-x pkcs11 -x nist -x qrypt -x namedpipe -x jitter`. The role's preflight stage asserts package presence and reads `/etc/sysconfig/rngd` non-fatally as a fact for post-deploy comparison; it does not modify the sysconfig file. The daemon's internal privilege drop to `daemon:daemon` is the load-bearing reason the process-internal drop-in must carry the multi-stage privilege-drop carve-out described below.

The unit ships no `ReadWritePaths=` directive in any artefact this topic deploys, and the topic does not introduce one; the boot-time runtime-path race that affects daemons that self-create directories under `/run/<svc>/` does not apply to this unit and the topic does not invoke its Pattern slug.

### Five-artefact deploy profile

The hardening profile splits across three drop-in INI files under `/etc/systemd/system/rngd.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-default baseline (`Protect*` family, `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `SystemCallArchitectures=`). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (`MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, additive plus subtractive `SystemCallFilter=` pair, three additive `SystemCallFilter=` lines for the multi-stage privilege-drop carve-out, two `CapabilityBoundingSet=` lines for the `/dev/hwrng` open plus the privilege-drop carve-out). |
| `nnp_rngd.cil` | Topic-owned SELinux module that grants `init_t → rngd_t : process2 nnp_transition`. |

The four-INI granularity (three drop-ins plus one CIL module) splits the rollback surface so an operator can revert layer-by-layer without losing the underlying baseline. Removing `99-process-restrict.conf` alone reverts the kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE, multi-stage privilege-drop carve-out) while leaving NNP and the namespace-default baseline in effect. Removing `99-nnp.conf` in addition reverts NNP. Removing `99-hardening.conf` in addition reverts the namespace-default baseline. Removing the CIL module is the last lever; it is harmless on its own once the NNP drop-in is gone. The three-stage rollback documented under §"Verification" atomizes the layer-by-layer reverts.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install handler and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/rngd.service.d/99-hardening.conf`.

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

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. The daemon needs no write access to these paths; the entropy-pool target `/dev/random` is a character device under `/dev`, unaffected by `ProtectSystem=`.
- `ProtectHome=yes` — operator home directories are inaccessible. The daemon does not consume per-user configuration.
- `ProtectKernelTunables=yes` / `ProtectKernelModules=yes` / `ProtectKernelLogs=yes` — the sysctl interface, the kernel-module IOCTL paths, and the kernel-log devices are denied. The daemon reads from `/dev/hwrng` (kernel `hw_random` Misc-Device) and feeds the kernel entropy pool via `/dev/random`; neither path requires the protected-kernel surfaces.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only. The daemon does not adjust resource limits.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. The daemon does not coordinate temporary state with other processes.
- `ProtectClock=yes` / `ProtectHostname=yes` — `settimeofday(2)` / `adjtimex(2)` and the hostname interfaces are denied.
- `LockPersonality=yes` — `personality(2)` is denied.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` policies are denied.
- `RestrictSUIDSGID=yes` — SUID and SGID file creation is denied.
- `SystemCallArchitectures=native` — the 32-bit personality on x86_64 is denied.

The baseline does **not** include `PrivateMounts=no`. The daemon is not a mount-manager; the implicit `PrivateMounts=true` enable that the `Protect*` directives carry has no operator-visible effect for this unit because the daemon issues no `mount(2)` calls. The boundary is stated here once as a fact about this profile.

### `99-nnp.conf`

Path: `/etc/systemd/system/rngd.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child. The kernel also enforces the invariant that capability reductions made under `no_new_privs` are **permanent** for the daemon's lifetime — once the `CapabilityBoundingSet=` is constrained, the daemon cannot regain a dropped capability even if it possesses the syscalls to do so. The permanence invariant is the load-bearing reason the multi-stage privilege-drop carve-out in `99-process-restrict.conf` requires both a `CapabilityBoundingSet=` line that includes `CAP_SETUID` and `CAP_SETGID` and `SystemCallFilter=` lines that permit the syscall family that performs the drop.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → rngd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t rngd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in §"`nnp_rngd.cil`" below. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/rngd.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
CapabilityBoundingSet=CAP_SYS_ADMIN
SystemCallFilter=setgroups setgid setuid setresgid setresuid setregid setreuid
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
SystemCallFilter=capset capget
```

Directive notes:

- `MemoryDenyWriteExecute=yes` — the daemon cannot create executable-and-writable memory mappings. The daemon has no JIT or self-modifying-code path and tolerates MDWE without functional regression.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` — only Unix-domain sockets and Netlink are reachable. `AF_UNIX` covers systemd manager IPC; `AF_NETLINK` covers audit-event posting and uevent reception. The daemon has no IP-stack requirement.
- `SystemCallFilter=@system-service` — the broad allowlist seed.
- `SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock` — the subtractive group strips eleven syscall classes from the allowlist.
- `CapabilityBoundingSet=CAP_SYS_ADMIN` — the first capability-bounding line scopes the daemon's effective permitted set to `CAP_SYS_ADMIN` for the `/dev/hwrng` Misc-Device open path.
- `SystemCallFilter=setgroups setgid setuid setresgid setresuid setregid setreuid` — the second `SystemCallFilter=` line is the first additive privilege-drop carve-out: after the subtractive group above strips the privilege-related syscalls from the allowlist, this positive line re-adds the seven members of the `set{groups,gid,uid,resgid,resuid,regid,reuid}` family that the daemon's internal privilege drop calls.
- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` — the second capability-bounding line **adds** `CAP_SETUID` and `CAP_SETGID` to the bounding set. The two capabilities are required even though the syscall layer permits the privilege-drop syscalls, because the `no_new_privs` invariant makes capability reductions permanent: without the two capabilities in the bounding set at daemon-start, the kernel denies the privilege-drop call with `EPERM` even if the syscall passes through the seccomp filter.
- `SystemCallFilter=capset capget` — the third additive `SystemCallFilter=` line is the second additive privilege-drop carve-out: after the daemon performs the UID switch to `daemon:daemon`, it calls `capset(2)` to perform a fine-grained capability reduction. Because `capset` is in `@privileged` and would be stripped by the subtractive group, this positive line is required to permit it after the subtractive group has run.

systemd's `SystemCallFilter=` directive is multi-line additive: the order is "seed allowlist (`@system-service`) → subtractive group (`~@privileged …`) → positive carve-outs". The topic ships three positive lines because the daemon's privilege drop is a multi-stage pipeline (set-id family → capability-bounding permit → post-UID-switch `capset(2)`), each stage contributing one positive line. The class mechanism — the kernel constraint that drives the layering, the `EPERM`-versus-`SIGSYS` distinction between capability-layer and seccomp-layer denials, and the audit-record `uid=` field that pinpoints which drop-stage failed — is documented in [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md).

### `nnp_rngd.cil`

Path: `/usr/local/share/selinux/nnp_rngd.cil`.

```cil
(allow init_t rngd_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_rngd.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: the Stage-2 rollback runs `semodule -X 400 -r nnp_rngd` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts, see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All four shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/rngd.service.d/99-hardening.conf` | `0644` | `root:root` | `rngd_unit_file_t` |
| `/etc/systemd/system/rngd.service.d/99-nnp.conf` | `0644` | `root:root` | `rngd_unit_file_t` |
| `/etc/systemd/system/rngd.service.d/99-process-restrict.conf` | `0644` | `root:root` | `rngd_unit_file_t` |
| `/usr/local/share/selinux/nnp_rngd.cil` | `0644` | `root:root` | `usr_t` |

Stock targeted policy on Fedora 44 or later carries a service-specific subtype `rngd_unit_file_t` and a type-transition `init_t → rngd_unit_file_t : file create` for files under `/etc/systemd/system/rngd.service.d/`. The role's `restorecon` after `ansible.builtin.copy` is what triggers the relabel from the install-time default to the unit-specific type.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_rngd/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rng-tools`), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the live UID and GID of the running PID via `awk '/^Uid:/{print $2}' /proc/<MainPID>/status` and the symmetric `Gid:` extraction, the kernel entropy-pool snapshot via `cat /proc/sys/kernel/random/entropy_avail`, the daemon journal filtered for the privilege-drop confirmation line and the per-source initialization lines (`hwrng`, `rdrand`, `jitter`), the `matchpathcon /usr/bin/rngd` mapping, and the `semodule -l | grep nnp_rngd` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_rngd/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `CapabilityBoundingSet` (whitespace-separated, lowercased, alphabetically sorted) | `cap_setgid cap_setuid cap_sys_admin` |
| `RestrictAddressFamilies` (source-order, not sorted) | `AF_UNIX AF_NETLINK` |
| `SystemCallFilter` length-plus-anchor | observed `--value` length `>= 1500` bytes; substrings `setgroups`, `setuid`, `capset`, `epoll_wait`, `recvfrom` all present |
| `SystemCallArchitectures` | `native` |
| `ProtectSystem` | `full` |
| Live SELinux domain | `rngd_t` |
| Live UID / GID | `2` / `2` (post-privilege-drop steady state) |
| `cat /proc/sys/kernel/random/entropy_avail` | non-negative integer |
| Privilege-drop confirmation in journal | `dropped to` line present since boot |
| At-least-one entropy source initialized | `>= 1` `Initialized` line for `hwrng`, `rdrand`, or `jitter` |
| `semodule -l \| grep nnp_rngd` | one line (sysadm_t-gated) |

Three normalisation conventions are load-bearing. `systemctl show -p CapabilityBoundingSet --value` returns the resolved bounding set as a whitespace-separated lower-case capability list whose order is policy-dependent; the verify script lowercases and alphabetically sorts the observed value before comparison, and the hardcoded expected value is also alphabetically sorted (`cap_setgid cap_setuid cap_sys_admin`). `systemctl show -p RestrictAddressFamilies --value` preserves the source order of the drop-in directive (the directive is a positive whitelist whose semantics are order-independent, but the property output is order-preserving), so the verify script compares the observed value against the source-order hardcoded value `AF_UNIX AF_NETLINK`. `systemctl show -p SystemCallFilter --value` returns the fully resolved filter as a multi-thousand-byte string; the verify script checks the observed value with a length-plus-anchor pair — length `>= 1500` bytes (a conservative lower bound that catches a truncated or empty result) plus the presence of the literal substrings `setgroups`, `setuid`, `capset`, `epoll_wait`, and `recvfrom` (the first three anchor the additive privilege-drop carve-outs; the last two anchor the `@system-service` group expansion and are stable across systemd versions on Fedora 44).

The live UID and GID probe asserts the daemon-steady-state values `2 / 2` (`daemon:daemon`, after the daemon's internal privilege drop). A live UID of `0` indicates the multi-stage privilege-drop pipeline did not complete and is drift for this topic's privilege-drop end-state.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `rngd_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `semodule -l | grep nnp_rngd` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC and SECCOMP posture

On a correctly applied host, the role-switched queries return zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot \
  | grep -E '(rngd_t|nnp_transition|rngd)'
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot \
  | grep 'comm="rngd"'
```

The verify script runs both filters and treats any hit as drift. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The SECCOMP-clean assertion is load-bearing because the multi-stage privilege-drop carve-out is the load-bearing layer of this topic — a non-empty SECCOMP filter for `comm="rngd"` is the diagnostic signal that one of the three additive `SystemCallFilter=` lines or the two-line `CapabilityBoundingSet=` is misconfigured. The verify script extracts the `syscall=`, `uid=`, and `gid=` fields from any non-zero SECCOMP record and reports them; the interpretation of the `uid=` field — which localizes the failed drop-stage between the pre-UID-switch and post-UID-switch layers — is documented in [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md).

### Entropy-pool smoketest

The post-deploy smoketest uses the kernel entropy state and the daemon journal:

```bash
cat /proc/sys/kernel/random/entropy_avail
journalctl -u rngd.service --since boot --no-pager \
  | grep -E '(dropped to|Initialization|Initialized)'
```

On a correctly hardened host with running rngd, `cat /proc/sys/kernel/random/entropy_avail` returns a non-negative integer (Linux 5.18 and later report a high-water mark of 256 once the kernel CRNG is initialized; the verify script asserts `>= 0` rather than a specific value because the running kernel's CRNG-init policy is platform-dependent). The journal contains the daemon's privilege-drop confirmation line (the `dropped to` line that prints once the `-D daemon:daemon` argument succeeds) and at least one entropy-source initialization line (the per-source set is platform-dependent; the verify script asserts `>= 1` initialized source from the `hwrng`, `rdrand`, and `jitter` set). The smoketest is functional, not a hardening assertion; it catches regressions where the multi-stage privilege-drop carve-out, the address-family restriction, or the capability bounding would silently break the daemon's entropy-feeding loop.

The pre-hardening entropy-pool sanity baseline is the operator-side companion to the post-deploy smoketest. Before deploying the five-artefact profile, capture:

```bash
cat /proc/sys/kernel/random/entropy_avail
journalctl -u rngd.service --since '-1 hour' --no-pager \
  | grep -E '(dropped to|Initialization|Initialized)'
grep -E '^RNGD_ARGS=' /etc/sysconfig/rngd
```

On a stock host with running rngd, the entropy-pool snapshot is a non-negative integer (kernel-policy-dependent), the journal contains the daemon's privilege-drop confirmation line plus at least one entropy-source initialization line, and `RNGD_ARGS` echoes the package default. The role's preflight stage runs the same recon and stores the outputs as facts for post-deploy comparison; deviations are reported non-fatally.

The role's modify stage is idempotent. The four shipping artefacts (three drop-in INI files plus the CIL module source) are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is three-stage. **Stage 1**: remove `99-process-restrict.conf` and run `daemon-reload && restart`: `rm /etc/systemd/system/rngd.service.d/99-process-restrict.conf && systemctl daemon-reload && systemctl restart rngd.service`. The kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE, multi-stage privilege-drop carve-out) are reverted; the namespace-default baseline and NNP remain in effect. **Stage 2**: in addition to Stage 1, remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_rngd`, then `systemctl daemon-reload` and `systemctl restart rngd.service`. The NNP layer is reverted and the topic-owned SELinux extension is removed; the namespace-default baseline remains. **Stage 3**: in addition to Stages 1 and 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The most likely boot-failure mode for this topic is the NNP-denial cascade that the CIL module covers; Stage 2 is the corresponding rollback. The recovery how-to covers the boot-failure variant.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → rngd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/rngd` at next boot under `no_new_privs`.
- [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) — Why a daemon that performs an internal privilege drop after `ExecStart=` requires three additive `SystemCallFilter=` lines plus a two-line `CapabilityBoundingSet=` when run under an aggressive subtractive seccomp group with `NoNewPrivileges=yes`, and how the audit-record `uid=` field localizes the failed drop-stage when one of the three layers is misconfigured.
