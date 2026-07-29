<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# alsa-state

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `alsa-state.service` ALSA-mixer-state-restore daemon on a Fedora 44 or later host. The end-state is a four-artefact deploy profile under `/etc/systemd/system/alsa-state.service.d/` and `/usr/local/share/selinux/`: a namespace-default baseline drop-in that establishes the `Protect*` family plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, and `SystemCallArchitectures=`; an isolated `NoNewPrivileges=yes` drop-in; a process-internal kernel-restriction drop-in carrying `MemoryDenyWriteExecute=`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, an additive plus subtractive `SystemCallFilter=` pair, and an empty `CapabilityBoundingSet=` that drops all stock-allowed capabilities; and a topic-owned SELinux CIL module that grants the `init_t → alsa_t : process2 nnp_transition` rule that stock targeted policy does not ship for this domain. The end-state also includes the verify discipline (per-property reads, paired `[ -d /proc/${main_pid} ]` liveness with a `comm=alsactl` probe that defeats the vendor `ExecStart=-` dash-prefix exit-masking, source-order address-family check, length-plus-anchor `SystemCallFilter=` check, live UID and GID probe of the steady-state root daemon, AVC-clean and SECCOMP-clean assertions, `matchpathcon` fcontext assertion for the F44 sbin/bin-equivalent paths), the saved-state file smoketest, the pre-hardening sanity baseline, and a three-stage rollback posture. This topic does not cover the ALSA kernel driver layer, the `/dev/snd/*` character-device interface itself, the per-user PulseAudio or PipeWire daemon stack (the per-user audio session is a separate topic), the companion `alsa-restore.service` oneshot (deliberately out of scope; the oneshot path is fragile under sandboxing), the `alsamixer` interactive CLI, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines four shipping artefacts: three drop-in INI files under `/etc/systemd/system/alsa-state.service.d/` and one CIL module under `/usr/local/share/selinux/`. The three drop-ins layer the namespace-default baseline, the `NoNewPrivileges=yes` switch, and the process-internal kernel restrictions in separate files so the rollback surface splits layer-by-layer. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates the directives the F44 stock vendor unit ships and does not ship.

### Service identity

The unit `alsa-state.service` is shipped by the `alsa-utils` package. The stock vendor file at `/usr/lib/systemd/system/alsa-state.service` is sparse:

| Property | Value |
|---|---|
| Unit | `alsa-state.service` |
| Type | `simple` |
| ExecStart | `-/usr/sbin/alsactl -E HOME=/run/alsa rdaemon` |
| Initial daemon UID / GID | `0` / `0` (no `User=` directive in the vendor unit) |
| Steady-state UID / GID | `0` / `0` (no internal privilege drop) |
| SELinux domain | `alsa_t` |

The leading `-` (dash) prefix on `ExecStart=` is vendor-shipped: systemd treats a non-zero exit of the binary as success when the prefix is present. This dash prefix is the load-bearing reason the verify discipline below pairs the `[ -d /proc/${main_pid} ]` liveness probe with a `comm=alsactl` probe; without the paired probe a `SIGSYS`-killed binary would be reported as an "active" unit by a superficial `systemctl is-active` check.

`alsactl` runs in restore-daemon mode (`rdaemon`), which keeps the process alive to react to a system halt or restart by re-saving ALSA mixer state to `/var/lib/alsa/asound.state` before shutdown. The daemon initialises as root and **stays at root** for its entire lifetime — there is no internal privilege drop. This single-uid steady state is the load-bearing reason the topic does not invoke the multi-stage privilege-drop pattern that other Phase-A or kernel-restriction profiles in this tree carry; the `99-process-restrict.conf` drop-in below ships only the seed allowlist plus the subtractive group, with no additive carve-out lines, and with an empty `CapabilityBoundingSet=`.

The SELinux type-transition `init_t → alsa_t` fires on the executable label `alsa_exec_t` carried by the daemon binary. On Fedora 44 or later the `alsa-utils` package places the binary at `/usr/sbin/alsactl`; under the sbin/bin equivalency rule, `/usr/bin/alsactl` is the canonical path and the sbin path is a compatibility symlink. Stock targeted policy ships an fcontext mapping that resolves both `/usr/bin/alsactl` and `/usr/sbin/alsactl` to `alsa_exec_t`; `matchpathcon` returns `alsa_exec_t` for both paths on a stock host, so the F44 sbin-bin equivalency does not surface drift for this unit. The role's preflight stage validates the mapping with two `matchpathcon` checks that fail fast on a `bin_t` mapping at either path. The role does not ship a `community.general.sefcontext` mitigation for this binary.

The vendor unit ships **no** `RuntimeDirectory=`, `StateDirectory=`, `ConfigurationDirectory=`, `LogsDirectory=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, or any other sandbox directive. The hardening surface is therefore entirely operator-side: the namespace-default baseline drop-in, the isolated NNP drop-in, the process-internal kernel-restriction drop-in, and the topic-owned CIL module are the topic's full contribution. The unit ships no `ReadWritePaths=` directive in any artefact this topic deploys, and the topic does not introduce one; the boot-time runtime-path race that affects daemons that self-create directories under `/run/<svc>/` does not apply to this unit.

The `alsa-utils` package ships the daemon binary at `/usr/sbin/alsactl` (with `/usr/bin/alsactl` as the F44-canonical path under sbin/bin equivalency), the systemd unit file, the SELinux service-specific subtype set (`alsa_t`, `alsa_exec_t`, `alsa_unit_file_t` shipped by stock targeted policy at priority 100), the saved-state file at `/var/lib/alsa/asound.state` (populated by the package's first-install hook), and the companion `alsa-restore.service` oneshot — which this topic does **not** harden. The role's preflight stage asserts package presence and reads the saved-state file size non-fatally as a fact for post-deploy comparison.

### Four-artefact deploy profile

The hardening profile splits across three drop-in INI files under `/etc/systemd/system/alsa-state.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-default baseline (`Protect*` family, `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `SystemCallArchitectures=`). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `99-process-restrict.conf` | Process-internal kernel restrictions (`MemoryDenyWriteExecute=`, `RestrictAddressFamilies=`, additive plus subtractive `SystemCallFilter=` pair, empty `CapabilityBoundingSet=`). |
| `nnp_alsa.cil` | Topic-owned SELinux module that grants `init_t → alsa_t : process2 nnp_transition`. |

The three-INI granularity (three drop-ins plus one CIL module) splits the rollback surface so an operator can revert layer-by-layer without losing the underlying baseline. Removing `99-process-restrict.conf` alone reverts the kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE) while leaving NNP and the namespace-default baseline in effect. Removing `99-nnp.conf` in addition reverts NNP. Removing `99-hardening.conf` in addition reverts the namespace-default baseline. Removing the CIL module is the last lever; it is harmless on its own once the NNP drop-in is gone. The three-stage rollback documented under §"Verification" atomizes the layer-by-layer reverts.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install handler and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/alsa-state.service.d/99-hardening.conf`.

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

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. `alsactl` needs no write access to these paths; the saved-state file at `/var/lib/alsa/asound.state` lives outside the protected hierarchy.
- `ProtectHome=yes` — operator home directories are inaccessible. The daemon does not consume per-user configuration.
- `ProtectKernelTunables=yes` / `ProtectKernelModules=yes` / `ProtectKernelLogs=yes` — the sysctl interface, the kernel-module IOCTL paths, and the kernel-log devices are denied. `alsactl` reads and writes mixer state via the ALSA control interface (`/dev/snd/controlC*` character devices); none of the protected-kernel surfaces are touched.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only. The daemon does not adjust resource limits.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. The daemon does not coordinate temporary state with other processes.
- `ProtectClock=yes` / `ProtectHostname=yes` — `settimeofday(2)` / `adjtimex(2)` and the hostname interfaces are denied.
- `LockPersonality=yes` — `personality(2)` is denied.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` policies are denied.
- `RestrictSUIDSGID=yes` — SUID and SGID file creation is denied.
- `SystemCallArchitectures=native` — the 32-bit personality on x86_64 is denied.

The baseline does **not** include `PrivateMounts=no`. The daemon is not a mount-manager; the implicit `PrivateMounts=true` enable that the `Protect*` directives carry has no operator-visible effect for this unit because `alsactl` issues no `mount(2)` calls. The boundary is stated here once as a fact about this profile.

The baseline does **not** include `PrivateDevices=yes`. `PrivateDevices=yes` would mask `/dev/snd/*` and break the daemon's only purpose; the directive is deliberately omitted (default `no`).

### `99-nnp.conf`

Path: `/etc/systemd/system/alsa-state.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. Setuid binaries that the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child. The kernel also enforces the invariant that capability reductions made under `no_new_privs` are **permanent** for the daemon's lifetime — once the `CapabilityBoundingSet=` is constrained, the daemon cannot regain a dropped capability even if it possesses the syscalls to do so. For this unit the practical consequence of the permanence invariant is mild: the deploy profile drops the bounding set to empty in `99-process-restrict.conf`, and `alsactl` in `rdaemon` mode does not need to regain any capability.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → alsa_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t alsa_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in §"`nnp_alsa.cil`" below. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `99-process-restrict.conf`

Path: `/etc/systemd/system/alsa-state.service.d/99-process-restrict.conf`.

```ini
[Service]
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
CapabilityBoundingSet=
```

Directive notes:

- `MemoryDenyWriteExecute=yes` — the daemon cannot create executable-and-writable memory mappings. `alsactl` has no JIT or self-modifying-code path and tolerates MDWE without functional regression.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` — only Unix-domain sockets and Netlink are reachable. `AF_UNIX` covers systemd manager IPC; `AF_NETLINK` covers audit-event posting and uevent reception. `alsactl` has no IP-stack requirement (mixer state is local).
- `SystemCallFilter=@system-service` — the broad allowlist seed.
- `SystemCallFilter=~@privileged @resources @debug @mount @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock` — the subtractive group strips eleven syscall classes from the allowlist.
- `CapabilityBoundingSet=` (empty) — the daemon's capability bounding set is reduced to the empty set, dropping all stock-allowed capabilities. `alsactl` does not need any capability to read or write `/var/lib/alsa/asound.state` (file is owned by `root:root`, mode `0644`), to access `/dev/snd/*` (the kernel sound subsystem grants access by file mode, not capability, when the daemon already runs as root), or to react to system halt. The empty bounding set is the strongest reduction available.

systemd's `SystemCallFilter=` directive is multi-line additive, but this unit ships exactly two lines: the seed allowlist `@system-service` and the subtractive group `~@privileged …`. The absence of additive privilege-drop carve-out lines (the `set{groups,resuid,resgid,reuid,regid,uid,gid}` family or `capset`/`capget`) is intentional and structural: the daemon performs no internal privilege drop, runs as root throughout its lifetime, and therefore needs no carve-out. The relevant pattern for daemons that *do* perform an internal drop, and the boundary marker that places this topic on the negative side of that pattern, is documented in [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) and is summarised in §"Related patterns" below.

### `nnp_alsa.cil`

Path: `/usr/local/share/selinux/nnp_alsa.cil`.

```cil
(allow init_t alsa_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_alsa.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: the Stage-2 rollback runs `semodule -X 400 -r nnp_alsa` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts, see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All four shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/alsa-state.service.d/99-hardening.conf` | `0644` | `root:root` | `alsa_unit_file_t` |
| `/etc/systemd/system/alsa-state.service.d/99-nnp.conf` | `0644` | `root:root` | `alsa_unit_file_t` |
| `/etc/systemd/system/alsa-state.service.d/99-process-restrict.conf` | `0644` | `root:root` | `alsa_unit_file_t` |
| `/usr/local/share/selinux/nnp_alsa.cil` | `0644` | `root:root` | `usr_t` |

Stock targeted policy on Fedora 44 or later maps a service-specialised type for these files: `file_contexts` carries `/usr/lib/systemd/system/alsa.*` → `alsa_unit_file_t`, and the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency in `file_contexts.subs_dist` extends that mapping to the drop-in path under `/etc`. The drop-in *directory* is not covered by it — the entry is qualified with `--`, which matches regular files only — so the directory keeps the generic `systemd_unit_file_t`, which is its correct type.

Nothing assigns the mapped type at creation time, and no `type_transition` to a `*_unit_file_t` exists for PID 1. A file written into the drop-in directory inherits that directory's `systemd_unit_file_t`, and the role's `restorecon -F -v -R` on the drop-in directory is what moves it to `alsa_unit_file_t`. The `-R` covers the directory itself, which this role creates and which no other step revisits; the `-F` additionally resets the SELinux user field, which a type-only comparison such as `restorecon -n` never reports. Without the relabel the merged unit still runs — systemd reads drop-ins regardless of label — but the hardening artefact keeps the wider generic type while the stock unit file beside it carries the narrower one. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_alsa_state/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`alsa-utils`), unit liveness, the merged unit body filtered for the three drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the live UID and GID of the running PID via `awk '/^Uid:/{print $2}' /proc/<MainPID>/status` and the symmetric `Gid:` extraction, the live `comm` of the running PID via `cat /proc/<MainPID>/comm`, the saved-state file size and mtime via `stat /var/lib/alsa/asound.state`, the daemon journal for context, the `matchpathcon` mappings for `/usr/bin/alsactl` and `/usr/sbin/alsactl`, and the `semodule -l | grep nnp_alsa` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_alsa_state/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `CapabilityBoundingSet` (whitespace-stripped, lowercased) | empty string |
| `RestrictAddressFamilies` (source-order, not sorted) | `AF_UNIX AF_NETLINK` |
| `SystemCallFilter` length-plus-anchor | observed `--value` length `>= 1500` bytes; substrings `epoll_wait`, `recvfrom` both present |
| `SystemCallArchitectures` | `native` |
| `ProtectSystem` | `full` |
| Live SELinux domain | `alsa_t` |
| Live UID / GID | `0` / `0` (root throughout — no privilege drop) |
| Live `/proc/${main_pid}/comm` | `alsactl` |
| `stat /var/lib/alsa/asound.state` | size > 0 |
| `semodule -l \| grep nnp_alsa` | one line (sysadm_t-gated) |

Three normalisation conventions are load-bearing. `systemctl show -p CapabilityBoundingSet --value` returns the empty string when the bounding set is empty; the verify script lowercases and whitespace-strips the observed value before comparing against the empty-string expected value, so a single non-empty capability appearing in the resolved output is drift. `systemctl show -p RestrictAddressFamilies --value` preserves the source order of the drop-in directive (the directive is a positive whitelist whose semantics are order-independent, but the property output is order-preserving), so the verify script compares the observed value against the source-order hardcoded value `AF_UNIX AF_NETLINK`. `systemctl show -p SystemCallFilter --value` returns the fully resolved filter as a multi-thousand-byte string; the verify script checks the observed value with a length-plus-anchor pair — length `>= 1500` bytes (a conservative lower bound that catches a truncated or empty result) plus the presence of the literal substrings `epoll_wait` and `recvfrom` (the two anchor the `@system-service` group expansion and are stable across systemd versions on Fedora 44). The verify script does **not** anchor on `setgroups`, `setuid`, or `capset` — those tokens are intentionally absent because the unit ships no additive privilege-drop carve-out.

The live UID and GID probe asserts the steady-state values `0 / 0`. A non-zero live UID or GID indicates that the topic profile is being applied to a misconfigured unit (for example, a vendor unit that has acquired a `User=` directive in a future package update); for this topic's end-state, both values are root.

Liveness is checked through `[ -d /proc/${main_pid} ]` (ownership-independent — see [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md)). For this unit, the liveness probe is paired with a `comm=alsactl` probe via `cat /proc/${main_pid}/comm`. The vendor `ExecStart=` directive carries a leading `-` (dash) prefix, which makes systemd treat a non-zero exit of the binary as success; without the `comm=alsactl` probe a `SIGSYS`-killed `alsactl` would report `active` to a superficial `systemctl is-active` check. The paired liveness + `comm` probe is the load-bearing detection for this exit-masking surface.

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `alsa_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `semodule -l | grep nnp_alsa` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC and SECCOMP posture

On a correctly applied host, the role-switched queries return zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC,USER_AVC -ts boot \
  | grep -E '(alsa_t|nnp_transition|alsa-state|alsactl)'
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot \
  | grep 'comm="alsactl"'
```

The verify script runs both filters and treats any hit as drift. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The SECCOMP-clean assertion is load-bearing because the dash-prefix exit-masking on `ExecStart=` would otherwise hide a `SystemCallFilter=`-induced kill. The kernel audit subsystem records the kill regardless of how systemd interprets the binary's exit code, so a non-empty SECCOMP filter for `comm="alsactl"` is the diagnostic signal that the subtractive seccomp group has stripped a syscall the daemon needs at runtime. The verify script extracts the `syscall=`, `uid=`, and `gid=` fields from any non-zero SECCOMP record and reports them.

### State-file smoketest

The post-deploy smoketest uses the saved-state file:

```bash
stat -c '%n: %s bytes, mtime=%y' /var/lib/alsa/asound.state
```

On a correctly hardened host, the file exists, is readable from `sysadm_t`, and has non-zero size (a fresh-from-package install populates a default state file via the package's first-install hook). The smoketest is functional, not a hardening assertion; it catches regressions where the namespace-default baseline (`ProtectSystem=full`, `ProtectHome=yes`) or the subtractive seccomp group would silently break the daemon's only persistent side effect — writing the saved-state file at system halt or restart. The mtime is reported informationally; an mtime check would require a controlled trigger and is not asserted as drift in a static verify pass.

The pre-hardening sanity baseline is the operator-side companion to the post-deploy smoketest. Before deploying the four-artefact profile, capture:

```bash
systemctl is-active alsa-state.service
stat -c '%n: %s bytes, mtime=%y' /var/lib/alsa/asound.state
journalctl -u alsa-state.service --since '-1 hour' --no-pager
awk '/^Uid:|^Gid:/{print}' \
  /proc/$(systemctl show -p MainPID --value alsa-state.service)/status
```

On a stock host with running alsa-state, `is-active` returns `active`, the saved-state file exists with non-zero size, the journal is typically quiet (`alsactl` in `rdaemon` mode is mostly idle), and the live UID and GID both read `0`. The role's preflight stage runs the same recon and stores the outputs as facts for post-deploy comparison; deviations are reported non-fatally.

The role's modify stage is idempotent. The four shipping artefacts (three drop-in INI files plus the CIL module source) are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is three-stage. **Stage 1**: remove `99-process-restrict.conf` and run `daemon-reload && restart`: `rm /etc/systemd/system/alsa-state.service.d/99-process-restrict.conf && systemctl daemon-reload && systemctl restart alsa-state.service`. The kernel-level process restrictions (capability bounding set, syscall filter, address-family filter, MDWE) are reverted; the namespace-default baseline and NNP remain in effect. **Stage 2**: in addition to Stage 1, remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_alsa`, then `systemctl daemon-reload` and `systemctl restart alsa-state.service`. The NNP layer is reverted and the topic-owned SELinux extension is removed; the namespace-default baseline remains. **Stage 3**: in addition to Stages 1 and 2, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The most likely boot-failure mode for this topic is the NNP-denial cascade that the CIL module covers; Stage 2 is the corresponding rollback. The recovery how-to covers the boot-failure variant.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → alsa_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/alsactl` at next boot under `no_new_privs`.
- [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) — The class of trap covered there does **not** apply to this unit. `alsactl` in `rdaemon` mode runs as `uid=0` from `ExecStart=` to process exit; it performs no `setgroups(2)`, no `setresuid(2)`, no `capset(2)`. Because no internal privilege drop is performed, the `99-process-restrict.conf` here ships only the seed `@system-service` allowlist plus the subtractive group, with no additive privilege-drop carve-out lines and an empty `CapabilityBoundingSet=`. This unit is the canonical example of the negative-case boundary the Pattern names — daemons that do not exhibit the trap because they never perform an internal drop.
