<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# tuned

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `tuned.service` dynamic-system-tuning daemon on a Fedora 44 or later host. The end-state is a one-artefact Phase-A baseline deploy profile under `/etc/systemd/system/tuned.service.d/`: a single namespace-default drop-in that establishes the `Protect*` family with two operator-tunable opt-outs (`ProtectKernelTunables=no` and `ProtectControlGroups=no`) plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, and `SystemCallArchitectures=`. The end-state also includes the `ProtectSystem=full`-not-`strict` rationale tied to the daemon-self-managed `/run/tuned/` PID-file path, the verify discipline (per-property reads, AVC-clean and SECCOMP-clean assertions, `matchpathcon` fcontext assertion, `tuned-adm active` smoketest, deliberate `tuned-adm verify` non-invocation), the active-profile-name observation as informational only (the operator selects the profile via `tuned-adm profile <name>`; profile-policy is operator-side and outside this topic), and a two-stage rollback posture. This topic does not cover `/etc/tuned/tuned-main.conf` content, the operator-selected active-profile name (`balanced`, `powersave`, `throughput-performance`, `latency-performance`, `virtual-host`, `virtual-guest`, etc.), the operator-policy profiles under `/etc/tuned/tuned-profiles/`, the kernel `cpufreq` governor layer, the kernel `intel_pstate` or `amd_pstate` driver layer, the AHCI ALPM (Aggressive Link Power Management) sysfs interface, the SCSI-host driver layer, the `tuned-ppd.service` companion unit, the `tuned-gui` package, the `tuned-adm` user-space tooling beyond the `tuned-adm active` smoketest, the `systemd-analyze security` numeric score model, or the deferred process-internal kernel-restriction layer (`NoNewPrivileges=yes`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, additional `RestrictAddressFamilies=`, additional `CapabilityBoundingSet=`, or topic-owned SELinux CIL module).

## End-state configuration

The end-state ships **one** artefact: a single drop-in INI file under `/etc/systemd/system/tuned.service.d/`. The single-INI granularity has no rollback-surface split; the drop-in is removed atomically. The two-stage rollback documented under §"Verification" distinguishes between reverting only the two opt-outs (Stage 1) and removing the drop-in entirely (Stage 2). Subsections below describe the artefact after a service-identity subsection that enumerates the directives the F44 stock vendor unit ships and does not ship and that fixes the structural property that distinguishes this topic from the sibling hardware-class topics: tuned ships no process-internal kernel-restriction layer at all, and the one-artefact end-state is a positive design decision rather than an interim state.

### Service identity

The unit `tuned.service` is shipped by the `tuned` package. The stock vendor file at `/usr/lib/systemd/system/tuned.service` is sparse:

| Property | Value |
|---|---|
| Unit | `tuned.service` |
| Type | `dbus` |
| ExecStart | `/usr/sbin/tuned -l -P` |
| BusName | `com.redhat.tuned` |
| PIDFile | `/run/tuned/tuned.pid` |
| Initial daemon UID / GID | `0` / `0` (no `User=` directive in the vendor unit) |
| Steady-state UID / GID | `0` / `0` (no internal privilege drop) |
| SELinux runtime domain | `tuned_t` |

The SELinux type-transition `init_t → tuned_t` fires on the executable label `tuned_exec_t` carried by the daemon binary. On Fedora 44 or later the `tuned` package places the binary at `/usr/bin/tuned`; the vendor unit's `ExecStart=` line names `/usr/sbin/tuned`, which resolves to `/usr/bin/tuned` via the F44 `/usr/sbin → /usr/bin` global path equivalency. The `ExecStart=` line names `/usr/sbin/tuned` and the binary lives at `/usr/bin/tuned` post-merge; the role's preflight validates the mapping with a `matchpathcon` fail-fast against the canonical `/usr/bin/tuned` path. The class mechanism — why the equivalency rewrites the lookup target before the `file_contexts` table is consulted, and why the canonical-side label is the one the kernel's type-transition relies on — is documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

The vendor unit ships **no** `RuntimeDirectory=`, `StateDirectory=`, `ConfigurationDirectory=`, `LogsDirectory=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, or any other sandbox directive. The Phase-A baseline is therefore an operator-side full namespace-default suite, not an incremental layer on top of an upstream-hardened unit. The hardening surface consists entirely of the one drop-in this topic deploys.

The vendor unit declares `PIDFile=/run/tuned/tuned.pid` but ships no `RuntimeDirectory=tuned` directive; the daemon creates `/run/tuned/` itself at startup. This topic ships **no** `ReadWritePaths=` directive in any artefact. The chosen Phase-A baseline directive `ProtectSystem=full` leaves `/run` writable for the daemon (rather than `ProtectSystem=strict`, which would mount `/run` read-only and require an explicit carve-out for the PID-file path). This boundary is stated once here as the rationale for the `full`-not-`strict` choice.

The `tuned` package ships the daemon binary at `/usr/bin/tuned` (with `/usr/sbin/tuned` as the pre-merge path under the F44 equivalency), the user-space tooling at `/usr/bin/tuned-adm`, the systemd unit file at `/usr/lib/systemd/system/tuned.service`, the dbus service activation file under `/usr/share/dbus-1/system-services/`, the system-bus policy file under `/usr/share/dbus-1/system.d/`, the operator configuration file `/etc/tuned/tuned-main.conf`, the active-profile pointer `/etc/tuned/active_profile`, the operator-policy profile directory `/etc/tuned/tuned-profiles/`, and the package-default profile data files under `/usr/lib/tuned/`. The role's preflight stage asserts package presence and `tuned-adm` tooling availability; the role does not modify `/etc/tuned/tuned-main.conf`, `/etc/tuned/active_profile`, the operator-policy profiles under `/etc/tuned/tuned-profiles/`, or the package-default profile data under `/usr/lib/tuned/`. Profile selection and profile content are operator-policy outside this topic.

### One-artefact deploy profile

The Phase-A baseline ships exactly one drop-in INI file under `/etc/systemd/system/tuned.service.d/` (mode `0644 root:root`, label `systemd_unit_file_t`):

| File | Layer |
|---|---|
| `99-hardening.conf` | Phase-A namespace-default baseline (`Protect*` family with two opt-outs, plus `PrivateTmp=`, `LockPersonality=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `SystemCallArchitectures=`). |

Targeted policy on Fedora 44 defines a `tuned_unit_file_t` type, but `file_contexts` carries no path pattern that assigns it, so the drop-in and its directory keep the generic `systemd_unit_file_t` they inherit at creation. The role still relabels with `restorecon -F` to normalise the SELinux user field; see the artefact section below.

**No second or third artefact.** Unlike the sibling hardware-class topics (`alsa-state`, `rngd`, `smartd`, `thermald`), this topic ships **no** `99-nnp.conf` and **no** `99-process-restrict.conf`. The reasons are stated as positive design claims: the daemon's data path includes sysctl and cgroup writes that the namespace-default baseline must accommodate via the two opt-outs documented under §"`99-hardening.conf`" below, and a Python-runtime daemon's mmap-write-execute requirement under `MemoryDenyWriteExecute=yes` has not been validated for this topic — the deferred process-internal kernel-restriction layer is therefore not part of the end-state documented here.

### `99-hardening.conf`

Path: `/etc/systemd/system/tuned.service.d/99-hardening.conf`.

```ini
[Service]
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=no
PrivateTmp=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
```

Directive notes:

- `ProtectSystem=full` — `/usr`, `/boot`, `/efi`, and `/etc` are mounted read-only for the daemon. tuned reads `/etc/tuned/tuned-main.conf` and the active profile's data files under `/usr/lib/tuned/<profile-name>/`; both are read paths, no write access required. The directive value is `full` rather than `strict` because the daemon self-creates `/run/tuned/` for its `PIDFile=/run/tuned/tuned.pid`; `ProtectSystem=full` leaves `/run` writable and avoids the runtime-race surface that would arise from a `ReadWritePaths=/run/tuned` carve-out without a `-` prefix on a unit whose `RuntimeDirectory=` is unset.
- `ProtectHome=yes` — operator home directories are inaccessible. tuned does not consume per-user configuration.
- **`ProtectKernelTunables=no` (deliberate opt-out).** The directive value is `no` rather than the namespace-default `yes`. tuned's profile execution path writes sysctl tunables (typical `balanced`-class profiles set `vm.swappiness`, `vm.dirty_ratio`, `vm.dirty_background_ratio`, `kernel.sched_*`, and others); `ProtectKernelTunables=yes` would mount `/proc/sys/` read-only and break the `[sysctl]` block of every standard profile that ships.
- `ProtectKernelModules=yes` — `init_module(2)` / `finit_module(2)` / `delete_module(2)` are denied. Several stock profiles include a `[modules]` block (e.g., `cpufreq_conservative=+r` for the `balanced` profile); on Fedora 44 the typical kernels ship the relevant cpufreq governors built into the kernel image (`modinfo cpufreq_conservative` reports `filename: (builtin)`), so the profile's `[modules]` block does not exercise `finit_module(2)` and the directive is compatible with the daemon's data path. A future kernel that ships these governors as loadable modules would surface drift; the role's preflight does not check this property (out of topic scope).
- `ProtectKernelLogs=yes` — `/dev/kmsg` and the `syslog(2)` system call are denied. tuned has no kernel-log consumption path.
- **`ProtectControlGroups=no` (deliberate opt-out).** The directive value is `no` rather than the namespace-default `yes`. tuned's profile execution path includes a `[scheduler]` plugin block that writes cgroup attributes (CPU affinity, `sched_runtime`, `sched_deadline`) under `/sys/fs/cgroup/`; `ProtectControlGroups=yes` would mount the cgroup pseudo-filesystem read-only and break the cgroup-write portion of every standard profile that includes a scheduler block.
- `PrivateTmp=yes` — the daemon receives a private `/tmp` and `/var/tmp`. tuned does not coordinate temporary state with other processes.
- `ProtectClock=yes` / `ProtectHostname=yes` — `settimeofday(2)` / `adjtimex(2)` and the hostname interfaces are denied.
- `LockPersonality=yes` — `personality(2)` is denied.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` policies are denied.
- `RestrictSUIDSGID=yes` — SUID and SGID file creation is denied.
- `SystemCallArchitectures=native` — the 32-bit personality on x86_64 is denied.

Two directives in this baseline carry the value `no` rather than the namespace-default `yes`: `ProtectKernelTunables=no` and `ProtectControlGroups=no`. Both opt-outs are deliberate concessions to the daemon's profile execution path, which writes sysctl tunables (`/proc/sys/`) and cgroup attributes (`/sys/fs/cgroup/`) as part of every standard profile that ships with the package. Tightening either directive to `yes` would mount the corresponding pseudo-filesystem read-only inside the unit's mount namespace and break the affected portion of the daemon's data path. The opt-outs are the operator-visible cost of running a profile-based tuning daemon under a partial namespace-default baseline; they are stated here as positive design decisions, not as oversights or as targets for a future incremental hardening pass.

The Phase-A baseline does **not** include `PrivateMounts=no`. tuned is not a mount-manager daemon; the implicit `PrivateMounts=true` enable that the remaining `Protect*` directives carry has no operator-visible effect for this unit because tuned issues no `mount(2)` calls. The boundary is stated here once as a fact about this profile.

The Phase-A baseline does **not** include `PrivateDevices=yes`. The directive is deliberately omitted (default `no`).

This topic ships no `SystemCallFilter=` or `CapabilityBoundingSet=` directive at any layer; the daemon runs as `root` throughout and performs no internal privilege drop, so the privilege-drop class that elsewhere requires a topic-owned SCF carve-out (the [phase-b-scf-privdrop](../../explanation/phase-b-scf-privdrop.md) Pattern) does not apply, and a Phase-B layer that would shrink the capability surface absent such a carve-out has been deferred from this Topic for the reason stated under §"End-state configuration".

This topic ships **no** `99-nnp.conf` drop-in and the role's `files/` directory contains **no** such file. The role's `handlers/main.yml` defines no SELinux-CIL-load handler. The role's `meta/main.yml` does **not** declare `foundation_selinux_cil_bootstrap` as a dependency. The structural reason for the absence is that the deferred process-internal kernel-restriction layer for this daemon has not been validated end-to-end. The daemon is a Python-runtime process; `MemoryDenyWriteExecute=yes` may interact with the Python interpreter's mmap-write-execute behaviour for module-import paths in ways that have not been observationally cleared on a stock Fedora 44 baseline. The present end-state is the only end-state this topic documents.

This topic ships **no** `99-process-restrict.conf` drop-in. The role's `files/` directory contains **no** such file. The reason is the same deferral rationale stated above; the directive set a future kernel-restriction drop-in might carry is not previewed here.

Unlike the sibling hardware-class topics (`alsa-state`, `rngd`, `smartd`), this topic does **not** ship a topic-owned CIL module and the operator does **not** run a `sesearch -A -s init_t -t tuned_t -c process2 -p nnp_transition` pre-test. The reason is **not** that stock targeted policy on Fedora 44 ships the relevant allow rule — it does not. The reason is structural and one step removed: this topic ships no `NoNewPrivileges=yes` drop-in, so the kernel-level NNP-transition constraint is not exercised, and the corrective CIL extension is consequently not required.

### File modes

The single shipping artefact is written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/tuned.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |

Targeted policy on Fedora 44 defines a `tuned_unit_file_t` type, but `file_contexts` carries no path pattern that assigns it: no entry matches `/usr/lib/systemd/system/tuned*`, so the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency resolves to nothing more specific than the generic rule. The expected type for the drop-in directory and for every file inside it is therefore the `systemd_unit_file_t` they inherit at creation, and `matchpathcon` confirms it. No `type_transition` to a `*_unit_file_t` exists for PID 1.

The role runs `restorecon -F -v -R` on the drop-in directory anyway. The call is a no-op on the type, but `-F` normalises the SELinux user field, which otherwise keeps the identity of whoever applied the role and stays invisible to the type-only comparison of `restorecon -n`. The step also remains correct if a future policy release adds a mapping for this path. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_tuned/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`tuned`), unit liveness, the merged unit body filtered for the drop-in filename and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `matchpathcon` mappings for `/usr/bin/tuned` and `/usr/sbin/tuned` (informational; reports both labels for the F44 sbin/bin-merge cross-check), the `tuned-adm active` smoketest (read-only when invoked by an unprivileged client; reports the active profile name on a healthy host), and the daemon journal for context. The probe does **not** invoke `tuned-adm verify` (deliberately — see §"Verify" below). The properties surveyed include both the topic-owned set (`ProtectSystem`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `PrivateTmp`, `ProtectClock`, `ProtectHostname`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `SystemCallArchitectures`, `MainPID`) and the explicit-absence baseline (`NoNewPrivileges`, `MemoryDenyWriteExecute`, `SystemCallFilter`, `CapabilityBoundingSet`, `RestrictAddressFamilies`) — the latter are reported but no topic-owned `EXPECTED_*` value is asserted against them in `verify.sh`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_tuned/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `ProtectSystem` | `full` |
| `ProtectHome` | `yes` |
| `ProtectKernelTunables` | `no` (deliberate opt-out — `yes` would be drift) |
| `ProtectKernelModules` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectControlGroups` | `no` (deliberate opt-out — `yes` would be drift) |
| `PrivateTmp` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectHostname` | `yes` |
| `LockPersonality` | `yes` |
| `RestrictRealtime` | `yes` |
| `RestrictSUIDSGID` | `yes` |
| `SystemCallArchitectures` | `native` |
| Live SELinux domain | `tuned_t` |
| `tuned-adm active` | exit `0` and stdout contains `Current active profile:` followed by a non-empty profile name |
| `matchpathcon /usr/bin/tuned` | resolves to `tuned_exec_t` |

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The `tuned-adm active` smoketest reports the operator-selected active profile name as informational output; this Topic asserts only that the command returns exit `0` and a non-empty profile name, not that any specific profile is selected.

The `tuned-adm verify` command compares the daemon's recorded Soll-state for the active profile against the live system state and reports any mismatch as `current system settings differ from the preset profile`. On hosts whose AHCI controller, mainboard firmware, or other platform component declines to honour a value the active profile attempts to write — for example, the AHCI ALPM (Aggressive Link Power Management) sysfs interface returning `EOPNOTSUPP` for `med_power_with_dipm` on SATA host ports whose driver does not expose ALPM — `tuned-adm verify` reports a mismatch even though the daemon and the namespace-default baseline of this Topic are both functioning correctly. The mismatch is a hardware-or-firmware property, not a Topic-owned drift signal. This Topic's verify discipline therefore deliberately does not invoke `tuned-adm verify`; the smoketest is `tuned-adm active`, which reports only the active profile name and exits `0` on a healthy daemon. An operator who wishes to investigate `tuned-adm verify` mismatches should treat the investigation as platform-side hardware diagnostics outside the scope of this Topic.

The `matchpathcon` boundary is asserted as either-or: `matchpathcon /usr/bin/tuned` resolves to `tuned_exec_t` (the canonical post-merge label) and `matchpathcon /usr/sbin/tuned` resolves to `bin_t` (the generic pre-merge label, because the equivalency rewrites the lookup target before the file-context table is consulted). If **neither** path resolves to `tuned_exec_t`, the verify reports drift and exits non-zero. The canonical-side label is the one the SELinux type-transition relies on; a host where `/usr/bin/tuned` does not resolve to `tuned_exec_t` would fail to enter `tuned_t` at execve time and the live-state probe would observe `init_t` or `bin_t` instead.

The verify script does **not** assert `EXPECTED_NNP`, `EXPECTED_MDWE`, `EXPECTED_RESTRICT_ADDRESS_FAMILIES`, `EXPECTED_SYSCALL_FILTER`, `EXPECTED_CAP_BOUNDING_SET`, `EXPECTED_RESTRICT_NAMESPACES`, `EXPECTED_PROTECT_PROC`, `EXPECTED_PROC_SUBSET`, `EXPECTED_PRIVATE_DEVICES`, or `EXPECTED_ACTIVE_PROFILE`. None of these directives are part of the topic-owned surface; presence of any of these `EXPECTED_*` constants in `verify.sh` is drift against the present end-state.

### AVC and SECCOMP posture

On a correctly applied host, the role-switched queries return zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(tuned_t|tuned_exec_t|tuned_log_t|tuned_etc_t|tuned_rw_etc_t)'
sudo -r sysadm_r -t sysadm_t ausearch -m seccomp -ts boot \
  | grep tuned
```

The verify script runs both filters and treats any hit as drift. The four-tool diagnosis loop that operators use when an AVC hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md). The SECCOMP-clean assertion catches a stock-systemd-side seccomp filter inherited from a higher-level unit; this topic ships no `SystemCallFilter=` directive, so any seccomp record naming tuned would itself be unexpected and surfaces as drift either way.

### Pre-hardening recon

Before deploying the drop-in, the operator runs:

```bash
systemctl is-active tuned.service
systemctl show tuned.service -p MainPID --value
tuned-adm active
sudo -r sysadm_r -t sysadm_t journalctl -b 0 -p err -u tuned.service --no-pager | tail -20
sudo -r sysadm_r -t sysadm_t journalctl -b 0 -u tuned.service --no-pager \
  | grep -iE 'verify: failed|EOPNOTSUPP|operation not supported' | tail -20
```

On a stock host with tuned active, `is-active` returns `active`, `MainPID` returns a non-zero PID, `tuned-adm active` returns the operator-selected active profile name, and the two `journalctl` tails capture the pre-hardening signature of any platform-side `tuned-adm verify` mismatches (for example, AHCI ALPM ERROR lines on hosts whose SATA controller declines `med_power_with_dipm`). Capturing the pre-hardening signature is required so that any post-deploy investigation of `tuned-adm verify` mismatches can distinguish the platform-side baseline from a topic-owned regression — the boundary stated under §"Verify". The role's preflight stage runs the same recon and reports the outcome non-fatally.

### Idempotence and rollback

The role's modify stage is idempotent. The single shipping artefact is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `restorecon`, `daemon-reload`, and `restart tuned` handlers each fire only on a change to the notifying task. The live-state probe is read-only. There is no `semodule install` handler (no CIL artefact ships) and no `meta: flush_handlers` synchronisation between a CIL load and the drop-in push. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is two-stage. **Stage 1**: shrink `99-hardening.conf` to the eleven-directive subset that matches the sibling hardware-class baselines by setting `ProtectKernelTunables=yes` and `ProtectControlGroups=yes`. The daemon then fails any profile write to `/proc/sys/` or `/sys/fs/cgroup/`; `tuned-adm verify` reports mismatches as a deliberate trade-off (the operator has chosen a tighter sandbox at the cost of profile fidelity). Stage 1 is a hardening-up rollback rather than a hardening-down rollback; it is documented for the operator who wishes to test whether a specific profile genuinely requires both opt-outs on a specific host. Reboot or `systemctl restart tuned.service` is required for Stage 1 to take effect. **Stage 2**: remove `99-hardening.conf` entirely and run `systemctl daemon-reload && systemctl restart tuned.service`. The unit reverts to the stock vendor configuration (no namespace-default baseline). The unit ships no `RefuseManualStop=` directive; the restart path is structurally available.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — The vendor unit's `ExecStart=` line names `/usr/sbin/tuned` while the package installs the binary at `/usr/bin/tuned`. The F44 `/usr/sbin → /usr/bin` global path equivalency rewrites the lookup target before the file-context table is consulted; `matchpathcon /usr/bin/tuned` returns the canonical `tuned_exec_t` and `matchpathcon /usr/sbin/tuned` returns the generic `bin_t`. The role's preflight runs both and requires `tuned_exec_t` from the canonical-side path as fail-fast.
- [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md) — The class of trap covered there does **not** apply to this unit. This topic is a third canonical "Pattern does not apply" example after thermald and alsa-state — for a different reason from those two: thermald and alsa-state ship a process-internal kernel-restriction layer with an empty `CapabilityBoundingSet=` because their data paths permit it; tuned defers the entire process-internal kernel-restriction layer rather than shipping such a layer with empty SCF. The `99-process-restrict.conf` artefact does not exist for this topic, and the structural-boundary mention here is the only treatment of the Pattern in this Topic Reference.
