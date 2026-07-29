<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# avahi-daemon

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of `avahi-daemon.service` on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/avahi-daemon.service.d/` and `/usr/local/share/selinux/`: a topic-owned hardening drop-in that adds twenty-three directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the `init_t → avahi_t : process2 nnp_transition` denial that stock targeted policy carries for this domain. The end-state also includes the verify discipline (per-property reads, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion), the two-class mDNS smoketest, the pre-hardening mDNS baseline, and a two-stage rollback posture. This topic does not cover `/etc/avahi/avahi-daemon.conf` content, the published-service definitions under `/etc/avahi/services/`, the daemon-internal `chroot()` configuration beyond the byte-exact internal-privilege-drop boundary marker, the dependency cascade of mDNS discovery on operator workflows (printer discovery, file-sharing discovery, multimedia-device discovery), or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: a topic-owned hardening drop-in that carries twenty-three directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's domain. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates what the F44 stock vendor unit already carries and what the topic therefore does not modify.

### Service identity

The unit `avahi-daemon.service` is shipped by the `avahi` package and is the multicast-DNS responder on a Fedora 44 host. The stock vendor file at `/usr/lib/systemd/system/avahi-daemon.service` carries the directives this topic does not modify. The daemon binary is installed at `/usr/bin/avahi-daemon`. The SELinux type-transition `init_t → avahi_t` fires on the executable label `avahi_exec_t` carried by the binary at that path.

| Property | Value |
|---|---|
| Unit | `avahi-daemon.service` |
| Type | `dbus` |
| BusName | `org.freedesktop.Avahi` |
| ExecStart | `/usr/bin/avahi-daemon -s` |
| User / group | not set on the unit (daemon-internal drop, see below) |
| SELinux domain | `avahi_t` |

avahi-daemon performs an internal privilege drop from `root` to user `avahi` and an internal `chroot()`, both controlled by `/etc/avahi/avahi-daemon.conf`; the role does not set `User=` or `Group=` because the daemon-internal drop preconditions the SELinux type-transition into `avahi_t` and overlapping systemd-side `User=` would race with the internal drop sequence.

Stock targeted policy on Fedora 44 ships the fcontext mapping `/usr/bin/avahi-daemon → avahi_exec_t` correctly, but a Fedora 44 host carries a global `/usr/sbin → /usr/bin` path equivalency that rewrites every `/usr/sbin/<binary>` lookup before the file-context table is consulted; an operator-side reference to `/usr/sbin/avahi-daemon` therefore resolves to the generic `bin_t` label rather than `avahi_exec_t`, and a unit that points at the `/usr/sbin/...` path runs unconfined as a result. All role-internal references use `/usr/bin/avahi-daemon`, and the role's preflight stage validates the mapping with a `matchpathcon /usr/bin/avahi-daemon` fail-fast. The class mechanism, the detection scan, and the mitigation form are documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

The F44 stock vendor unit ships no sandbox layer. The directives it already carries are:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `Type=dbus` | service readiness signalled by D-Bus name acquisition |
| `BusName=org.freedesktop.Avahi` | system-bus name the daemon registers under |
| `ExecStart=/usr/bin/avahi-daemon -s` | daemon process; `-s` selects syslog rather than own logfile |
| `ExecReload=/usr/bin/avahi-daemon -r` | reload via `kill -HUP` semantics |
| `NotifyAccess=main` | only the main PID may issue `sd_notify` |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope. The table also implicitly states what the F44 stock unit does not ship — every `Protect*=`, `Restrict*=`, `Private*=`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `LockPersonality=`, `NoNewPrivileges=`, `CapabilityBoundingSet=`, `User=`, `Group=`, `UMask=`, `ProcSubset=`, `ReadWritePaths=`, `RuntimeDirectory=`, and `StateDirectory=` directive is absent from the vendor unit. The absence is the entirety of what the topic-owned hardening surface fills.

The `avahi` package ships the daemon binary `/usr/bin/avahi-daemon`, the systemd unit file, the resolver helper `avahi-resolve-host-name`, the discovery client `avahi-browse`, the publishing client `avahi-publish`, and the system-tmpfiles configuration that creates `/run/avahi-daemon` at boot. The companion `avahi-libs` package ships the shared libraries; `avahi-tools` ships additional clients; `avahi-glib` and `avahi-gobject` ship language bindings. The role's preflight checks `avahi` package presence; the role does not interact with `/etc/avahi/avahi-daemon.conf` content, with `/etc/avahi/services/` content, or with the system-tmpfiles configuration.

### Three-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/avahi-daemon.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Topic-owned hardening surface (the twenty-three directives below). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_avahi_daemon.cil` | Topic-owned SELinux module that grants `init_t → avahi_t : process2 nnp_transition`. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the topic-owned hardening surface as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/avahi-daemon.service.d/99-hardening.conf`.

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
ProtectProc=invisible
ProcSubset=pid
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/run/avahi-daemon
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service chown fchown lchown chroot
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT
UMask=0027
```

The drop-in carries the twenty-three-directive Phase-A hardening surface that the F44 stock vendor unit does not ship. The Phase-A profile is comprehensive because the F44 avahi stock vendor unit is near-empty: the boundary table above enumerates the five Stock-shipped directives (`Type`, `BusName`, `ExecStart`, `ExecReload`, `NotifyAccess`) and nothing else. The Topic's hardening surface therefore carries every directive systemd would otherwise apply for a moderately-hardened daemon profile, which is why this is the largest topic-owned surface among the topic-tier articles in this tree. The directives group into five effect-classes.

**Kernel-surface protections.** `ProtectSystem=strict` mounts the entire host filesystem read-only inside the unit's mount namespace, with `/etc` and `/var` also denied for write; `ReadWritePaths=/run/avahi-daemon` re-opens the daemon's runtime path as the single writable carve-out under that read-only umbrella. `ProtectHome=yes` denies the operator home directories. `ProtectKernelTunables=yes` denies writes under `/proc/sys/*`. `ProtectKernelModules=yes` denies `init_module(2)`, `finit_module(2)`, and `delete_module(2)`. `ProtectKernelLogs=yes` denies access to `/dev/kmsg` and the `syslog(2)` system call. `ProtectControlGroups=yes` mounts the cgroup pseudo-filesystem read-only. `ProtectClock=yes` denies `settimeofday(2)` and `adjtimex(2)`. `ProtectHostname=yes` denies `sethostname(2)` and `setdomainname(2)`. `ProtectProc=invisible` hides every other process under `/proc/<pid>` from the unit's view. `ProcSubset=pid` further hides the non-PID subdirectories of `/proc` from the unit. `/run/avahi-daemon` is the daemon's only writable runtime path under `ProtectSystem=strict`; the path is created at boot by the system tmpfiles configuration shipped with the `avahi` package and exists before the unit's `ExecStart=` runs, so a host-side runtime-race between systemd's mount setup and the daemon's own runtime-directory creation does not apply to this unit.

**Namespace and personality restrictions.** `PrivateTmp=yes` gives the unit a private `/tmp` and `/var/tmp`. `PrivateDevices=yes` reduces `/dev` to a minimal device set; mDNS uses no character devices beyond the `/dev` minimum (no audio, no video, no block-device access). `RestrictNamespaces=yes` denies `unshare(2)` and `setns(2)`; the daemon does not create namespaces. `LockPersonality=yes` denies `personality(2)`; the daemon runs in the host's native personality and never switches.

**Address-family restriction.** `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK` enumerates the four address families the daemon needs and denies every other family. `AF_INET` and `AF_INET6` carry mDNS multicast traffic. `AF_UNIX` carries the system-bus traffic the daemon registers under `org.freedesktop.Avahi`. `AF_NETLINK` carries kernel-to-userspace interface enumeration that the daemon uses to learn about network interface state changes.

**Syscall and memory-execute restrictions.** `RestrictRealtime=yes` denies `SCHED_FIFO` and `SCHED_RR` realtime scheduling classes. `RestrictSUIDSGID=yes` denies `chmod(2)` invocations that would set SUID or SGID bits on a created file. `MemoryDenyWriteExecute=yes` denies `mmap(PROT_WRITE | PROT_EXEC)` and any `mprotect()` upgrade to `PROT_EXEC` on a writable mapping; the daemon does not JIT. `SystemCallArchitectures=native` denies non-native syscall ABIs (the 32-bit personality on x86_64). The `SystemCallFilter=` directive uses the **allow-list form** (`@system-service` plus the four privileged calls the daemon needs for its initial-startup-plus-internal-drop-plus-internal-chroot path) and never the subtractive form (`~@privileged @resources`); the allow-list strategy avoids the subtractive-filter trap that elsewhere requires a topic-owned SCF iteration profile (see [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md)).

**Capability and umask scope.** `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT` caps the maximum capability set the daemon may ever hold. The five capabilities in `CapabilityBoundingSet=` map to specific operations of the daemon's pre-drop initial-startup phase: `CAP_CHOWN` and `CAP_DAC_OVERRIDE` for ownership and access on `/run/avahi-daemon`, `CAP_SETUID` and `CAP_SETGID` for the internal drop to user `avahi`, and `CAP_SYS_CHROOT` for the internal `chroot()`; once the drop completes the daemon retains none of the five (the bounding set caps the maximum, not the effective set). `UMask=0027` sets the daemon's file-creation default mode so any file the daemon writes under `/run/avahi-daemon` is denied world-read.

The profile does not include `PrivateUsers=`, `DeviceAllow=`, `NoExecPaths=`, `ExecPaths=`, or any further `Restrict*=`/`Protect*=` directive beyond the twenty-three above. Extending the surface to those classes is operator-policy outside this topic and is not validated by the verify discipline this topic ships. The topic also does not modify `/etc/avahi/avahi-daemon.conf` (operator-policy outside this topic; the daemon-internal drop and chroot configuration is upstream-controlled) and does not modify `/etc/avahi/services/` (mDNS service-publishing is operator-policy).

### `99-nnp.conf`

Path: `/etc/systemd/system/avahi-daemon.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon process and on every descendant of that process. avahi-daemon does not exec helper binaries on the mDNS path; the bit applies to the daemon's own process and to any future operator-policy descendants under `/etc/avahi/services/` activation.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → avahi_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t avahi_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_avahi_daemon.cil`

Path: `/usr/local/share/selinux/nnp_avahi_daemon.cil`.

```cil
(allow init_t avahi_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_avahi_daemon.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_avahi_daemon` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched. Appending the rule to a shared multi-service CIL module would couple this topic's deploy and rollback to the deploy and rollback of every other service that shares the module; topic-tier discipline rules out that coupling.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts (kernel-level NNP-transition constraint, why stock policy lacks the rule for this domain, the per-domain scope of the rule), see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/avahi-daemon.service.d/` | `0755` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/avahi-daemon.service.d/99-hardening.conf` | `0644` | `root:root` | `avahi_unit_file_t` |
| `/etc/systemd/system/avahi-daemon.service.d/99-nnp.conf` | `0644` | `root:root` | `avahi_unit_file_t` |
| `/usr/local/share/selinux/nnp_avahi_daemon.cil` | `0644` | `root:root` | `usr_t` |

Stock targeted policy on Fedora 44 or later does carry a service-specialised type for these files. `file_contexts` maps `/usr/lib/systemd/system/avahi.*` to `avahi_unit_file_t`, and the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency in `file_contexts.subs_dist` extends that mapping to the drop-in path under `/etc`. The drop-in *directory* is not covered by the mapping — the entry is qualified with `--`, which matches regular files only — so it keeps the generic `systemd_unit_file_t`, which is its correct type.

Nothing assigns the mapped type at creation time. A file written into the drop-in directory inherits that directory's `systemd_unit_file_t`, and the role's `restorecon -F -v -R` on the drop-in directory is what moves it to `avahi_unit_file_t`. The `-R` covers the directory itself, which this role creates and which no other step revisits; the `-F` additionally resets the SELinux user field, which a type-only comparison such as `restorecon -n` never reports. Without the relabel the merged unit still runs — systemd reads drop-ins regardless of label — but the hardening artefact keeps the wider generic type while the stock unit file beside it carries the narrower one. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_avahi_daemon/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`avahi`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the mDNS multicast-join count read from the journal via `journalctl -u avahi-daemon -b 0 --no-pager | grep -F "Joining mDNS multicast group"`, the mDNS resolution roundtrip via `avahi-resolve-host-name $(hostname).local` with a default 5-second timeout, and the `semodule -l | grep nnp_avahi_daemon` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_avahi_daemon/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `yes` |
| `ProtectKernelTunables` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectControlGroups` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectHostname` | `yes` |
| `ProtectProc` | `invisible` |
| `ProcSubset` | `pid` |
| `PrivateTmp` | `yes` |
| `PrivateDevices` | `yes` |
| `ReadWritePaths` | contains substring `/run/avahi-daemon` |
| `RestrictAddressFamilies` | exactly `AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_NETLINK` |
| `RestrictNamespaces` | `yes` |
| `RestrictRealtime` | `yes` |
| `RestrictSUIDSGID` | `yes` |
| `LockPersonality` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `SystemCallArchitectures` | `native` |
| `SystemCallFilter` | contains `@system-service`, `chown`, `fchown`, `lchown`, `chroot` |
| `CapabilityBoundingSet` | exactly `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_CHROOT` |
| `UMask` | `0027` (or the equivalent decimal `23`) |
| Live SELinux domain | `avahi_t` |
| mDNS multicast-join | one or more lines in the journal since boot |
| mDNS resolution roundtrip | exit `0` with non-empty stdout in 5 seconds |
| `semodule -l \| grep nnp_avahi_daemon` | one line (sysadm_t-gated) |

The `ReadWritePaths` value returned by `systemctl show -p ReadWritePaths --value` is path-list-formatted; the verify script normalises and asserts substring presence. The `RestrictAddressFamilies` and `CapabilityBoundingSet` values are normalised against whitespace and the exact-set match is enforced — presence of any other family or capability is drift, absence of any of the listed values is drift. The `SystemCallFilter` value is asserted by substring presence of the five tokens; the directive's effect is positive-allow form. The `UMask` value is normalised against the decimal-form (`23`) that some systemd versions return.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `avahi_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The mDNS multicast-join count is asserted as one-or-more; failure on this is drift, because the daemon failed to join any multicast group at boot (a directive regression in `99-hardening.conf` is suspected — most commonly `RestrictAddressFamilies=` missing one of the four families). The mDNS resolution roundtrip is asserted as a non-zero-exit-or-empty failure being a warning, not drift; the resolution path depends on host-side network reachability that is outside the role's scope. The `semodule -l | grep nnp_avahi_daemon` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(avahi_t|avahi_exec_t|nnp_transition|avahi)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### mDNS smoketest

The post-deploy smoketest uses two complementary checks with different exit-state semantics:

```bash
journalctl -u avahi-daemon -b 0 --no-pager | grep -F "Joining mDNS multicast group"
avahi-resolve-host-name "$(hostname).local"
```

The first check is the **drift class**. `journalctl -u avahi-daemon -b 0 --no-pager | grep -cF "Joining mDNS multicast group"` returns one or more lines per active interface on a healthy host (typically one IPv4 plus one IPv6 line per non-loopback interface plus the corresponding loopback lines). A zero-count outcome is drift. The check is deterministic and reads persistent boot-state from the journal; it does not depend on network reachability at verify time.

The second check is the **warning class**. `avahi-resolve-host-name "$(hostname).local"` exits `0` and prints a non-empty resolution within a 5-second default timeout. A non-zero exit or empty output is a warning, not drift; the resolution path includes external mDNS reachability that is outside the role's hardening scope.

The pre-hardening mDNS baseline is the operator-side companion to the post-deploy smoketest. Before deploying the three-artefact profile, capture:

```bash
systemctl is-active avahi-daemon.service
journalctl -u avahi-daemon -b 0 --no-pager | grep -F "Joining mDNS multicast group" | head -10
journalctl -b 0 -p err -u avahi-daemon --no-pager | tail -20
avahi-resolve-host-name "$(hostname).local" || true
```

On a stock host with avahi-daemon active, the multicast-join grep returns one or more lines per active interface. The error-stream tail is empty on a healthy stock host. The resolution roundtrip succeeds on a host with a routable interface. The role's preflight stage runs the same recon and reports the outcome non-fatally; a non-empty error stream signals a pre-existing avahi issue that the operator should investigate before deploying the role (post-deploy errors would otherwise be misattributed to the hardening surface).

The role's modify stage is idempotent. The three shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee. A restart of `avahi-daemon.service` interrupts mDNS service publishing and discovery on the host; established LAN peers' caches expire over the daemon's normal TTL window after the restart, and the role's `restart avahi-daemon` handler is the documented apply path on a host where a brief mDNS interruption is acceptable, with the alternative being to apply the role and reboot.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_avahi_daemon`, then `systemctl daemon-reload` and `systemctl restart avahi-daemon.service`. The NNP layer alone is reverted; the topic-owned hardening surface remains. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback. avahi-daemon's hardening surface is the largest in this tree, which raises the misconfiguration probability over the smaller-surface topics; a misconfigured CIL module (a wrong target-domain in a manual edit, for example) or a `NoNewPrivileges=yes` deploy without the matching CIL extension causes the daemon to fail at next boot. The Recovery-Pointer banner below is the operator's path through that case; the topic body does not enumerate the operator workflows that depend on mDNS discovery.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → avahi_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/avahi-daemon` at next boot under `no_new_privs`.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — Why a daemon whose stock SELinux mapping points at `/usr/sbin/<binary>` runs unconfined on Fedora 44, and why `/usr/bin/avahi-daemon` is the only path the role and the verify discipline reference.
