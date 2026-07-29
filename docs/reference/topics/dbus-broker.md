<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# dbus-broker

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the system-bus `dbus-broker.service` on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/dbus-broker.service.d/` and `/usr/local/share/selinux/`: a topic-owned hardening drop-in that adds six conservative directives the F44 stock vendor unit does not already ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the `init_t → system_dbusd_t : process2 nnp_transition` denial that stock targeted policy carries for this domain. The end-state also includes the verify discipline (per-property reads, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion), the system-bus functional smoketest, the pre-hardening system-bus baseline, and a two-stage rollback posture. This topic does not cover `/etc/dbus-1/system.conf`, the configuration include directories under `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`, the per-user session-bus broker, the legacy `dbus-daemon` reference implementation, the `systemd-analyze security` numeric score model, or any extended hardening direction beyond the six conservative directives in `99-hardening.conf`.

## End-state configuration

The end-state combines three shipping artefacts: a topic-owned hardening drop-in that carries six directives the F44 stock vendor unit does not already ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's domain. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates what the F44 stock vendor unit already carries and what the topic therefore does not modify.

### Service identity

The unit `dbus-broker.service` is shipped by the `dbus-broker` package and is the system-wide D-Bus message broker on a Fedora 44 host. The stock vendor file at `/usr/lib/systemd/system/dbus-broker.service` carries the directives this topic does not modify. The daemon runs as `root` throughout and performs no privilege drop. `ExecStart=` is `/usr/bin/dbus-broker-launch --scope system --audit`. The unit is socket-activated through `dbus.socket`, which pre-binds the system-bus AF_UNIX socket at `/run/dbus/system_bus_socket` before the broker's `ExecStart=` runs.

| Property | Value |
|---|---|
| Unit | `dbus-broker.service` |
| Type | `notify-reload` |
| ExecStart | `/usr/bin/dbus-broker-launch --scope system --audit` |
| User / group | `root:root` (no privilege drop) |
| Sockets | `dbus.socket` (`Requires=`, `After=`) |
| SELinux domain | `system_dbusd_t` |

The SELinux type-transition `init_t → system_dbusd_t` fires on the executable label `dbusd_exec_t` carried by the broker binary at `/usr/bin/dbus-broker` and the launcher wrapper at `/usr/bin/dbus-broker-launch`.

The vendor unit ships **no** `RuntimeDirectory=` and **no** `StateDirectory=`. The system-bus AF_UNIX socket at `/run/dbus/system_bus_socket` is owned by `dbus.socket` activation and exists before the broker's `ExecStart=` runs, so the broker writes no self-managed runtime path. As a consequence, no boot-time mount-namespace race on a daemon-created runtime path applies to this unit — the structural reason is that the broker writes no runtime path at all, not that a `RuntimeDirectory=` declaration pre-creates one.

The F44 stock vendor unit ships a minimal sandbox layer. The directives it already carries are:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `Type=notify-reload` | broker raises `SIGHUP` for live config reload |
| `Sockets=dbus.socket` | system-bus AF_UNIX socket pre-bound by socket activation |
| `ProtectSystem=full` | `/usr`, `/boot`, `/efi` read-only (`/etc` and `/var` writable) |
| `PrivateTmp=true` | private `/tmp` and `/var/tmp` |
| `PrivateDevices=true` | `/dev` reduced to a minimal device set |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope. The table also implicitly states what the F44 stock unit does not ship — every other `Protect*=`, `Restrict*=`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `RestrictAddressFamilies=`, `LockPersonality=`, `NoNewPrivileges=`, `CapabilityBoundingSet=`, `User=`, `Group=`, `RuntimeDirectory=`, and `StateDirectory=` directive is absent from the vendor unit, and that absence is what the topic-owned hardening surface partially fills.

The `dbus-broker` package ships the broker binary `/usr/bin/dbus-broker`, the launcher wrapper `/usr/bin/dbus-broker-launch`, the systemd unit file, and integration with the `dbus.socket` activation path. The companion `dbus-common` package ships `/etc/dbus-1/system.conf` and the system-bus configuration include directories under `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`. The legacy `dbus-daemon` package is a parallel reference implementation and is not active on a host where dbus-broker is the system-bus provider. The role's preflight stage checks `dbus-broker` package presence; the role does not interact with `/etc/dbus-1/system.conf` content or with the configuration include directories.

### Three-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/dbus-broker.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Topic-owned hardening surface (six conservative `Protect*=`/`SystemCallArchitectures=`/`MemoryDenyWriteExecute=` directives). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_dbus_broker.cil` | Topic-owned SELinux module that grants `init_t → system_dbusd_t : process2 nnp_transition`. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the topic-owned hardening surface as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/dbus-broker.service.d/99-hardening.conf`.

```ini
[Service]
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
```

The drop-in adds six conservative directives the F44 stock vendor unit does not already ship. Each directive's effect on this daemon:

- `ProtectClock=yes` — denies `settimeofday(2)` and `adjtimex(2)` from the broker. dbus-broker has no clock-related codepath; the directive is risk-free.
- `ProtectKernelLogs=yes` — denies access to `/dev/kmsg` and the `syslog(2)` system call. The broker writes its messages to the systemd journal via `sd_notify` and `sd_journal_send`, not directly to `/dev/kmsg`.
- `ProtectKernelModules=yes` — denies `init_module(2)`, `finit_module(2)`, and `delete_module(2)`. The broker does not load or unload kernel modules.
- `ProtectControlGroups=yes` — mounts the cgroup pseudo-filesystem read-only inside the unit's mount namespace. The broker does not write to cgroup paths.
- `SystemCallArchitectures=native` — denies non-native syscall ABIs (the 32-bit personality on x86_64). The broker is built native-only; the directive eliminates the 32-bit syscall surface as a confused-deputy class.
- `MemoryDenyWriteExecute=yes` — denies `mmap(PROT_WRITE | PROT_EXEC)` and `mprotect()` upgrades to `PROT_EXEC` on writable mappings. The broker does not JIT.

The surface is deliberately conservative. dbus-broker is the system-wide D-Bus message broker; a `Restrict*=`/`Private*=`/`Protect*=` directive that breaks broker startup or live-reload cascades into every login service that depends on the system bus. The topic restricts the surface to the six well-understood directives above that have no documented broker-side codepath and are reboot-validated as side-effect-free. The drop-in does **not** include `RestrictNamespaces=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectHostname=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `LockPersonality=`, `RestrictAddressFamilies=`, `ProcSubset=`, `UMask=`, `CapabilityBoundingSet=`, `SystemCallFilter=`, `User=`, or `Group=` directives. Extending the surface to those classes is operator-policy outside this topic and is not validated by the verify discipline this topic ships. The topic also does not modify `/etc/dbus-1/system.conf` (system-bus configuration is upstream-managed) and does not layer a topic-side `SystemCallFilter=` profile.

This Topic documents the **system-bus** dbus-broker.service end-state only; the per-user session-bus broker (started by the `dbus-broker.service` user-unit out of `dbus.socket` user-instance) is operator-policy outside this Topic and is not configured by the role.

dbus-broker runs as `root` throughout and performs no privilege drop, so the privilege-drop class that elsewhere requires a topic-owned SCF profile (see [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md)) does not apply to this daemon.

### `99-nnp.conf`

Path: `/etc/systemd/system/dbus-broker.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the broker process and on every descendant of that process. The broker does not exec helper binaries on the system-bus path; activated services started through D-Bus activation (dbus-daemon-style legacy activation or systemd-activated units) execute outside the broker's process tree and are not affected by this directive.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → system_dbusd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t system_dbusd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_dbus_broker.cil`

Path: `/usr/local/share/selinux/nnp_dbus_broker.cil`.

```cil
(allow init_t system_dbusd_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_dbus_broker.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_dbus_broker` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched. Appending the rule to a shared multi-service CIL module would couple this topic's deploy and rollback to the deploy and rollback of every other service that shares the module; topic-tier discipline rules out that coupling.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts (kernel-level NNP-transition constraint, why stock policy lacks the rule for this domain, the per-domain scope of the rule), see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/dbus-broker.service.d/99-hardening.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/dbus-broker.service.d/99-nnp.conf` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/usr/local/share/selinux/nnp_dbus_broker.cil` | `0644` | `root:root` | `usr_t` |

Targeted policy on Fedora 44 defines a `dbusd_unit_file_t` type, but `file_contexts` carries no path pattern that assigns it: no entry matches `/usr/lib/systemd/system/dbus-broker*`, so the `/etc/systemd/system` → `/usr/lib/systemd/system` equivalency resolves to nothing more specific than the generic rule. The expected type for the drop-in directory and for every file inside it is therefore the `systemd_unit_file_t` they inherit at creation, and `matchpathcon` confirms it. No `type_transition` to a `*_unit_file_t` exists for PID 1.

The role runs `restorecon -F -v -R` on the drop-in directory anyway. The call is a no-op on the type, but `-F` normalises the SELinux user field, which otherwise keeps the identity of whoever applied the role and stays invisible to the type-only comparison of `restorecon -n`. The step also remains correct if a future policy release adds a mapping for this path. See [Drop-in files and SELinux context inheritance](../../explanation/dropin-selinux-context-inheritance.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_dbus_broker/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`dbus-broker`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `busctl --system list` system-bus smoketest, the `dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames` round-trip smoketest, and the `semodule -l | grep nnp_dbus_broker` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_dbus_broker/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectControlGroups` | `yes` |
| `SystemCallArchitectures` | `native` |
| `MemoryDenyWriteExecute` | `yes` |
| Live SELinux domain | `system_dbusd_t` |
| `busctl --system list` | exit `0`, output contains `org.freedesktop.DBus` |
| `dbus-send` round-trip | exit `0`, reply parses as `method return` containing a non-empty `array of string` |
| `semodule -l \| grep nnp_dbus_broker` | one line (sysadm_t-gated) |

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `system_dbusd_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `busctl --system list` check returns the bus-name list of the system bus and is the primary functional smoketest; on a healthy host the list contains `org.freedesktop.DBus` and a set of `:1.N`-style unique names for connected peers, and a non-zero exit or an empty list is drift. The `dbus-send` round-trip exercises the broker's request-reply path through the public D-Bus interface and is the secondary functional smoketest; failure on either smoketest is drift, not warning. The `semodule -l | grep nnp_dbus_broker` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(system_dbusd_t|nnp_transition|dbus_broker|dbusd_exec_t)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### System-bus smoketest

The post-deploy smoketest uses the public D-Bus interface stack:

```bash
busctl --system list
dbus-send --system --print-reply --dest=org.freedesktop.DBus \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames
```

On a correctly hardened host, `busctl --system list` returns exit `0` with a non-empty bus-name list. The list contains at least `org.freedesktop.DBus` (the broker's own self-name) and `:1.N`-style unique-name entries for connected peers. The `dbus-send` invocation returns exit `0` with a `method return` reply containing an `array of string` of the same set. The smoketest is functional, not a hardening assertion; it catches regressions where one of the six topic-owned directives would silently break the broker's IPC path (rare on the F44 dbus-broker code path, which uses none of the denied subsystems, but the smoketest is the operator's signal).

The pre-hardening system-bus baseline is the operator-side companion to the post-deploy smoketest. Before deploying the three-artefact profile, capture:

```bash
busctl --system list
journalctl -b 0 -u dbus-broker.service --no-pager | tail -20
journalctl -b 0 -p err -t dbus-broker --no-pager | tail -20
```

On a stock host, `busctl --system list` returns a populated bus-name list including `org.freedesktop.DBus` and several `:1.N` unique names. The two `journalctl` invocations capture the broker's startup state and any error-level records since the last boot, both expected empty on a healthy stock host. The role's preflight stage runs the same recon and reports the outcome non-fatally; a non-empty error stream signals a pre-existing broker-side issue that the operator should investigate before deploying the role (post-deploy errors would otherwise be misattributed to the hardening surface).

The role's modify stage is idempotent. The three shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee. A restart of `dbus-broker.service` interrupts the system message bus and disconnects every connected peer; the role's `restart dbus-broker` handler is the documented apply path on a host where a restart is acceptable, and the alternative is to apply the role and reboot.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_dbus_broker`, then `systemctl daemon-reload` and `systemctl restart dbus-broker.service`. The NNP layer alone is reverted; the topic-owned hardening surface remains. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback. dbus-broker is the system-wide D-Bus message broker; a misconfigured CIL module (a wrong target-domain in a manual edit, for example) or an `NoNewPrivileges=yes` deploy without the matching CIL extension causes the broker to fail at next boot, which cascades into every login service that depends on the system bus. The Recovery-Pointer banner below is the operator's path through that cascade; the topic body does not enumerate the dependent services.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → system_dbusd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/bin/dbus-broker-launch` at next boot under `no_new_privs`.
