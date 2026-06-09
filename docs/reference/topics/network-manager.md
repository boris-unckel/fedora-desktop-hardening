<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# NetworkManager

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of the `NetworkManager.service` system network-management daemon on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/NetworkManager.service.d/` and `/usr/local/share/selinux/`: a namespace-default baseline drop-in, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that enables the `init_t → NetworkManager_t : process2 nnp_transition` rule that stock targeted policy does not ship for this domain. The end-state also includes the `ReadWritePaths=` runtime-race mitigation via a leading `-` on `/run/NetworkManager`, the verify discipline (per-property reads, alphabetical-source-order address-family check, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion), the connectivity smoketest, and a two-stage rollback posture. This topic does not cover `MemoryDenyWriteExecute=`, `SystemCallFilter=`, or `CapabilityBoundingSet=` narrowing — the daemon `dlopen`'s plugins from the libnm family, VPN backends, and dispatcher hooks, and the process-internal kernel-restrictions layer requires a per-plugin audit that is operator-policy outside this topic. This topic also does not cover the NetworkManager plugin packages (`NetworkManager-wifi`, `NetworkManager-openvpn`, and other operator-policy surface), the sister units `nm-dispatcher.service` and `NetworkManager-wait-online.service`, the connection-profile content under `/etc/NetworkManager/system-connections/`, or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: a namespace-default baseline drop-in that carries the `Protect*` family, the address-family restriction, and the personality and architecture restrictions; an isolated `NoNewPrivileges=yes` drop-in; and a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's domain. Subsections below describe each artefact in turn.

### Service identity

The unit `NetworkManager.service` is shipped by the `NetworkManager` package. The stock vendor file at `/usr/lib/systemd/system/NetworkManager.service` carries the directives this topic does not modify:

| Property | Value |
|---|---|
| Unit | `NetworkManager.service` |
| Type | `dbus` (`BusName=org.freedesktop.NetworkManager`) |
| ExecStart | `/usr/sbin/NetworkManager --no-daemon` |
| User / group | `root:root` |
| SELinux domain | `NetworkManager_t` |

The SELinux type-transition `init_t → NetworkManager_t` fires on the executable label `NetworkManager_exec_t` carried by the binary. The stock vendor unit ships `ProtectSystem=true` and `KillMode=process`. The latter is a keep-children invariant: the DHCP client, the active connection state, and the helper processes the daemon spawned remain alive across a daemon restart, so a restart of the unit does not tear down the configured network. Both directives are inherited unchanged by the hardened end-state.

The vendor unit ships **no** `RuntimeDirectory=NetworkManager`, **no** `StateDirectory=`, **no** `ConfigurationDirectory=`, and **no** `LogsDirectory=` directive. The daemon creates `/run/NetworkManager` itself, in its own startup code path, after the unit's namespace setup has completed. The absence of `RuntimeDirectory=NetworkManager` is the precondition for the runtime-race mitigation in `99-hardening.conf` below; the role's preflight stage greps the vendor unit and aborts with a manifest-revision-required message if a future package version upstreams the directive.

The `NetworkManager` package ships the daemon binary, the libnm core library, and the D-Bus interface definitions. NetworkManager plugin packages and the connection-profile content under `/etc/NetworkManager/system-connections/` are operator-policy and outside this topic. The role's preflight stage checks the `NetworkManager` package presence; the role does not interact with plugin packages.

### Two-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/NetworkManager.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Namespace-default baseline (`Protect*` suite, `ReadWritePaths=` with the runtime-race mitigation, address-family restriction, namespace and personality restrictions, architecture restriction, UMask). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_network_manager.cil` | Topic-owned SELinux module that grants `init_t → NetworkManager_t : process2 nnp_transition`. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the namespace-default baseline as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/NetworkManager.service.d/99-hardening.conf`.

```ini
[Service]
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/NetworkManager /var/lib/NetworkManager -/run/NetworkManager
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0027
```

Directive notes:

- `ProtectSystem=strict` — `/usr`, `/boot`, `/efi`, `/etc`, and `/var` are mounted read-only for the daemon. Combined with the explicit `ReadWritePaths=` list below, the daemon retains write access only to the three paths it needs: its config tree, its state tree, and its runtime tree.
- `ProtectHome=yes` — operator home directories are inaccessible. The daemon does not consume per-user configuration in the system-mode service.
- `ReadWritePaths=/etc/NetworkManager /var/lib/NetworkManager -/run/NetworkManager` — three writable paths under `ProtectSystem=strict`. The leading `-` on `/run/NetworkManager` is the runtime-race mitigation: the path does not exist at boot time, and an unmodified entry would cause systemd's NAMESPACE step to fail with `status=226/NAMESPACE` before the daemon's own startup code can create the directory. The class mechanism — why the bind-mount runs before `ExecStart=`, why the trap surfaces only at next boot, and why the `-`-prefix is the minimally invasive fix — is documented in [ReadWritePaths runtime race](../../explanation/readwritepaths-runtime-race.md). Symptom signature: journal `Failed to set up mount namespacing` plus `status=226/NAMESPACE`.
- `ProtectKernelLogs=yes` — the kernel log devices are denied. The daemon reads kernel state via netlink and does not require `/dev/kmsg`.
- `ProtectControlGroups=yes` — the cgroup pseudo-filesystem is read-only. The daemon does not adjust resource limits.
- `ProtectClock=yes` — `settimeofday(2)` and `adjtimex(2)` are denied.
- `ProtectProc=invisible` — the per-process `/proc` view is restricted to PIDs the daemon owns. The daemon reads its own networking state via `/proc/<self>/net/*`, not other daemons' PIDs.
- `PrivateTmp=yes` — private `/tmp` and `/var/tmp`. The daemon does not coordinate temporary state with other processes.
- `PrivateDevices=yes` — only the device-list essentials are visible (`/dev/null`, `/dev/zero`, `/dev/random`, and the small set of pseudo-devices the standard library expects); raw block devices and most special devices are hidden. The daemon's connection setup uses netlink-based interface manipulation, not `/dev`-resident interfaces.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX` — five address families, alphabetical-source-order. `AF_NETLINK` is required for RTNETLINK (route and address manipulation). `AF_PACKET` is required for raw-packet sockets used by the DHCP client (Layer-2 broadcast before IP configuration is established). `AF_INET` and `AF_INET6` are the IPv4 and IPv6 socket families. `AF_UNIX` is the D-Bus transport. Removing any of these breaks a specific NetworkManager subsystem. `systemctl show -p RestrictAddressFamilies --value` returns the families source-ordered, so the verify script normalises both observed and expected to alphabetical lower-case-equivalent form for stable comparison.
- `RestrictNamespaces=yes` — denies `unshare(2)` and `setns(2)` for all namespace types. The daemon does not create namespaces.
- `RestrictRealtime=yes` — `SCHED_FIFO` and `SCHED_RR` are denied.
- `RestrictSUIDSGID=yes` — refuses `chmod` setting the SUID or SGID bits on file creation and rename.
- `LockPersonality=yes` — refuses `personality(2)` calls.
- `SystemCallArchitectures=native` — denies non-native syscall ABIs.
- `UMask=0027` — files the daemon creates default to mode `0640`, directories to `0750`.

The profile does **not** include `MemoryDenyWriteExecute=`, `SystemCallFilter=`, or `CapabilityBoundingSet=` narrowing. The daemon `dlopen`'s the libnm-* core plugins, VPN backends (when their plugin packages are installed), and dispatcher hooks; a writable-to-executable memory page is a normal `dlopen` step, and `MemoryDenyWriteExecute=yes` would break plugin loading. Plugins call into varied syscall classes; narrowing `SystemCallFilter=` requires a per-plugin audit that the operator is not in a position to perform without breaking site-specific deployments. The stock capability set is broad (the daemon needs `CAP_NET_ADMIN` and `CAP_NET_RAW` for connection management, plus `CAP_DAC_READ_SEARCH` for some plugin paths and the kernel-module IOCTL paths some plugins use), and trimming it requires the same per-plugin audit. The boundary marker keeps this topic distinct from a daemon profile that ships the multi-stage privilege-drop layer (see [Multi-stage privilege-drop and SystemCallFilter carve-outs](../../explanation/phase-b-scf-privdrop.md)).

The `Protect*` family directives in this drop-in carry an implicit `PrivateMounts=true` enable. The daemon is not a mount-manager; it issues no `mount(2)` calls and does not coordinate filesystem visibility with other processes. The implicit enable has no operator-visible effect here, and the boundary marker keeps this topic distinct from the mount-manager class.

### `99-nnp.conf`

Path: `/etc/systemd/system/NetworkManager.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon and on every descendant. The daemon's helper processes — the DHCP client, the dispatcher script invocation path, and the DNS plugin — all start under the bit, and setuid binaries the daemon executes lose their privilege escalation; the bit is sticky and cannot be cleared by a child.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → NetworkManager_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t NetworkManager_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_network_manager.cil`

Path: `/usr/local/share/selinux/nnp_network_manager.cil`.

```cil
(allow init_t NetworkManager_t (process2 (nnp_transition)))
```

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_network_manager.cil` from a `sysadm_r/sysadm_t` role-switch. The module isolates the role's deploy and rollback footprint at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_network_manager` and removes only this topic's policy extension, leaving any other site-local CIL modules at the same priority untouched.

Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). For the broader class of trap that the rule lifts, see [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/NetworkManager.service.d/99-hardening.conf` | `0644` | `root:root` | `NetworkManager_unit_file_t` |
| `/etc/systemd/system/NetworkManager.service.d/99-nnp.conf` | `0644` | `root:root` | `NetworkManager_unit_file_t` |
| `/usr/local/share/selinux/nnp_network_manager.cil` | `0644` | `root:root` | `usr_t` |

Stock targeted policy on Fedora 44 or later carries a type-transition `init_t → NetworkManager_unit_file_t : file create` for files under `/etc/systemd/system/NetworkManager.service.d/`. The role's `restorecon` after `ansible.builtin.copy` is what triggers the relabel from the install-time default (typically `staff_u:object_r:systemd_unit_file_t` when the operator drops the file from a `staff_t` shell) to the unit-specific type. Without the relabel the merged unit still runs because systemd reads merged units regardless of label, but `ls -lZ` shows the wrong type and a future audit flags it.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_network_manager/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`NetworkManager`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `nmcli -t -f STATE general` connectivity smoketest, and the `semodule -l | grep nnp_network_manager` lookup that confirms the CIL module is loaded. The CIL lookup is gated behind a `sysadm_t` check and reports `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_network_manager/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` and `WARN` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `ProtectSystem` | `strict` |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX` (alphabetical normalisation) |
| `RestrictNamespaces` | `yes` |
| `LockPersonality` | `yes` |
| Live SELinux domain | `NetworkManager_t` |
| `nmcli -t -f STATE general` | `connected` |
| `semodule -l \| grep nnp_network_manager` | one line (sysadm_t-gated) |

The `RestrictAddressFamilies` normalisation is load-bearing. `systemctl show -p RestrictAddressFamilies --value` returns the families in source order; the verify script sorts both the observed and the expected value into alphabetical order before the equality check, so a drop-in that re-orders the families (a stylistic edit, not a functional change) does not false-flag as drift.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a root-owned PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `NetworkManager_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `nmcli -t -f STATE general` check is read-only and works from `staff_t` without escalation; it is the primary functional smoketest. The `semodule -l | grep nnp_network_manager` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(NetworkManager_t|nnp_transition|NetworkManager)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Connectivity smoketest

The post-deploy smoketest uses the public connectivity stack:

```bash
nmcli -t -f STATE general
ip route show default
nmcli -t -f IP4.ADDRESS,IP4.DNS device show
```

On a correctly hardened host with a working network, the first command returns `connected`, the second returns at least one default-route line, and the third returns a non-empty IPv4 address on the active interface. The smoketest is functional, not a hardening assertion; it catches regressions where a too-aggressive sandbox layer would silently break a NetworkManager subsystem (DHCP, plugin load, dispatcher invocation). The role captures the same baseline under `nmcli -t -f STATE general` in the preflight stage and the verify stage compares post-deploy state against the captured baseline.

The role's modify stage is idempotent. The three shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_network_manager`, then `systemctl daemon-reload` and `systemctl restart NetworkManager.service`. The NNP layer alone is reverted; the namespace-default baseline remains. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback (the `status=226/NAMESPACE` shape that the `-`-prefix mitigation prevents on a correctly deployed host). If a host without the mitigation enters the boot-failure state, the recovery is a rescue-image chroot; this Reference does not inline boot-failure recovery.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [ReadWritePaths runtime race](../../explanation/readwritepaths-runtime-race.md) — Why a `ReadWritePaths=` entry on a self-managed runtime path fails the bind-mount step at boot, why the trap is invisible to `systemd-analyze verify` and to `systemctl restart`, and why the `-`-prefix on the affected entry is the minimally invasive fix.
- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → NetworkManager_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/sbin/NetworkManager` at next boot under `no_new_privs`.
