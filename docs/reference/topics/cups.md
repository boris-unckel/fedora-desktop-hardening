<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# cups

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state hardening of `cups.service` on a Fedora 44 or later host. The end-state is a three-artefact deploy profile under `/etc/systemd/system/cups.service.d/` and `/usr/local/share/selinux/`: a topic-owned hardening drop-in that adds seven directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the `init_t → cupsd_t : process2 nnp_transition` denial that stock targeted policy carries for this domain together with three inter-domain helper-spawn rules for the cupsd-driven helper subdomains. The end-state also includes the verify discipline (per-property reads, `[ -d /proc/${main_pid} ]` liveness, AVC-clean assertion, live-domain assertion, four positive-rule presence checks against the loaded SELinux policy), three drift-class print smoketests, the pre-hardening printer baseline, and a two-stage rollback posture. This topic does not cover `/etc/cups/cupsd.conf` content, the printer definitions under `/etc/cups/printers.conf`, the class definitions under `/etc/cups/classes.conf`, the policy file `/etc/cups/cups-files.conf`, the daemon working directories under `/var/spool/cups/` and `/var/log/cups/`, the published service definitions under `/etc/cups/services/`, the cupsd-internal privilege model (the `User=` and `Group=` directives are not configured by this role), or the `systemd-analyze security` numeric score model.

## End-state configuration

The end-state combines three shipping artefacts: a topic-owned hardening drop-in that carries seven directives the F44 stock vendor unit does not ship, an isolated `NoNewPrivileges=yes` drop-in, and a topic-owned SELinux CIL module that lifts the kernel NNP-transition denial for the daemon's main domain and for three helper subdomains that cupsd spawns under `no_new_privs`. Subsections below describe each artefact in turn, after a service-identity subsection that enumerates what the F44 stock vendor unit already carries and what the topic therefore does not modify.

### Service identity

The unit `cups.service` is shipped by the `cups` package and is the print scheduler on a Fedora 44 host. The stock vendor file at `/usr/lib/systemd/system/cups.service` carries the directives this topic does not modify. The daemon binary is installed at `/usr/sbin/cupsd`. cupsd retains the privilege model defined by the upstream `cups` package; the role does not set `User=` or `Group=` and does not modify `/etc/cups/cupsd.conf`, `/etc/cups/cups-files.conf`, or any printer or class definitions under `/etc/cups/printers.conf` and `/etc/cups/classes.conf`. The unit listens on TCP `127.0.0.1:631` and `[::1]:631`.

| Property | Value |
|---|---|
| Unit | `cups.service` |
| Type | `notify` |
| ExecStart | `/usr/bin/cupsd -l` |
| User / group | not set on the unit (upstream-controlled internal privilege model) |
| Daemon binary | `/usr/sbin/cupsd` |
| SELinux domain | `cupsd_t` |
| Drop-in directory SELinux type | `cupsd_unit_file_t` |
| Listen sockets | TCP `127.0.0.1:631`, `[::1]:631` |

The Fedora 44 cups package installs the daemon binary at `/usr/sbin/cupsd`. A Fedora 44 host carries a global `/usr/sbin → /usr/bin` path equivalency that rewrites every `/usr/sbin/<binary>` lookup before the file-context table is consulted; the F44 `/usr/sbin → /usr/bin` equivalency rewrites the lookup, and the role validates the mapping with a `matchpathcon` fail-fast against both `/usr/sbin/cupsd` and `/usr/bin/cupsd` (either path resolving to `cupsd_exec_t` is sufficient). The class mechanism, the detection scan, and the mitigation form are documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

The F44 stock vendor unit ships no sandbox layer. The directives it already carries are:

| Stock directive (F44 vendor unit) | Effect |
|---|---|
| `Type=notify` | service readiness signalled by `sd_notify` |
| `ExecStart=/usr/bin/cupsd -l` | daemon process; `-l` selects launch-on-demand (socket-activated) mode |
| `Restart=on-failure` | unit restarts automatically when the main process exits non-zero |
| `Slice=system-cups.slice` | the unit runs under a dedicated cgroup slice |
| `Requires=cups.socket` | socket-activation precondition; the listening sockets are managed by `cups.socket` |

The table is a boundary tabulation only, not a derivation: the rationale for each stock directive is upstream's responsibility and is out of topic scope. The table also implicitly states what the F44 stock unit does not ship — every `Protect*=`, `Restrict*=`, `Private*=`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `LockPersonality=`, `NoNewPrivileges=`, `CapabilityBoundingSet=`, `UMask=`, `ProcSubset=`, `ReadWritePaths=`, `RuntimeDirectory=`, and `StateDirectory=` directive is absent from the vendor unit. The absence is the entirety of what the topic-owned hardening surface fills.

The `cups` package ships the daemon binary `/usr/sbin/cupsd`, the systemd unit file, the runtime tmpfiles configuration that creates `/run/cups/` at boot, the configuration files under `/etc/cups/`, the spool directory layout under `/var/spool/cups/`, the log directory under `/var/log/cups/`, the cache directory under `/var/cache/cups/`, the backends under `/usr/lib/cups/backend/` (LPD, IPP, USB, dnssd, snmp, socket, http, beh, parallel, scsi), the filters under `/usr/lib/cups/filter/`, the CGI helpers under `/usr/lib/cups/cgi-bin/`, the notifier helpers under `/usr/lib/cups/notifier/`, the resolver helper `lpinfo`, and the queue-control helper `lpstat`. The companion `cups-libs` package ships the shared libraries; `cups-client` ships additional clients; `cups-filters` ships the filter cascade; `cups-pdf` ships the PDF backend. `cups-browsed` is a separate companion daemon outside this topic's scope. The role's preflight checks `cups` package presence and `lpinfo` tooling availability.

### Three-artefact deploy profile

The hardening profile splits across two drop-in INI files under `/etc/systemd/system/cups.service.d/` and one CIL module under `/usr/local/share/selinux/`:

| File | Layer |
|---|---|
| `99-hardening.conf` | Topic-owned hardening surface (the seven directives below). |
| `99-nnp.conf` | `NoNewPrivileges=yes` only. |
| `nnp_cups.cil` | Topic-owned SELinux module that grants four `process2 nnp_transition` rules covering the main domain plus three helper subdomains. |

The split is granular by intent. Removing `99-nnp.conf` alone does not by itself prevent transition denials at next boot if the CIL module remains loaded, but the CIL module is harmless on its own; the documented Stage-1 rollback removes both atomically. Stage 2 reverts the topic-owned hardening surface as well.

The deploy ordering invariant is that the CIL module must be loaded **before** `99-nnp.conf` is dropped in. The role's `tasks/main.yml` enforces the order with a `meta: flush_handlers` between the CIL install and the drop-in push. A deploy that pushes `99-nnp.conf` before the CIL module is loaded leaves a window where a service restart — manual, package-triggered, or system reboot — hits the kernel-level NNP-transition constraint.

### `99-hardening.conf`

Path: `/etc/systemd/system/cups.service.d/99-hardening.conf`.

```ini
[Service]
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
```

The drop-in carries the seven-directive hardening surface that the F44 stock vendor unit does not ship. cups is a print server with a broad runtime surface — LPD-helper spawn, USB-backend access, multiple filesystem roots, an upstream-controlled privilege model — so the topic-owned surface is conservative by design. Extending it would couple this topic's deploy to package-version-specific path moves and risk breaking print job execution under upstream privilege transitions. The directives group into two effect classes.

**Kernel-surface protections.** `ProtectClock=yes` denies `settimeofday(2)` and `adjtimex(2)`; cupsd does not adjust the system clock. `ProtectKernelLogs=yes` denies access to `/dev/kmsg` and the `syslog(2)` system call; cupsd does not consume the kernel ring buffer. `ProtectKernelModules=yes` denies `init_module(2)`, `finit_module(2)`, and `delete_module(2)`; cupsd does not load kernel modules. `ProtectControlGroups=yes` mounts the cgroup pseudo-filesystem read-only inside the unit's view; cupsd does not write into the cgroup tree.

**Namespace and syscall restrictions.** `SystemCallArchitectures=native` denies non-native syscall ABIs (the 32-bit personality on x86_64). `MemoryDenyWriteExecute=yes` denies `mmap(PROT_WRITE | PROT_EXEC)` and any `mprotect()` upgrade to `PROT_EXEC` on a writable mapping; cupsd does not JIT. `RestrictNamespaces=yes` denies `unshare(2)` and `setns(2)`; cupsd does not create namespaces.

`PrivateDevices=yes` is **not** part of the topic-owned hardening surface; cups uses USB-printer backends (`/usr/lib/cups/backend/usb`) that require unrestricted access to character devices under `/dev/bus/usb/`, and `PrivateDevices=yes` would reduce the unit's `/dev` view to a minimal device set that omits the USB bus.

The role does not configure `ProtectSystem=` because cups writes to multiple filesystem roots (`/var/spool/cups/`, `/var/log/cups/`, `/var/cache/cups/`, `/run/cups/`) and a single `ReadWritePaths=` whitelist would couple this topic's deploy to package-version-specific path moves; `ProtectHome=yes` is not configured because cups may resolve home-directory user data for print preferences (operator-policy in `/etc/cups/cups-files.conf`); `PrivateTmp=yes` is not configured because cupsd uses `/tmp` for spool overflow under operator-policy paths; `RestrictAddressFamilies=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `LockPersonality=`, `SystemCallFilter=`, `CapabilityBoundingSet=`, `UMask=`, `ProtectKernelTunables=`, `ProtectHostname=`, `ProtectProc=`, and `ProcSubset=` are not configured for the same out-of-scope reasoning: each would either break a known cups runtime path or carry a service-specific iteration burden that is operator-policy outside this topic. Extending the surface beyond the seven directives above is operator-policy and is not validated by the verify discipline this topic ships.

### `99-nnp.conf`

Path: `/etc/systemd/system/cups.service.d/99-nnp.conf`.

```ini
[Service]
NoNewPrivileges=yes
```

`NoNewPrivileges=yes` sets the `no_new_privs` bit on the daemon process and on every descendant of that process. cupsd spawns helper subdomains on the LPD, configuration, and PDF-print paths; the bit is inherited on every helper exec.

The directive is **not** safe to apply to this unit on its own. Stock targeted policy on Fedora 44 or later does not ship the `init_t → cupsd_t : process2 nnp_transition` allow rule. The pre-test that confirms the negative posture for the main domain is:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s init_t -t cupsd_t \
  -c process2 -p nnp_transition
```

Expected output on a stock host: empty. The empty return is the unambiguous signal that an NNP drop-in cannot be deployed safely without an SELinux extension. This topic ships the extension as a topic-owned CIL module described in the next subsection. The class mechanism — why the kernel's NNP-transition check denies an `execve(2)` under `no_new_privs` when no allow rule covers the source-target pair, and why stock policy's per-domain coverage is incomplete — is documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md).

The deploy ordering invariant is that the CIL module must be loaded before this drop-in is installed; the role enforces the ordering with `meta: flush_handlers` between the CIL install handler and the drop-in push.

### `nnp_cups.cil`

Path: `/usr/local/share/selinux/nnp_cups.cil`.

```cil
(allow init_t cupsd_t (process2 (nnp_transition)))
(allow cupsd_t cupsd_lpd_t (process2 (nnp_transition)))
(allow cupsd_t cupsd_config_t (process2 (nnp_transition)))
(allow cupsd_t cups_pdf_t (process2 (nnp_transition)))
```

The first rule is the standard `init_t → service_t` form that lifts the kernel NNP-transition denial for the daemon's main domain. The remaining three rules are the inter-domain form: under `NoNewPrivileges=yes`, the no-new-privs bit is inherited by every descendant of the daemon process; when cupsd spawns a helper that triggers a SELinux type-transition (the LPD-protocol helper into `cupsd_lpd_t`, the configuration helper into `cupsd_config_t`, or the PDF backend into `cups_pdf_t`), the kernel checks the `process2 nnp_transition` permission between the source domain (`cupsd_t`) and the helper target domain. Without each allow rule, the helper spawn is denied and the dependent print path stalls; the failure is not a boot failure — it surfaces only when the print path is exercised, hours or days after the apply. The class mechanism is documented in [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md).

The four rules are loaded as a single CIL module to keep this topic's deploy and rollback footprint atomic at the topic boundary: a Stage-1 rollback runs `semodule -X 400 -r nnp_cups` and removes only this topic's policy extension. Appending any of the rules to a shared multi-service CIL module would couple this topic's deploy and rollback to the deploy and rollback of every other service that shares the module; topic-tier discipline rules out that coupling.

The module is loaded at priority 400 via `semodule -X 400 -i /usr/local/share/selinux/nnp_cups.cil` from a `sysadm_r/sysadm_t` role-switch. Priority 400 places the extension above the stock targeted policy (which ships at priority 100) and below operator-side high-priority overrides. The mechanism the module rides on — the priority-400 publish path under `/usr/local/share/selinux/` and the `semodule -X 400 -i` install command — is provisioned by [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md). The base kernel-NNP-transition mechanism for the boot-time `init_t → cupsd_t` rule is the same class documented in [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md); the three helper rules are the inter-domain extension class documented in [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md).

The role's preflight stage runs three helper-subdomain pre-tests as non-fatal informational reports; the role deploys all four allow rules unconditionally, and the pre-test report tells the operator which of the helper rules are no-ops because stock policy already covers them:

```bash
sudo -r sysadm_r -t sysadm_t sesearch -A -s cupsd_t -t cupsd_lpd_t \
  -c process2 -p nnp_transition
sudo -r sysadm_r -t sysadm_t sesearch -A -s cupsd_t -t cupsd_config_t \
  -c process2 -p nnp_transition
sudo -r sysadm_r -t sysadm_t sesearch -A -s cupsd_t -t cups_pdf_t \
  -c process2 -p nnp_transition
```

### File modes

All three shipping artefacts are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets the mode and ownership explicitly per file rather than relying on the operator UMASK. The explicit `chmod 0644` is the standard reflex established in [UMASK 0027](../foundation/umask.md).

The drop-in directory `/etc/systemd/system/cups.service.d/` and the two drop-in files inside it carry the SELinux type `cupsd_unit_file_t` — a service-specialised `*_unit_file_t` type that stock targeted policy on Fedora 44 ships for cups. This is anomalous compared to the other Topics in this tree: `udisks2`, `smartd`, `NetworkManager`, `chronyd`, `dbus-broker`, and `avahi-daemon` all use the generic `systemd_unit_file_t`. The role's `restorecon` after `ansible.builtin.copy` is what triggers the relabel from the install-time default (typically `staff_u:object_r:systemd_unit_file_t` when the operator drops the file from a `staff_t` shell) to the canonical `cupsd_unit_file_t`. Without the relabel the merged unit still runs because systemd reads merged units regardless of label, but `ls -lZ` shows the wrong type and a future SELinux audit flags it.

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/cups.service.d/99-hardening.conf` | `0644` | `root:root` | `cupsd_unit_file_t` |
| `/etc/systemd/system/cups.service.d/99-nnp.conf` | `0644` | `root:root` | `cupsd_unit_file_t` |
| `/usr/local/share/selinux/nnp_cups.cil` | `0644` | `root:root` | `usr_t` |

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_cups/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`cups`), unit liveness, the merged unit body filtered for the two drop-in filenames and the directives this topic configures, the effective values of the managed properties via per-property `systemctl show -p <PROP> --value` calls (one call per property; never multi-property, because multi-property output ordering is not stable across systemd versions), the live SELinux domain of the running PID via `awk -F: '{print $3}' /proc/<MainPID>/attr/current`, the `matchpathcon` mapping for both `/usr/sbin/cupsd` and `/usr/bin/cupsd`, the listening sockets on TCP port `631`, the `lpstat -p -d` printer enumeration, the `lpinfo -v` backend enumeration, and the `semodule -l | grep nnp_cups` lookup that confirms the CIL module is loaded. The CIL module-presence lookup and the four positive-rule presence checks are gated behind a `sysadm_t` check and report `SKIP needs sysadm_t` from `staff_t`. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_cups/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `ProtectClock` | `yes` |
| `ProtectKernelLogs` | `yes` |
| `ProtectKernelModules` | `yes` |
| `ProtectControlGroups` | `yes` |
| `SystemCallArchitectures` | `native` |
| `MemoryDenyWriteExecute` | `yes` |
| `RestrictNamespaces` | `yes` |
| Live SELinux domain | `cupsd_t` |
| `semodule -l \| grep nnp_cups` | one line (sysadm_t-gated) |
| `sesearch init_t → cupsd_t` | one or more lines (sysadm_t-gated) |
| `sesearch cupsd_t → cupsd_lpd_t` | one or more lines (sysadm_t-gated) |
| `sesearch cupsd_t → cupsd_config_t` | one or more lines (sysadm_t-gated) |
| `sesearch cupsd_t → cups_pdf_t` | one or more lines (sysadm_t-gated) |

Every other systemd directive is left at its stock default; the verify script does not assert values for `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictAddressFamilies`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `ProtectKernelTunables`, `ProtectHostname`, `ProtectProc`, `ProcSubset`, `ReadWritePaths`, `SystemCallFilter`, `CapabilityBoundingSet`, or `UMask`. None of those directives are part of the topic-owned surface, and asserting them would mistake the absence of a topic-owned setting for drift.

In addition to the `semodule -l | grep -w nnp_cups` module-presence check, the verify script runs four explicit `sesearch -A` calls under `sudo -r sysadm_r -t sysadm_t` and asserts each of the four allow rules in `nnp_cups.cil` is present in the loaded policy. Each call is reported as one positive presence check (`OK` or `FAIL` per call). All four must pass for the verify exit code to remain `0`; any single rule missing is `FAIL` and bumps the exit code to `1`. From a `staff_t` shell every one of the four positive-rule checks reports `SKIP needs sysadm_t`; the module-presence check is also `SKIP needs sysadm_t` from `staff_t`.

Liveness is checked through `[ -d /proc/${main_pid} ]`; from a `staff_t` shell `kill -0` against a foreign-uid PID returns `EPERM` rather than `ESRCH`, so the `[ -d /proc/${main_pid} ]` form is ownership-independent. The class trap is documented in [The kill-0 cross-user EPERM trap](../../explanation/kill-0-cross-user-eperm.md).

The live SELinux domain is read via `awk -F: '{print $3}' < /proc/${main_pid}/attr/current` and compared against the expected value `cupsd_t`. The read works from `staff_t` for non-own PIDs in the absence of `hidepid=`. The `semodule -l | grep nnp_cups` check reports CIL module presence and is gated behind a `sysadm_t` check; from `staff_t`, the line reports `SKIP needs sysadm_t` rather than drift.

The role's modify stage is idempotent. The three shipping artefacts are pushed via `ansible.builtin.copy` from the role's `files/` directory and converge on byte-for-byte content match. The `semodule install`, `daemon-reload`, `restart`, and `restorecon` handlers each fire only on a change to their notifying task. The live-state probe is read-only. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee. A restart of `cups.service` interrupts in-flight print jobs and printer-discovery on the host; queued jobs survive the restart in the spool, but jobs in active transmission to a printer are aborted and must be re-submitted, and the role's `restart cups` handler is the documented apply path on a host where a brief interruption of active print transmission is acceptable, with the alternative being to apply the role and reboot.

The rollback posture is two-stage. **Stage 1**: remove `99-nnp.conf` and unload the CIL extension with `semodule -X 400 -r nnp_cups`, then `systemctl daemon-reload` and `systemctl restart cups.service`. The NNP layer alone is reverted; the topic-owned hardening surface remains. **Stage 2**: in addition to Stage 1, remove `99-hardening.conf`. The unit reverts entirely to the stock vendor configuration. The recovery how-to covers the boot-failure variant of the rollback. cups's hardening surface is conservative (seven directives plus the NNP layer), so a topic-owned-surface misconfiguration is unlikely to cause a boot failure; the most likely failure mode is a delayed helper-spawn failure when the print path is exercised after the apply.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(cupsd_t|cupsd_exec_t|cupsd_lpd_t|cupsd_config_t|cups_pdf_t|nnp_transition|cups)'
```

The verify script runs this filter and treats any hit as drift. The four-tool diagnosis loop that operators use when a hit appears is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Print smoketest

The post-deploy smoketest uses three drift-class checks; all three exit non-zero on failure (no warning class):

```bash
lpstat -p -d
ss -ltn 'sport = 631'
lpinfo -v
```

`lpstat -p -d` exits `0` and prints the configured printer queue and default printer; the queue may be empty on a host without configured printers, and an empty stdout is acceptable, but a non-zero exit code is drift. `ss -ltn 'sport = 631'` shows at least one of the two IPP listen sockets — `127.0.0.1:631` or `[::1]:631` — and the verify script asserts substring presence of either form; the absence of both is drift. `lpinfo -v` exits `0` with non-empty stdout listing at least one backend; an empty backend list signals a sandbox-broken backend-lookup path and is drift.

The pre-hardening printer baseline is the operator-side companion to the post-deploy smoketest. Before deploying the three-artefact profile, capture:

```bash
systemctl is-active cups.service
journalctl -b 0 -p err -u cups.service --no-pager | tail -20
lpstat -p -d || true
ss -ltn 'sport = 631' || true
lpinfo -v || true
```

On a stock host with cups active, `is-active` returns `active`, the error-stream tail is empty, `lpstat` lists the configured queue (may be empty), `ss` shows the IPP listen sockets, and `lpinfo` lists the available backends. The role's preflight stage runs the same recon and reports the outcome non-fatally; a non-empty error stream signals a pre-existing cups issue that the operator should investigate before deploying the role (post-deploy errors would otherwise be misattributed to the hardening surface).

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [NNP and SELinux transition trap](../../explanation/nnp-selinux-transition-trap.md) — Why stock targeted policy on Fedora 44 does not ship the `init_t → cupsd_t : process2 nnp_transition` allow rule, and why deploying `NoNewPrivileges=yes` without the topic-owned CIL module would deny the `execve(2)` of `/usr/sbin/cupsd` at next boot under `no_new_privs`.
- [NNP inter-domain transition](../../explanation/nnp-interdomain-transition.md) — Why the kernel `process2 nnp_transition` permission check applies to every helper-spawn type-transition that crosses a SELinux domain boundary (not just the boot-time `init_t → service_t` check), and why stock targeted policy may carry the rule for some daemon-helper pairs and not for others.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — Why the daemon binary at `/usr/sbin/cupsd` is matched through the global `/usr/sbin → /usr/bin` path equivalency before the file-context table is consulted, and why the role validates the mapping with a `matchpathcon` fail-fast against both `/usr/sbin/cupsd` and `/usr/bin/cupsd`.
