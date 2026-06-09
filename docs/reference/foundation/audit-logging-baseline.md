<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Audit and logging baseline

## Role in the hardening model

This Foundation layer documents the end-state of the host's audit and logging subsystems: the package map and unit semantics for the kernel audit pipeline (`auditd`) and the system journal (`systemd-journald`), the shape of the configuration files for both subsystems and the stock-Fedora defaults in those files, the `/etc/audit/rules.d/` concatenation flow that turns operator drop-in fragments into the live ruleset, the journald posture for persistent storage, the audit toolset and the SELinux role each tool requires, the read-discipline imposed by the labels on the audit-store and journal-store paths, the four-tool AVC diagnosis loop and where it hands off to the policy-loader contract, the rotation and retention surface on both subsystems, and the recovery properties that hold under partial misconfiguration.

This Foundation layer is a prerequisite for: every Topic role that pushes audit rules into `/etc/audit/rules.d/`, every Topic role that ships a custom SELinux module derived from an `audit2allow` draft, every Topic role that hardens `auditd.service` itself with a service-level drop-in, and every operator-facing How-to that documents AVC triage. It depends on Layer 0 (UMASK 0027) for the file-mode discipline that applies to operator-authored config under `/etc/audit/` and `/etc/systemd/journald.conf.d/`, and on Layer 1 (`staff_u` and sudo role transitions) for the `sysadm_t` escalation that every audit tool and every system-journal read requires on a `staff_u`-confined host.

## End-state configuration

The end-state spans four orthogonal concerns: the audit subsystem (the `auditd` daemon, its configuration file, the rules.d concatenation flow, the immutability lock, and the rule-shape categories), the journal subsystem (`systemd-journald`'s default posture and the persistent-storage trigger), the tooling and read-discipline that govern who may inspect what (the audit toolset, the role-switch requirement, the three log-label classes), and the AVC diagnosis loop with the recovery properties that follow.

### Audit subsystem configuration

The kernel audit pipeline ships from three packages on Fedora 44 or later: `audit` (the `auditd` daemon, the `audisp-*` dispatchers, and `libaudit`), `audit-libs` (the shared library), and `audit-rules` (sample rule fragments under `/usr/share/audit/sample-rules/`). The service unit is `auditd.service`.

Stock `auditd.service` carries `RefuseManualStart=yes` and `RefuseManualStop=yes`. A direct `systemctl restart auditd` invocation fails:

```text
Failed to restart auditd.service: Operation refused, unit auditd.service may
be requested by dependency only (it is configured to refuse manual start/stop).
```

The intent of the refuse-manual posture is gap-freeness across the audit log: the daemon is started by the early-boot dependency tree and is not subject to ad-hoc operator action. A live rule reload uses `auditctl -R /etc/audit/audit.rules` or `augenrules --load`, which re-applies the concatenated rule set without restarting the daemon. A full daemon restart requires a reboot.

The configuration file `/etc/audit/auditd.conf` ships at mode `0640 root:audit`. The Fedora-stock directives relevant to the baseline are:

```text
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = audit
freq = 50
num_logs = 5
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
name_format = NONE
```

Each directive serves one purpose. `log_file` names the active rotation target. `log_format=ENRICHED` adds CWD and PATH records to every event so a downstream tool does not need to correlate against a separate process tree. `log_group=audit` grants the `audit` POSIX group read on the rotated archive — this is the Fedora-default mechanism by which `ausearch` and `aureport`, running with `audit`-group membership in `sysadm_t`, reach the store. `num_logs=5` × `max_log_file=8` MB × `max_log_file_action=ROTATE` produces a sliding ~40 MiB window of recent audit events; `KEEP_LOGS` retains forever, `SUSPEND` halts the daemon when the cap is reached. `admin_space_left_action=SUSPEND`, `disk_full_action=SUSPEND`, and `disk_error_action=SUSPEND` together describe the conservative posture that prefers a halted audit pipeline to a continuing one with lost events. This Foundation does not push `auditd.conf`; an operator who deliberately raises `num_logs`, switches to `KEEP_LOGS`, or relaxes any on-error action accepts the trade-off and writes the change explicitly.

The file `/etc/audit/auditd.conf` is unreadable from `staff_t`. A plain `sudo cat /etc/audit/auditd.conf` from a `staff_u`-confined account fails with `Permission denied` because `staff_sudo_t` has no read on the file's `auditd_etc_t` label. The role-switch form `sudo -r sysadm_r -t sysadm_t cat /etc/audit/auditd.conf` succeeds.

Audit rules live under `/etc/audit/rules.d/` as one or more files of the form `<NN>-<name>.rules`. Stock-Fedora ships no operator rules, only the daemon's bookkeeping fragment. The `augenrules` tool walks `/etc/audit/rules.d/` in C-locale lexical order, concatenates the contents into `/etc/audit/audit.rules`, and (when invoked at `auditd.service` start) loads the concatenation into the kernel. Convention across this tree: numeric prefixes (`10-`, `20-`, …) order fragments deterministically across roles. The first effective rule in the concatenation is `-D` (clear the live ruleset), so re-application is idempotent regardless of prior state. Files in `rules.d/` are mode `0640 root:root`. The manual reload form is `augenrules --load`.

The control flag `-e` carries three states. `-e 0` is the default unlocked state. `-e 1` locks the audit configuration until the next reboot: rules cannot be added or removed, but the daemon continues to operate. `-e 2` locks immutably — the kernel forbids any rule change for the lifetime of the running kernel; recovery from a misconfigured rule under `-e 2` requires a reboot. This Foundation describes the option but does not push it. An operator who chooses `-e 1` or `-e 2` accepts the recovery trade-off explicitly.

Audit rule contents fall into four categories. Each role that ships rules describes its own contents in its own Reference; this Foundation describes the categories and the augenrules concatenation. The shape of a rules.d fragment with one entry from each category:

```text
## clear prior state
-D

## buffers
-b 8192
-f 1
-r 60

## file watches
-w <path> -p wa -k <key>

## syscalls
-a always,exit -F arch=b64 -S <syscall> -F <filter> -k <key>

## exclude noise
-a never,user -F msgtype=<type>
```

Categories:

- **File watches** (`-w <path> -p <r|w|x|a> -k <key>`) attach to one path and trigger an event on the listed access modes. They are inexpensive at the kernel side and are the most common rule shape across hardening rule sets.
- **Syscall rules** (`-a always,exit -F arch=b64 -S <syscall> -F <filter> -k <key>`) match a syscall on a specific architecture, optionally filtered by uid/gid/exit/etc. They are more expensive than file watches because every covered syscall is intercepted; matched events carry a key for later triage.
- **Control rules** govern kernel-side state: `-D` clears, `-b <bufsize>` sets the kernel backlog (events queued before the dispatcher consumes them), `-f <0|1|2>` sets the failure mode (silent, printk, panic), and `-r <rate>` rate-limits events per second.
- **Exclude rules** (`-a never,user -F msgtype=<type>`) drop classes of events at the audit ingress, before they reach the log. They are a noise-suppression surface used sparingly because over-application erodes the audit value.

Specific paths, syscalls, and keys belong to per-Topic Reference articles. The `audit-rules` package ships sample fragments under `/usr/share/audit/sample-rules/`; copying a sample into `/etc/audit/rules.d/` is a one-line operator action and is out of scope here.

### Journal subsystem configuration

`systemd-journald` is shipped by the `systemd` package; there is no separate journal package. The unit is `systemd-journald.service`. The configuration file `/etc/systemd/journald.conf` is the package default and ships with every directive commented out. The compiled-in defaults that take effect when no override is present are:

```ini
[Journal]
Storage=auto
Compress=yes
Seal=yes
ForwardToSyslog=no
SystemMaxUse=
SystemKeepFree=
RuntimeMaxUse=
MaxRetentionSec=0
RateLimitIntervalSec=30s
RateLimitBurst=10000
```

`Storage=auto` flips between volatile (events written to `/run/log/journal/`, lost on reboot) and persistent (events written to `/var/log/journal/<machine-id>/`) based on whether the persistent directory exists. `Compress=yes` zstd-compresses files above the compression threshold. `Seal=yes` enables Forward-Secure-Sealing of the on-disk journal — the daemon periodically writes a verification tag that detects after-the-fact tampering. `ForwardToSyslog=no` prevents duplicate writes to the legacy syslog pipeline. The empty `SystemMaxUse`/`SystemKeepFree`/`RuntimeMaxUse` directives carry compiled-in defaults: 10% of the `/var/log` filesystem (capped at 4 GiB) for `SystemMaxUse`, 15% of the `/var/log` filesystem (capped at 4 GiB) for `SystemKeepFree`, 10% of the `/run/log` filesystem (capped at 4 GiB) for `RuntimeMaxUse`. `MaxRetentionSec=0` disables time-based retention. The size caps are soft: they apply opportunistically on rotation, so a single very large event can momentarily exceed the cap until the next rotation cycle.

Operator overrides live in `/etc/systemd/journald.conf.d/<name>.conf` at mode `0644 root:root`. Stock-Fedora ships no drop-ins under `journald.conf.d/`. This Foundation pushes none. An operator who wants to raise `SystemMaxUse`, shorten `MaxRetentionSec`, or disable `Seal` writes a drop-in deliberately and accepts the change.

Persistent journal storage is keyed on the directory `/var/log/journal/<machine-id>/`. When the directory exists, `Storage=auto` writes there; when it does not, the daemon stays volatile. The directory may be created by `systemd-tmpfiles --create` at boot, by `mkdir -p /var/log/journal && systemctl restart systemd-journald`, or implicitly by setting `Storage=persistent` in a drop-in (which causes the daemon to create the directory on the next start). End-state on a Fedora 44 host:

```text
drwxr-sr-x+ 3 root systemd-journal system_u:object_r:var_log_t:s0 60 ... /var/log/journal
```

Mode `2755` (the setgid bit propagates `systemd-journal` group ownership to per-machine-id subdirectories), owner `root`, group `systemd-journal`. The directory itself carries label `var_log_t`; the active journal files inside it carry `systemd_journal_t`. The directory entry's mode and label can be inspected from `staff_t`; the journal file contents cannot.

### Tooling and read discipline

`auditd` forwards every kernel-audit event to two downstream sinks. The first is `kmsg`, which surfaces audit events in `dmesg` for early-boot triage. The second is `systemd-journald`, via the audit transport — the daemon adds an `_TRANSPORT=audit` field to each forwarded record, and the `_AUDIT_TYPE_NAME` field carries the audit message type (for example `AVC`, `SYSCALL`, `USER_LOGIN`). The journal-side filters that consume this transport are uniform:

```bash
sudo -r sysadm_r -t sysadm_t journalctl _TRANSPORT=audit
sudo -r sysadm_r -t sysadm_t journalctl _AUDIT_TYPE_NAME=AVC
sudo -r sysadm_r -t sysadm_t journalctl _AUDIT_TYPE_NAME=AVC --since "-1h"
```

System-journal reads from `staff_t` are blocked at the `systemd_journal_t:dir search` level. `journalctl` invoked from a `staff_u`-confined shell either returns no events or returns a degraded subset (the operator's own user-instance journal, not the system journal); the system journal requires the role switch documented in [staff_u and sudo role transitions](./sudo-roles.md). Every system-journal command in this Reference is therefore quoted in its `sudo -r sysadm_r -t sysadm_t` form.

The audit toolset comprises `auditctl`, `ausearch`, `aureport`, `audit2why`, `audit2allow`, `autrace`, and `augenrules`. Each tool either reads the audit store at `/var/log/audit/` (label `auditd_log_t`) or transitions through an audit-domain process type (`auditctl_t`, `audit_t`) that the kernel grants only to the audit-domain caller. Plain sudo from a `staff_u`-confined account lands in `staff_sudo_t`, which has neither read on `auditd_log_t` nor `process2 nnp_transition` into `auditctl_t`. The role-switch form is uniform across the toolset:

```bash
sudo -r sysadm_r -t sysadm_t auditctl -s
sudo -r sysadm_r -t sysadm_t auditctl -l
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot
sudo -r sysadm_r -t sysadm_t aureport --summary
sudo -r sysadm_r -t sysadm_t audit2why -a
sudo -r sysadm_r -t sysadm_t audit2allow -a
sudo -r sysadm_r -t sysadm_t augenrules --check
sudo -r sysadm_r -t sysadm_t augenrules --load
```

Three label classes govern read access to log paths:

- **Audit store** — `/var/log/audit/audit.log*`. Label `auditd_log_t`, owner `root:audit`, mode `0600`. The `audit` POSIX group is the read surface, but stock policy denies `staff_sudo_t` the read. Practical access is via `ausearch` or `aureport` from `sysadm_t`. `cat`, `tail`, and `less` against the file fail at any sudo level on a `staff_u`-confined host.
- **System journal** — `/var/log/journal/<machine-id>/*.journal`. Label `systemd_journal_t`, owner `root:systemd-journal`, mode `0640` (the `systemd-journal` group is the read surface). Practical access is via `journalctl` from `sysadm_t`. From `staff_t`, the read is blocked at the `systemd_journal_t:dir search` denial; the operator role-switches.
- **User-instance journal** — `~/.local/share/systemd/journal/<uid>/*.journal`. Owned by the operator. Readable from `staff_t` via `journalctl --user`. This path holds only the operator's own user-session events (systemd `--user` units, GNOME session messages); the system journal is a separate store and requires the role switch.

When an operator routes per-command sudo I/O logging to a custom path via `Defaults!<absolute-path> logfile=/var/log/<wrapper>.log` in a drop-in under `/etc/sudoers.d/`, the path needs SELinux type `sudo_log_t`, or stock policy silently drops the audit data; the rule is described in [Sudo custom logfile and SELinux labeling](../../explanation/sudo-logfile-seclabel.md). Audit-tooling sessions that operators wrap in this manner inherit the same labeling rule; this Foundation cross-links the pattern rather than restating it.

### AVC diagnosis workflow and recovery

A four-tool sequence drives AVC triage. All four steps run from `sysadm_t`:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts <ts> | \
  sudo -r sysadm_r -t sysadm_t audit2allow -p /etc/selinux/targeted/policy/policy.kern
sudo -r sysadm_r -t sysadm_t audit2why -a
```

`ausearch -m AVC -ts <ts>` filters AVC denial records over the time window — `boot` for "since boot", `today`, `recent` (last ten minutes), or an explicit `YYYY-MM-DD HH:MM:SS`. `audit2why -p <policy>` reads the kernel policy and explains why each denial happened: a missing TE rule, a `dontaudit` rule that hides the denial under stock policy, a type-mismatch caused by a misordered file context, a constraint mismatch on MLS levels. `audit2allow -a` drafts the TE/CIL rule that would grant the denial; the draft is a starting point, not a deployable artifact, and an operator inspects it before deploying.

Translating an `audit2allow` draft into a deployable custom CIL module is the loader contract documented in [SELinux custom CIL bootstrap](./selinux-cil-bootstrap.md). The handoff is clean: the audit pipeline produces the denial record, the diagnosis tool produces the candidate rule, the loader contract handles install, list, remove, and recovery. This Reference describes only the audit-side surface up to the candidate rule; the loader contract is one Foundation layer over.

One specific class of AVCs warrants forward-mention here without inline coverage: denials that arise when `systemd` enforces `NoNewPrivileges=yes` on a service whose target SELinux domain has no stock-policy `process2 nnp_transition` allow. The interaction motivates a class of priority-400 modules that grant the missing transition; the trap, the symptom shape, and the diagnosis recipe are described separately as a Pattern Explanation (slug: `nnp-selinux-transition-trap`). This Reference mentions the class only for completeness; the AVC diagnosis loop above is the entry point regardless of which class of denial the operator is chasing.

Rotation and retention separate cleanly across the two subsystems. On the audit side, the controlling triple is `max_log_file` (MB cap per file) × `num_logs` (count of rotated files retained) × `max_log_file_action` (`ROTATE` keeps a sliding window, `KEEP_LOGS` retains forever, `SUSPEND` halts auditing on cap). Stock-default 8 MB × 5 × `ROTATE` produces a ~40 MiB sliding window. On the journal side, rotation is normally driven by `SystemMaxUse` and is implicit; the operator-invoked one-shots are:

```bash
sudo -r sysadm_r -t sysadm_t journalctl --rotate
sudo -r sysadm_r -t sysadm_t journalctl --vacuum-time=<spec>
sudo -r sysadm_r -t sysadm_t journalctl --vacuum-size=<spec>
```

`--rotate` forces an immediate rotation of the active file. `--vacuum-time=<spec>` drops files older than `<spec>`. `--vacuum-size=<spec>` drops files until the total size is under the cap. The vacuum forms are operator-invoked; the daemon does not consult them on its own rotation cycle.

Four recovery properties hold for the baseline:

- **Auditd misconfig fail-fast.** A syntactically broken `auditd.conf` causes `auditd` to refuse start at next boot. The fix is to repair the file under `sysadm_t`. Because `auditd.service` carries `RefuseManualStart=yes`, the repair takes effect at the next reboot; there is no live-reload path for `auditd.conf`. The live-reload path is restricted to `audit.rules` via `auditctl -R` and `augenrules --load`.
- **Augenrules syntax check.** `augenrules --check` reports rule-syntax errors against the concatenated `/etc/audit/audit.rules` before the operator runs `augenrules --load`. The two-step form (check, then load) is the canonical sequence; a misconfigured rule rejected by `--check` never reaches the kernel.
- **Journald volatile fallback.** When `/var/log/journal/` becomes unwritable (filesystem full, label corruption, permission drift), `systemd-journald` falls back to volatile mode (`/run/log/journal/`) without a daemon failure. The fallback is reported in the journal's own bootup log and is recoverable by repairing the persistent path and restarting the daemon — `systemd-journald.service` does not carry `RefuseManualStart`.
- **Idempotence.** `augenrules --load` re-applies the concatenated rules.d set; the leading `-D` clears the prior live state, so the operation is idempotent across re-runs. The Ansible role of this Foundation does not push rules.d files (per-Topic territory) and does not push `auditd.conf` (the Foundation verifies the Fedora stock); no audit-side mutation is issued by the role itself. On the journal side, `systemctl restart systemd-journald` is supported, and the role pushes no `journald.conf.d` content, so no handler is needed. The role's modify stage is therefore confined to package presence and persistent-journal-directory presence.

## Verification

Probe:

```bash
bash ansible/roles/foundation_audit_logging_baseline/files/probe.sh
```

Verify:

```bash
bash ansible/roles/foundation_audit_logging_baseline/files/verify.sh
```

The verify script exits `0` on a clean host, `1` on drift, `2` on invocation error. It reports four classes of check: required-package presence (`audit`, `audit-libs`, `audit-rules`, `policycoreutils-python-utils`), unit liveness (`auditd.service` and `systemd-journald.service` both `active`), persistent-journal directory state (`/var/log/journal` at mode `2755`, group `systemd-journal`, label `*:var_log_t:*`), and the journald-effective `Storage=` value reported by `systemctl show systemd-journald`. Checks that need `sysadm_t` (`auditctl -s`, `journalctl --disk-usage`) are reported as `SKIP` rather than as drift when the script is run from `staff_t`.

Expected verify output on a correctly applied host, run from `staff_t` from a fresh login shell:

```text
OK   pkg_audit                      installed
OK   pkg_audit_libs                 installed
OK   pkg_audit_rules                installed
OK   pkg_policycoreutils_python     installed
OK   unit_auditd                    active
OK   unit_systemd_journald          active
OK   journal_dir_present            /var/log/journal mode=02755 owner=root:systemd-journal
OK   journal_dir_label              system_u:object_r:var_log_t:s0
OK   journald_storage_effective     persistent
SKIP auditctl_state                 needs sysadm_t
SKIP journalctl_disk_usage          needs sysadm_t
```

On the same host re-run as `sudo -r sysadm_r -t sysadm_t bash files/verify.sh`, the two `SKIP` lines become:

```text
OK   auditctl_state                 enabled=1 pid=<pid>
OK   journalctl_disk_usage          <bytes> on disk
```

A `Storage=` value of `auto` is also reported `OK` when the persistent-journal directory exists, because `auto` flips to persistent on directory presence; only an `effective` value that contradicts the observed directory state is reported as drift.

## Related patterns

- [Sudo custom logfile and SELinux labeling](../../explanation/sudo-logfile-seclabel.md) — Why an audit-tooling session that routes per-command I/O logging through a custom `Defaults!<cmd> logfile=` path needs `sudo_log_t` on the path, and the symmetric rule for `iolog_dir=`.
