<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# aide

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state operator-deployed integrity-monitor profile for the AIDE file-integrity check on a Fedora 44 or later host. The end-state ships three core artefacts plus one optional artefact plus one managed configuration block: two operator-supplied unit files under `/etc/systemd/system/` (`aide-check.service`, `aide-check.timer`), one topic-owned one-rule SELinux CIL module under `/usr/local/share/selinux/` (`aide_extras.cil`), an opt-in acknowledgement-aware interactive-shell push-banner under `/etc/profile.d/` (`aide-alert.sh`), and one marker-delimited scope-tuning block appended to the stock `/etc/aide.conf`. The managed scope-tuning block is **in scope** for this topic: the role adds it to the stock configuration to remove structurally volatile paths from the daily delta so that a future non-zero exit again means a real integrity change. The end-state also includes the database refresh discipline (`aide --init` plus the post-refresh `restorecon` on the database, with a forensic pre-rebaseline note), the daily-check exit-code semantics (the AIDE bitmask `new(1) + removed(2) + changed(4) = 7` is by-design and not a unit failure), the verify discipline, and the rollback posture. This topic does **not** cover the stock `/etc/aide.conf` body outside the managed block, the `aide-update` companion subcommand, the cron-driven path via `/etc/cron.daily/aide`, the full AIDE selector grammar beyond the attributes the managed block uses, the operator-side mailer integration that pipes the daily-check diff into a mail recipient, the `systemd-analyze security` numeric score model, or any extended hardening direction beyond the one-allow CIL surface.

## End-state configuration

The end-state ships **three** core artefacts, **one** optional artefact, and **one** managed configuration block. The core artefacts are mutually orthogonal — the unit files alone produce a working timer-driven check (with AVC noise); the CIL module alone closes the policy gaps but does not schedule anything; the banner alone visualises a non-zero exit bitmask but does not run anything. The managed scope-tuning block shapes what the check considers a delta but does not change the schedule, the policy, or the display. The artefacts deploy together and roll back in stages.

### Service identity

AIDE is the file-integrity monitor whose daily-check audit stream feeds the diagnosis loop documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md); the AVC-posture check below is that diagnosis loop applied against AIDE's own audit stream.

The `aide` package on Fedora 44 or later ships the binary at `/usr/sbin/aide`, the configuration at `/etc/aide.conf` (mode `0600 root:root`, label `etc_t`), the database directory `/var/lib/aide/` (label `aide_db_t`), and the log directory `/var/log/aide/` (label `aide_log_t`). The package declares the SELinux types `aide_t` (runtime domain), `aide_exec_t` (binary entrypoint), `aide_db_t` (database), and `aide_log_t` (log); the `aide_conf_t` configuration type also exists in policy, but stock file-contexts on Fedora 44 label the default `/etc/aide.conf` as `etc_t`. Stock targeted policy declares the type-transition `init_t → aide_t` on `aide_exec_t`, so the timer-triggered service spawns the binary in the canonical `aide_t` domain.

The package does **not** ship `aide-check.service` or `aide-check.timer`; both unit files are operator-supplied and are part of this topic's deploy profile. The package does ship `/etc/cron.daily/aide` as an alternative cron-driven scheduler; this topic uses the systemd-timer path and does not configure the cron-driven path.

| Property | Value |
|---|---|
| Service unit | `aide-check.service` (operator-supplied; oneshot) |
| Timer unit | `aide-check.timer` (operator-supplied; daily) |
| Initial UID / GID | `0` / `0` (no `User=` / `Group=` in the service unit) |
| SELinux runtime domain | `aide_t` (kernel type-transition `init_t → aide_t` on `aide_exec_t`) |

The `aide` package installs the binary at `/usr/sbin/aide`. The Fedora 44 `/usr/sbin → /usr/bin` global path equivalency rewrites the lookup target so `matchpathcon /usr/sbin/aide` resolves via the canonical `/usr/bin/aide` entry. The role's preflight runs both `matchpathcon` calls and requires `aide_exec_t` from at least one of the two as fail-fast. Why the equivalency rewrites the lookup target before the file-context table is consulted, and why the canonical-side label is the one the kernel's type-transition relies on, is documented in [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md).

### Deploy profile

| File | Layer |
|---|---|
| `/etc/systemd/system/aide-check.service` | Operator-supplied oneshot service unit invoking `/usr/sbin/aide --check`. |
| `/etc/systemd/system/aide-check.timer` | Operator-supplied daily timer with 30-minute jitter and `Persistent=yes`. |
| `/usr/local/share/selinux/aide_extras.cil` | Topic-owned one-allow-rule CIL module loaded at priority 400. |
| `/etc/aide.conf` (managed block appended) | Stock configuration plus one marker-delimited scope-tuning block. |
| `/etc/profile.d/aide-alert.sh` (optional) | Acknowledgement-aware interactive-shell push-banner decoding the most recent daily-check exit bitmask. |

### `aide-check.service`

Path: `/etc/systemd/system/aide-check.service`.

```ini
[Unit]
Description=AIDE file-integrity check (oneshot)
Documentation=man:aide(1) man:aide.conf(5)
ConditionPathExists=/var/lib/aide/aide.db.gz

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --check
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
```

Directive notes:

- `Type=oneshot` — systemd considers the unit `active (exited)` only after `aide --check` has terminated. The service has no `MainPID` between runs.
- `ExecStart=/usr/sbin/aide --check` — invokes the binary at its canonical post-merge path. The unit ships **no** `User=` / `Group=` directive because the daemon must read the database under `aide_db_t` (mode `0600 root:root`); `aide-check` runs as `root:root`, and the SELinux type-transition `init_t → aide_t` confines the runtime context.
- `Nice=19` and `IOSchedulingClass=idle` — push the daily check to lowest-priority CPU and idle-class block I/O so a coincident interactive workload is not noticeably slowed.
- `ConditionPathExists=/var/lib/aide/aide.db.gz` — the unit refuses to start if the database does not exist; this gates the operator's first `aide --init` baseline as a prerequisite.
- `StandardOutput=journal` and `StandardError=journal` — the diff stream lands in the systemd journal. The unit's exit code is the AIDE bitmask; a value of `1` + `2` + `4` = `7` is by-design, not drift, and is the load-bearing input for the optional `/etc/profile.d/aide-alert.sh` banner.

The unit ships **no** systemd hardening directives: no `NoNewPrivileges=`, no `Protect*`, no `Private*`, no `SystemCallFilter=`, no `RestrictAddressFamilies=`, no `CapabilityBoundingSet=`. AIDE walks every protected path the configuration lists (canonically `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/usr`, `/etc`); the data path is fundamentally a full-system read walk plus database hashing. A namespace-restricting profile would hide subtrees from AIDE's view and silently shrink the integrity-monitoring surface — the opposite of this topic's purpose. The omission of the sandbox directive set is a positive design decision tied to AIDE's data-path shape, not a target for a future incremental tightening pass.

### `aide-check.timer`

Path: `/etc/systemd/system/aide-check.timer`.

```ini
[Unit]
Description=Daily timer for AIDE file-integrity check
Documentation=man:systemd.timer(5)

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=yes
Unit=aide-check.service

[Install]
WantedBy=timers.target
```

Directive notes:

- `OnCalendar=daily` — once per calendar day, anchored to local midnight before randomisation.
- `RandomizedDelaySec=30m` — adds up to 30 minutes of jitter so a fleet of hosts does not all run at exactly 00:00.
- `Persistent=yes` — if the host was off at the scheduled time, the timer fires on next boot. Load-bearing for desktops and laptops that are not powered around the clock.
- `Unit=aide-check.service` — explicit binding (the default would also work because of the filename match, but the explicit binding documents the relationship).
- `WantedBy=timers.target` — enables the timer at boot via `systemctl enable aide-check.timer`.

The role's `tasks/main.yml` runs `systemctl enable --now aide-check.timer` at deploy time so the timer is both enabled and active in a single step.

### `aide_extras.cil`

Path: `/usr/local/share/selinux/aide_extras.cil`. Loaded at priority 400 via `semodule -X 400 -i aide_extras.cil`.

```cil
(allow aide_t dosfs_t (filesystem (getattr)))
```

The module ships one allow rule that closes a Reference-Policy gap an `aide --check` run reveals on a stock Fedora 44 host:

- **Rule 1** (`aide_t × dosfs_t : filesystem getattr`) covers the `fstatfs(2)` syscall AIDE issues on every walked path's containing filesystem to record the filesystem-type fingerprint. vfat-mounted paths — the EFI System Partition under `/boot/efi/` and any plug-in USB drives — are typed `dosfs_t`, and stock targeted policy on Fedora 44 lacks the `aide_t × dosfs_t : filesystem getattr` allow.

The module is topic-owned rather than appended to a shared module. Topic-tier discipline isolates the role's deploy and rollback footprint: the rollback step `semodule -X 400 -r aide_extras` removes only this topic's extension; no other topic's CIL module is touched. Priority 400 places the extension above stock targeted policy (which ships at priority 100) but below any operator-side high-priority overrides.

### `/etc/aide.conf` scope tuning

The role appends one marker-delimited block to the stock `/etc/aide.conf` via `ansible.builtin.blockinfile`. A stock Fedora 44 host reaches the end-state by adding this block; the role does **not** ship a whole `aide.conf`. The stock body outside the block, and the file's `0600 root:root` mode and `etc_t` label, are preserved.

```text
# BEGIN topic_aide scope tuning (managed)
# AIDE 0.19+ deepest-match: these specific lines override broader stock rules.

# Custom rule-group (inode- and ctime-tolerant).
# vfat carries no SELinux labels and no stable inodes, so VarVfat omits
# selinux/xattrs/acl and the i/n inode attributes.
VarVfat        = p+u+g+s+m+sha256+sha512

# 1. systemd runtime resource-control tree (machine-managed): out of scope.
!/etc/systemd/system\.control

# 2. EFI System Partition (vfat): keep content, tolerate synthesized-inode churn.
/boot/efi(/.*)?$  =vfat  VarVfat

# 3. CUPS notification state (volatile).
!/etc/cups/subscriptions\.conf(\.O)?$

# 4. Volatile caches (non-config).
!/root/\.cache
!/usr/lib/sysimage/libdnf5/.*\.sqlite(-shm|-wal)?$
# END topic_aide scope tuning (managed)
```

The block defines one reduced rule-group and four scope decisions.

`VarVfat = p+u+g+s+m+sha256+sha512` is the rule-group for content stored on a FAT filesystem. It omits `selinux`, `xattrs`, and `acl` because FAT carries no SELinux labels or extended attributes, and omits the `i` (inode) and `n` (link count) attributes because vfat inodes are synthesized rather than stable. The remaining attributes — permissions, owner, group, size, mtime, and the two SHA digests — still detect a genuine content change.

The four scope decisions rely on the AIDE 0.19+ deepest-match algorithm: AIDE selects the tree node by the most specific matching line, so a more specific line in the appended block overrides a broader stock rule without editing any stock line.

- `!/etc/systemd/system\.control` fully excludes the machine-managed runtime resource-control tree. systemd rewrites these drop-ins (the per-slice and per-service CPU/IO/memory weight files) on every reload and login, shuffling inodes without a meaningful content change. The tree is machine state, not administrator configuration, so it is removed from scope entirely.
- `/boot/efi(/.*)?$  =vfat  VarVfat` is a filesystem-type Restricted Rule. The `=vfat` qualifier restricts the rule to entries whose containing filesystem type is `vfat`, which is why the reduced `VarVfat` group (no label or extended-attribute attributes) is the correct group there. The rule keeps the EFI System Partition's content under watch while tolerating the synthesized-inode churn that vfat produces on mount and `fsck`.
- `!/etc/cups/subscriptions\.conf(\.O)?$` excludes the CUPS notification-state file (and its `.O` rotation sibling), which CUPS rewrites continuously as subscriptions change.
- `!/root/\.cache` and `!/usr/lib/sysimage/libdnf5/.*\.sqlite(-shm|-wal)?$` exclude volatile non-configuration caches: the root account's cache tree and the package-manager SQLite databases with their write-ahead-log and shared-memory siblings.

Each excluded or restricted path is structurally volatile — machine-rewritten inodes, vfat synthesized inodes, or volatile caches — so its daily delta was scope overreach, not an integrity event. The goal of the tuning is that a future non-zero `aide --check` exit again carries signal: it means a real change rather than recurring noise from a stable set of structurally volatile paths.

The block edit preserves `/etc/aide.conf` at mode `0600 root:root`. Keeping — rather than widening — the mode on an in-place configuration edit is the explicit-mode reflex described in [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md): the role's `blockinfile` task sets `mode: "0600"`, `owner: root`, `group: root` explicitly so the edit cannot widen the configuration to `0644`.

### `aide-alert.sh` (acknowledgement-aware push-banner)

Path: `/etc/profile.d/aide-alert.sh`. Opt-in via the role default `topic_aide_install_alert_banner: true`. Setting the default to `false` skips the file write (and removes an already-installed banner).

```bash
# Skip non-interactive shells (cron, scp, sftp).
case $- in *i*) ;; *) return 0 ;; esac

# Last invocation exit status. Empty (never ran) or 0 (clean) -> silent.
_aide_rc=$(systemctl show -p ExecMainStatus --value aide-check.service 2>/dev/null)
case "$_aide_rc" in 0|"") unset _aide_rc; return 0 ;; esac

_aide_ts=$(systemctl show -p ExecMainExitTimestamp --value aide-check.service 2>/dev/null)

# Run identity + acknowledgement: silent when this run was already acknowledged.
_aide_mono=$(systemctl show -p ExecMainExitTimestampMonotonic --value aide-check.service 2>/dev/null)
_aide_ack="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/aide-alert.ack"
if [ -n "$_aide_mono" ] && [ -f "$_aide_ack" ] && \
   [ "$(cat "$_aide_ack" 2>/dev/null)" = "$_aide_mono" ]; then
    unset _aide_rc _aide_ts _aide_mono _aide_ack ; return 0
fi

# Decode the AIDE bitmask (1=new, 2=removed, 4=changed); >= 8 is a tool error.
_aide_parts=""
case "$_aide_rc" in
    [1-7])
        [ $((_aide_rc & 1)) -ne 0 ] && _aide_parts="${_aide_parts}new "
        [ $((_aide_rc & 2)) -ne 0 ] && _aide_parts="${_aide_parts}removed "
        [ $((_aide_rc & 4)) -ne 0 ] && _aide_parts="${_aide_parts}changed "
        ;;
    *)
        _aide_parts="(non-bitmask exit=$_aide_rc - I/O or database error, check the journal)"
        ;;
esac

printf '\n  \033[1;33m! AIDE delta:\033[0m %s\n' "${_aide_parts% }"
printf '    Last run: %s\n' "${_aide_ts:-?}"
printf '    Review:   journalctl -u aide-check.service -b 0 --no-pager\n'
printf '    Refresh:  sudo -r sysadm_r -t sysadm_t aide --init   (then move the new database into place and restorecon -Fv)\n'
printf '    Ack:      echo %s > %s\n\n' "$_aide_mono" "$_aide_ack"

unset _aide_rc _aide_ts _aide_parts _aide_mono _aide_ack
```

The banner is sourced once per interactive shell. It returns immediately on a non-interactive shell, on an empty `ExecMainStatus` (no run since boot), and on a clean `0` exit. For a non-zero bitmask in the `1`–`7` range it decodes the three bit fields (`new(1)`, `removed(2)`, `changed(4)`) into a human-readable list; for a `≥ 8` exit it emits a non-bitmask error form so the operator distinguishes drift from a tool-internal error.

The acknowledgement gate is the distinguishing behaviour of the end-state. The current run is identified by its `ExecMainExitTimestampMonotonic` value. A per-user stamp file at `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/aide-alert.ack` holds the acknowledged monotonic value. The banner is silent when the stamp equals the current run's monotonic value, and re-arms automatically when a new check run produces a new monotonic value. The `Ack:` line prints the exact `echo <monotonic-value> > <ackfile>` command the operator runs to acknowledge the current run; the acknowledgement is pure ergonomics and has no integrity-scope effect. Because the stamp lives under `$XDG_RUNTIME_DIR`, it resets at reboot, which re-arms the banner after every boot.

The role's modify stage installs the file with mode `0644 root:root`, label `bin_t` (the `matchpathcon` default for `/etc/profile.d/`).

### File modes

The three core artefacts and the optional banner are written with mode `0644`, owner `root`, group `root`. The role's modify stage sets mode and ownership explicitly per file rather than relying on the operator UMASK; the explicit `chmod 0644` is the standard reflex described in [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md). For `/etc/aide.conf`, the same reflex applies in the opposite direction: the `blockinfile` task sets `mode: "0600"` explicitly so an in-place edit preserves — rather than widens — the stock `0600 root:root` triplet. The role's preflight stage runs `matchpathcon` against each install path and asserts the result resolves to the expected type as a fail-fast gate before the install task runs. A `restorecon` handler is wired as a defence-in-depth reflex for the shipped artefacts; it fires on file change but is a no-op on a correctly installed file.

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/etc/systemd/system/aide-check.service` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/aide-check.timer` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/usr/local/share/selinux/aide_extras.cil` | `0644` | `root:root` | `usr_t` |
| `/etc/aide.conf` (managed block appended) | `0600` | `root:root` | `etc_t` |
| `/etc/profile.d/aide-alert.sh` (optional) | `0644` | `root:root` | `bin_t` |

### Database refresh

AIDE's database at `/var/lib/aide/aide.db.gz` (label `aide_db_t`, mode `0600 root:root`) is the integrity-monitor's authoritative state. After any operator-driven change to a path the configuration covers — a system update, a `/etc/**` configuration edit, a SELinux relabel sweep, or a change to the managed scope-tuning block — the operator regenerates the database with the canonical sequence:

```bash
sudo -r sysadm_r -t sysadm_t aide --init
sudo -r sysadm_r -t sysadm_t mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo -r sysadm_r -t sysadm_t restorecon -Fv /var/lib/aide/aide.db.gz
```

`aide --init` writes the new database to `aide.db.new.gz` rather than overwriting the live database, so a failed init does not leave the integrity-monitor blind. The `mv` step promotes the new database to the canonical filename only after init has succeeded. The `restorecon -Fv` step fixes the SELinux user component on the new file: `aide --init` runs from the operator's `sysadm_r` session, so the database is initially labelled with the operator's SELinux user; the canonical type is correct but the user component must be `system_u` for the timer-spawned `aide-check` runs (which run with the `system_u` SELinux user) to read it without a user-component-driven AVC.

Interactive AIDE invocation under plain `sudo` (the `staff_sudo_t` context) fails with `execmem` AVCs against AIDE's hash-routine `mmap(PROT_EXEC)` and additionally lacks DAC search rights on `/var/log/aide/`; the canonical refresh therefore requires the `sudo -r sysadm_r -t sysadm_t` role-switch documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

As a forensic-trail discipline, the operator archives the current comparison before re-initialising — `aide --check > aide-prebaseline-<timestamp>.log 2>&1` — and refuses the rebaseline when that check exits `≥ 8` (a tool-internal error), rather than baselining over an unreadable database. The archived log preserves what the pre-refresh delta was, so a baseline taken across a system update remains auditable after the fact.

The role does **not** perform the first `aide --init` baseline automatically. The role's preflight stage detects a missing database, and the role surfaces a baseline-prompt `pause:` task containing the canonical command sequence above — both when the database is missing and when the managed scope block changed on the current run. Subsequent re-applies, after the operator has run the baseline, are idempotent.

### Exit-code semantics

`aide-check.service` exits with the AIDE-defined bitmask:

| Exit code | Meaning |
|---|---|
| `0` | the database matches the live filesystem; no new, removed, or changed entries |
| `1` | new entries detected (`new(1)`) |
| `2` | removed entries detected (`removed(2)`) |
| `4` | changed entries detected (`changed(4)`) |
| `1` + `2` + `4` = `7` | any combination thereof; for example `5` = `new`+`changed`, `7` = `new`+`removed`+`changed` |
| `≥ 8` | tool-internal error (database I/O failure, configuration parse error, hash-library failure) |

A non-zero exit `< 8` is **by-design** and means the integrity-monitor detected drift, not that the unit failed. systemd labels exit codes `1`–`7` with internal status names that do not align with AIDE's bitmask semantics and marks the unit `failed` because its `ExecMainStatus` is non-zero; this is a known systemd-versus-tool exit-code-namespace mismatch, not a deploy regression. The optional `/etc/profile.d/aide-alert.sh` banner is the operator-visible decode path. The unit deliberately does **not** ship `SuccessExitStatus=1 2 3 4 5 6 7`; doing so would mask genuine tool-internal errors at exit `≥ 8`.

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both are runnable from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface that the SELinux-side checks transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_aide/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`aide`), timer activity and the next-run listing, the full unit-file listing for both units, the most-recent run's exit code and timestamp via per-property `systemctl show -p <prop> --value aide-check.service` (one call per property), the database file's existence and mode/owner/label triplet, the configuration file's existence and triplet, and the `matchpathcon` mappings for `/usr/sbin/aide` and `/usr/bin/aide` (informational; reports both labels for the F44 sbin/bin-merge cross-check). It also reports whether the managed scope-tuning marker is present in `/etc/aide.conf`, whether `aide --config-check` parses clean, and whether the banner carries the acknowledgement block. The scope-marker, `aide --config-check`, and CIL-module-presence reports are gated behind a `sysadm_t` domain check (reading `/etc/aide.conf` and querying the policy store both require `sysadm_t`) and report `SKIP` from a `staff_t` shell; the banner-acknowledgement report needs only read access to the `0644` banner. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_aide/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `rpm -q aide` | exit `0`, stdout non-empty |
| `systemctl is-active aide-check.timer` | `active` |
| `systemctl is-enabled aide-check.timer` | `enabled` |
| `/var/lib/aide/aide.db.gz` exists | yes |
| Database triplet | mode `600`, owner `root:root`, label `aide_db_t` |
| `/etc/aide.conf` triplet | mode `600`, owner `root:root`, label `etc_t` |
| `/etc/systemd/system/aide-check.service` triplet | mode `0644`, owner `root:root`, label `systemd_unit_file_t` |
| `/etc/systemd/system/aide-check.timer` triplet | mode `0644`, owner `root:root`, label `systemd_unit_file_t` |
| `matchpathcon /usr/sbin/aide` or `matchpathcon /usr/bin/aide` | at least one resolves to `aide_exec_t` (either-or fail-fast) |
| `semodule -l \| grep -cx aide_extras` | `1` (sysadm_t-gated; `SKIP` from staff_t) |
| `sesearch -A -s aide_t -t dosfs_t -c filesystem -p getattr` | at least one allow line (sysadm_t-gated; `SKIP` from staff_t) |
| Managed scope-tuning marker in `/etc/aide.conf` | present (sysadm_t-gated; `SKIP` from staff_t) |
| `aide --config-check` | clean parse (sysadm_t-gated; `SKIP` from staff_t) |
| Banner acknowledgement block | the monotonic-stamp marker present in the installed banner (`SKIP` when the banner is opted out) |

The verify script does **not** assert `EXPECTED_NNP`, `EXPECTED_PROTECT_*`, `EXPECTED_PRIVATE_*`, `EXPECTED_RESTRICT_*`, `EXPECTED_SYSCALL_FILTER_*`, `EXPECTED_CAP_*`, or `EXPECTED_RESTRICT_ADDRESS_FAMILIES`. The unit ships no systemd hardening directives by design; presence of any of these `EXPECTED_*` constants in `verify.sh` is itself drift against the present end-state.

The verify script does **not** ship a `MainPID` liveness check. The service is `Type=oneshot` and has no `MainPID` between runs; the active probe is the timer (`systemctl is-active aide-check.timer`), not the service.

The `matchpathcon` boundary is asserted as either-or: at least one of `matchpathcon /usr/sbin/aide` and `matchpathcon /usr/bin/aide` resolves to `aide_exec_t`. The F44 equivalency rewrites the lookup target so the canonical-side path is the one the SELinux type-transition relies on; if **neither** path resolves to `aide_exec_t`, the verify reports drift and exits non-zero.

### AVC posture

On a correctly applied host, the role-switched query returns zero hits across the boot:

```bash
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E '(aide_t|aide_exec_t|aide_db_t|aide_log_t|aide_conf_t)'
```

The verify script runs this filter and treats any hit as drift. The diagnosis loop documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md) reads its records from the audit stream this topic's daily check exercises end-to-end (the file walk and the database write); the AVC-posture check above is therefore that diagnosis loop applied against AIDE's own audit stream.

### Functional smoketest

The post-deploy smoketest invokes the daily check on demand:

```bash
sudo -r sysadm_r -t sysadm_t systemctl start aide-check.service
```

The run takes roughly one-and-a-half to three minutes on a typical desktop with the stock `/etc/aide.conf` plus the managed scope block. Once the service exits, the operator reads the bitmask:

```bash
systemctl show -p ExecMainStatus --value aide-check.service
journalctl -u aide-check.service -b 0 --no-pager | tail -50
```

The bitmask decodes per the table under "Exit-code semantics". On a host whose database was rebaselined after the scope block was applied, the smoketest is the place to confirm the scope tuning took effect: the structurally volatile paths no longer appear in the delta, so a previously recurring non-zero exit becomes a clean `0`. The smoketest also runs the AVC-clean assertion immediately after the run completes; on a correctly applied host the filter returns zero hits both before and after the run.

### Pre-hardening recon

Before deploying the profile (and before running the first `aide --init`), the operator runs:

```bash
rpm -q aide
sudo -r sysadm_r -t sysadm_t ausearch -m AVC -ts boot \
  | grep -E 'aide_t|aide_exec_t' | head -20
ls -laZ /var/lib/aide/ 2>/dev/null
systemctl is-active aide-check.timer 2>/dev/null
```

On a stock host without this topic applied, `rpm -q aide` either reports the installed version or that the package is not installed; the `ausearch` filter typically returns empty (no daily check has ever run on a vanilla install); the database directory is empty (no `aide.db.gz`); the timer is `inactive` (the package does not enable it). The role's preflight stage runs the same recon and reports the outcome non-fatally. A non-empty AVC stream against `aide_t` on a vanilla host indicates a previous incomplete deployment and signals the operator to clean up before redeploying. Establishing this recon as a baseline before any tuning is the [pre-hardening smoketest baseline](../../explanation/smoketest-baseline.md) discipline: it distinguishes pre-existing innocent failures from a hardening regression.

### Idempotence and rollback

The role's modify stage is idempotent. The two unit files, the CIL source, and the optional banner are pushed via `ansible.builtin.copy` and converge on byte-for-byte content match. The managed scope-tuning block is applied via `ansible.builtin.blockinfile` and converges on the marker-delimited block; a re-apply against an unchanged block body reports no change and preserves the `0600 root:root` mode. The `aide --config-check` gate is read-only and aborts the apply before the timer is enabled if the merged configuration fails to parse. The `semodule install`, `restorecon`, `daemon-reload`, and `restart aide-check.timer` handlers each fire only on a change to the notifying task. The first `aide --init` baseline — and any rebaseline after a scope-block change — is **not** performed by the role; the role surfaces a baseline-prompt `pause:` task with the canonical refresh-discipline command sequence. There is **no** `restart aide-check.service` handler — the service is `Type=oneshot`. On a correctly applied host with the database in place, `--check` reports zero changes. Stated as a claim, not a guarantee.

The rollback posture is staged so the operator can stop at any depth.

**Stage 1** reverts the operator-visible ergonomics and the scheduling, leaving the policy and the scope tuning in place:

```bash
systemctl disable --now aide-check.timer
rm /etc/profile.d/aide-alert.sh
```

**Stage 2** additionally reverts the scope tuning by removing the managed block (then rebaselining so the restored scope is the database's baseline):

```bash
sudo -r sysadm_r -t sysadm_t sed -i '/# BEGIN topic_aide scope tuning (managed)/,/# END topic_aide scope tuning (managed)/d' /etc/aide.conf
sudo -r sysadm_r -t sysadm_t aide --init
sudo -r sysadm_r -t sysadm_t mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo -r sysadm_r -t sysadm_t restorecon -Fv /var/lib/aide/aide.db.gz
```

**Stage 3** additionally unloads the CIL module and removes the unit files, reverting the topic-owned policy and scheduling surface entirely; the package and the database file are preserved:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r aide_extras
rm /etc/systemd/system/aide-check.service /etc/systemd/system/aide-check.timer
systemctl daemon-reload
```

**Stage 4** additionally removes the package and the database directory, reverting to a stock host with no integrity-monitor:

```bash
dnf remove aide
rm -rf /var/lib/aide /var/log/aide
```

AIDE itself is not in the boot path: the timer is post-boot, and `/etc/aide.conf`, the banner, and the CIL module are not in the boot path. A malformed unit file or CIL module does not prevent boot, so the recovery how-to is referenced for completeness rather than as a likely failure mode for this topic.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — the `aide` package installs the binary at `/usr/sbin/aide` and the Fedora 44 `/usr/sbin → /usr/bin` global path equivalency rewrites the lookup target before the file-context table is consulted. The role's preflight runs both `matchpathcon` calls and requires `aide_exec_t` from at least one as fail-fast.
- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — the explicit-mode reflex. The role sets `0644` explicitly on the shipped artefacts and sets `0600` explicitly on the `/etc/aide.conf` block edit so the managed block preserves, rather than widens, the configuration mode.
- [Pre-hardening smoketest baseline](../../explanation/smoketest-baseline.md) — the pre-deploy recon establishes a baseline so pre-existing innocent failures are not misread as a hardening regression once the profile is applied.
