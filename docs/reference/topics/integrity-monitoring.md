<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# integrity-monitoring

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents the end-state file-integrity monitoring profile for a Fedora 44 or later host. The end-state replaces a whole-tree AIDE run with four checks that divide the work by *what actually needs a baseline*: a package-database verification pass, an unowned-file sweep, a scope-reduced AIDE run, and a SELinux context dry-run. It ships one wrapper under `/usr/local/sbin/`, three operator-supplied unit files plus one retained inner unit under `/etc/systemd/system/`, three acceptance lists under `/etc/integrity-check/`, one marker-delimited inversion block appended to `/etc/aide.conf`, and an optional acknowledgement-aware shell banner under `/etc/profile.d/`. In scope: the four-check split and its rationale, the single-trigger design and the serialisation it relies on, the SELinux domain constraint that forces one check to run through a nested unit, the two status-propagation traps, the acceptance model and its deliberate asymmetry, the exit-code semantics, the verify discipline, and the rollback posture. Not in scope: the stock `/etc/aide.conf` body outside the managed block, the full AIDE selector grammar, the cron-driven AIDE path, mailer integration, the `systemd-analyze security` numeric score model, and any intrusion-detection capability beyond change detection.

## End-state configuration

### Why only one check carries a baseline

On a package-managed host, the overwhelming majority of the monitored tree already has a baseline that maintains itself: the package database. A measurement on a representative host found **298,414 of 300,051** paths under `/usr`, `/opt`, `/boot` and `/etc` to be package-owned — **99.45 %**. Re-hashing that set into a second, hand-maintained baseline buys no additional coverage and costs a refresh after every transaction. Worse, that refresh is what turns a change detector into a self-confirming one: an automated post-update rebaseline accepts every change before anyone has looked at it.

The end-state therefore splits the job:

| Check | Covers | Baseline |
|---|---|---|
| `rpm -Va` | Content, mode, owner, group and capabilities of the package-owned set. | **None.** The package database is updated atomically by the transaction that changes the files. |
| Unowned sweep | Files present on disk that no package owns. | **None.** Computed against the package database on every run. |
| AIDE | Hash history of the remainder. | **Yes** — and it now spans a few thousand paths instead of the whole tree. |
| `restorecon -nvR` | SELinux context drift. Dry-run only. | **None.** |

Checks one and two are complementary rather than redundant. A package verification pass cannot see a file that belongs to no package — a new unowned binary in a system binary directory is invisible to it by construction, and that is precisely the artefact worth noticing. The sweep sees existence; AIDE sees content. Neither subsumes the other.

Measured effect of the split on the reference host: the AIDE database fell from **29,253,354 to 198,211 bytes**, and all four checks together complete in **47 s** against **2 m 19 s** for the full-tree AIDE run alone.

### Single trigger

Exactly one timer drives the aggregate check. `aide-check.service` is retained but has **no timer of its own**; it runs only as a nested step of the aggregate check. Any second caller — an operator update script, a manual invocation — starts the aggregate unit rather than invoking the tools directly.

This is load-bearing, not stylistic. AIDE takes a lock on its `report_url` file target. Two concurrent runs make the second fail with **exit 21, `File lock error`** — a value outside the `1/2/4` change bitmask, which a classifier written against that bitmask reports as an unspecific tool failure rather than as a lock collision. A daily timer carrying `Persistent=yes` places its catch-up run in the post-boot window, which is exactly when an operator's update routine tends to run, so the collision is systematic rather than unlucky.

With a single unit as the only entry point, systemd's job engine serialises concurrent starts and the collision cannot occur. On the reference host a second `systemctl start` issued against the running unit waited **46 s** for the first to finish.

### SELinux domains — the constraint and its resolution

A wrapper script placed under a local `sbin` directory carries `bin_t`. PID 1 starts it through `type_transition init_t bin_t:process unconfined_service_t`, and from `unconfined_service_t` there are **no** type-transitions to `aide_exec_t`, `rpm_exec_t` or `setfiles_exec_t`:

```console
$ sesearch -T -s unconfined_service_t -t aide_exec_t -c process
$ sesearch -T -s init_t -t bin_t -c process
type_transition init_t bin_t:process unconfined_service_t;
```

A wrapper that invoked AIDE directly would therefore run it outside `aide_t`, losing the confinement the stock policy provides for exactly this tool. The end-state resolves this by **not** running AIDE from the wrapper. The wrapper runs:

```sh
systemctl start --wait aide-check.service
```

PID 1 execs the binary, the stock `init_t → aide_t` transition applies, and the confinement is preserved.

The trade-off is bounded and stated deliberately: `rpm -Va` and `restorecon -n` still run under `unconfined_service_t`. Both are strictly read-only — `restorecon` exclusively in dry-run mode — so the value of `rpm_t` or `setfiles_t` for a pure verification pass is small. A deployment that wants them confined applies the same nesting pattern to them without any redesign.

### Status propagation — two traps

Both were found by measurement rather than by reading documentation, and both produce a check that reports success while doing nothing useful.

**`systemctl start --wait` does not propagate the inner unit's exit code.** An inner unit exiting `5` produced caller `rc=1`. The status must be read explicitly:

```sh
systemctl start --wait aide-check.service || true
status="$(systemctl show -p ExecMainStatus --value aide-check.service)"
```

Consuming the caller's return code instead collapses AIDE's bitmask onto "non-zero", which makes a tool failure — including the lock collision above — indistinguishable from an ordinary content delta.

**`ExecMainStatus` reflects `ExecStart` only, never `ExecStartPost`.** The baseline-refresh unit performs the database move and the subsequent `restorecon` as `ExecStartPost` steps. If either failed, `ExecMainStatus` would still read `0`, the previous database would still be present and non-empty, and a check of `ExecMainStatus` combined with a non-empty file test would report success on a refresh that never happened. The refresh path must additionally require `Result=success` **and** prove that the intermediate database file is gone:

```sh
status="$(systemctl show -p ExecMainStatus --value aide-init.service)"
result="$(systemctl show -p Result --value aide-init.service)"
[ "$status" = 0 ] && [ "$result" = success ] || exit 2
[ ! -e /var/lib/aide/aide.db.new.gz ] || exit 2
```

### Locale pinning

The wrapper exports `LC_ALL=C`. Two independent reasons, both correctness rather than tidiness: `comm` requires identically sorted inputs while `sort` collates by locale, so a non-C locale produces wrong set differences; and part of the parsed tool output is translated — the package verification pass reports a localised word for a missing file.

### Deploy profile

| File | Layer |
|---|---|
| `/usr/local/sbin/integrity-check` | Wrapper. Two modes: `check` (default) and `accept`. |
| `/etc/systemd/system/integrity-check.service` | Operator-supplied oneshot running the wrapper. |
| `/etc/systemd/system/integrity-check.timer` | Operator-supplied daily timer with jitter and `Persistent=yes`. |
| `/etc/systemd/system/aide-check.service` | Retained inner unit. No timer. Preserves `aide_t`. |
| `/etc/systemd/system/aide-init.service` | Acceptance unit. No timer, no `[Install]`. |
| `/etc/aide.conf` (managed block appended) | Stock configuration plus one marker-delimited inversion block. |
| `/etc/integrity-check/accepted-*.txt` | Three acceptance lists. |
| `/etc/profile.d/aide-alert.sh` (optional) | Acknowledgement-aware shell banner. |

### `integrity-check.service`

```ini
[Unit]
Description=Aggregated file-integrity check
Documentation=man:rpm(8) man:aide(1) man:restorecon(8)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/integrity-check check
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30min
```

The service ships **no** systemd hardening directives — no `NoNewPrivileges`, no `Protect*`, no `Private*`, no `SystemCallFilter`, no `CapabilityBoundingSet`. This is by design and matches the retained inner unit: the checks perform full-system read walks, and a namespace-restricting profile would hide subtrees from their view and silently shrink the monitored surface. The presence of any such directive on either unit is drift.

### `integrity-check.timer`

```ini
[Unit]
Description=Daily timer for the aggregated file-integrity check
Documentation=man:systemd.timer(5)

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=yes

[Install]
WantedBy=timers.target
```

`Persistent=yes` is deliberate on a host that is not powered continuously: it guarantees the catch-up run. It is also the reason the single-trigger design matters — see the collision above.

### `aide-init.service`

```ini
[Unit]
Description=AIDE baseline refresh (manual acceptance step)
Documentation=man:aide(1)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --init
ExecStartPost=/usr/bin/mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
ExecStartPost=/usr/sbin/restorecon -Fv /var/lib/aide/aide.db.gz
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30min
```

The unit carries no `[Install]` section and no timer. It is reachable only through the wrapper's `accept` mode, which is itself a manual command. The `restorecon` step is not optional: `aide --init` creates the database with the calling process's context, and `aide_db_t` is required.

### `/etc/aide.conf` scope inversion

The managed block removes the package-owned trees from AIDE's scope and adds back what the package manager cannot cover. The whole-tree rules are commented out in place rather than deleted, so a future stock configuration update remains diffable:

```text
# ic-inverted (covered by the package verification pass): /bin    NORMAL
# ic-inverted (covered by the package verification pass): /sbin   NORMAL
# ic-inverted (covered by the package verification pass): /lib    NORMAL
# ic-inverted (covered by the package verification pass): /lib64  NORMAL
# ic-inverted (covered by the package verification pass): /opt    CONTENT
# ic-inverted (covered by the package verification pass): /usr    NORMAL

# === BEGIN integrity-monitoring scope inversion (managed) ===
/usr/local  NORMAL
# === END integrity-monitoring scope inversion (managed) ===

# Acceptance lists: hashed, not merely permission-checked.
/etc/integrity-check  NORMAL
```

What stays in scope, and why:

- **`/etc`** in full. It holds a few thousand files of which a meaningful minority is not package-owned, and hashing all of it — including the package-owned part, which the verification pass also covers — costs almost nothing. Enumerating only the non-owned subset would require a path list that has to be maintained by hand every time a drop-in is added.
- **`/root`**, **`/boot`** and the variable-state rules, unchanged. Keeping `/boot` means kernel updates produce a handful of added and removed entries; that is accepted deliberately, because the alternative is losing coverage of the early-boot image, and the entries now correlate with a recorded transaction identifier.
- **`/usr/local`**, added back explicitly. It sits under the removed `/usr` tree but is by definition not package-managed, which makes it exactly the case a hash baseline is for.

Any pre-existing scope-tuning block in the configuration remains valid and is left untouched; the inversion composes with it rather than replacing it.

The rule for the acceptance directory is added **outside** the marker-guarded block. This is deliberate: a re-apply on a host that already carries the block must still pick the rule up, and a gate that only runs in the "block is missing" branch would never deliver it. The rule itself matters because the catch-all rule for the configuration tree is permissions-only — a content edit to an acceptance list, which is the direct route to suppressing findings for anyone who already knows the check exists, would otherwise be invisible.

The edit is validated with `aide --config-check` against the candidate file **before** it is made live; a configuration that fails the check leaves the live file untouched.

### Acceptance lists

Three plain-text files under `/etc/integrity-check/`, version-controllable and diffable:

| File | Holds |
|---|---|
| `accepted-rpm-verify.txt` | Accepted package-verification deviations. |
| `accepted-unowned.txt` | Accepted non-package-owned paths. |
| `accepted-context.txt` | Accepted SELinux context deviations. |

They are **not** a baseline in the AIDE sense. They are not regenerated after every transaction — only when the actual state changes.

Ghost entries — paths the package declares but does not ship, carrying the file-type marker `g` — are filtered from the verification pass before comparison. The package manager declares them expected-to-differ, so reporting them on every run is noise by construction. On the reference host this filter reduced the verification pass from 47 lines to 28.

**The context list is deliberately asymmetric.** The acceptance step refreshes the first two lists and **never** the third. Context drift is a defect, not an inventory: it disappears by being fixed, not by being accepted. Only proven false positives belong there — the canonical one being a path that resolves onto a filesystem which cannot carry SELinux labels at all, where `restorecon` would want to relabel forever and could never succeed.

### Acceptance procedure

```console
# sudo /usr/local/sbin/integrity-check accept
```

There is no automatic refresh anywhere in the end-state. An automatic refresh accepts every change before anyone has looked at it, which is the failure mode the whole topic is built to avoid.

The order of operations inside `accept` is load-bearing:

1. Write the acceptance lists from current state.
2. **Then** refresh the hash baseline.

The reverse order leaves the freshly written lists outside the baseline, so the very next check reports them as changed. That finding is a phantom — no review can resolve it, because every acceptance run recreates it.

For the same structural reason, the acceptance lists **include themselves** in the unowned list. They are not package-owned, and they cannot appear in the sweep result that produces them, because the sweep runs first. Excluding the acceptance directory from the sweep would be the wrong fix: listing the files explicitly keeps their *disappearance* a finding, which is what an operator wants to know if someone removes an acceptance list to suppress results.

### Exit-code semantics

| Status | Meaning |
|---|---|
| `0` | All four checks clean. |
| `1` | At least one check reports findings. |
| `2` | At least one check failed as a tool. |

Deliberately **not** AIDE's `1/2/4` bitmask. That encoding describes one tool's three change classes and does not extend to four aggregated checks; carrying it forward after the split would be actively wrong rather than merely imprecise. Which check fired, and what it found, is recorded in the run log.

A findings result is not automatically a failure state. Known findings that are deliberately left visible — context drift awaiting a fix, for instance — keep the aggregate at `1` indefinitely, and that is the intended behaviour: the alternative is accepting them, which would hide them.

### `aide-alert.sh` banner

Optional. Reads the **aggregate** unit's status, not AIDE's:

```sh
_ic_rc=$(systemctl show -p ExecMainStatus --value integrity-check.service 2>/dev/null)
case "$_ic_rc" in 0|"") unset _ic_rc; return 0 ;; esac
```

The acknowledgement mechanism is keyed on the run's monotonic exit timestamp, so a reviewed finding stops re-announcing itself on every login without suppressing the next, distinct run:

```sh
_ic_mono=$(systemctl show -p ExecMainExitTimestampMonotonic --value integrity-check.service 2>/dev/null)
_ic_ack="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/aide-alert.ack"
if [ -n "$_ic_mono" ] && [ -f "$_ic_ack" ] && \
   [ "$(cat "$_ic_ack" 2>/dev/null)" = "$_ic_mono" ]; then
    return 0
fi
```

The acknowledgement file lives in the per-boot runtime directory, so it expires at reboot by construction. The banner decodes no bitmask — it distinguishes findings from tool failure and points at the log.

### Log files and retention

One log per run, at `/var/log/aide/integrity-<timestamp>-dnf<transaction>.log`.

The directory is the AIDE log directory rather than a dedicated one. That is deliberate: it carries `aide_log_t`, which is the one location the inner `aide_t` domain is permitted to write, and a separate directory would have required a file-context entry for no gain.

The file name carries the package-manager transaction identifier, which binds the forensic trail to the transaction that triggered the run. This replaces after-the-fact correlation between a diff and a transaction log.

The wrapper writes the log itself; no sub-process ever inherits a write descriptor on it. Sub-command output is captured into shell variables and emitted by the wrapper. This matters because sub-commands transition into other domains, and a descriptor inherited by a transitioned domain is checked against *that* domain's write set.

Retention is an age limit over the set:

```sh
find /var/log/aide -maxdepth 1 -name 'integrity-*.log' -mtime +90 -delete
```

`logrotate` is the wrong tool here. It rotates per file; a per-run file set makes its generation counting inapplicable — a `rotate N` directive counts generations of each individual file and never deletes anything — and its truncate mode leaves zero-byte artefacts, which is precisely the shape that hides a broken forensic trail.

### File modes

| Path | Mode | Owner | SELinux type |
|---|---|---|---|
| `/usr/local/sbin/integrity-check` | `0755` | `root:root` | `bin_t` |
| `/etc/systemd/system/integrity-check.service` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/integrity-check.timer` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/aide-check.service` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/systemd/system/aide-init.service` | `0644` | `root:root` | `systemd_unit_file_t` |
| `/etc/profile.d/aide-alert.sh` | `0644` | `root:root` | `bin_t` |
| `/etc/integrity-check/accepted-*.txt` | `0644` | `root:root` | `etc_t` |
| `/etc/aide.conf` | `0600` | `root:root` | `etc_t` |
| `/var/lib/aide/aide.db.gz` | `0600` | `root:root` | `aide_db_t` |

Two entries deserve a note. A unit file without `systemd_unit_file_t` is **not loaded at all** — the manager refuses it and the failure presents as a missing unit rather than as a permission error, so `restorecon` after installation is mandatory rather than tidy. And `bin_t` on the shell-profile drop-in is the stock context for that directory, not an anomaly.

`/etc/aide.conf` stays at its stock `0600`. The tool runs as `root` and no service user reads it, so a blanket `0644` — the reflex that is correct for daemon configuration under a restrictive umask — would only expose the integrity ruleset locally.

## Verification

### Probe

Read-only. Reports the package-owned ratio and the unowned residue so an operator can see whether the inversion is worth it on the host in question before applying it, and measures each check's runtime and finding count as a noise baseline.

### Verify

Returns non-zero on drift. Checks:

- All artefacts present with expected mode, owner and SELinux label.
- The superseded AIDE timer removed; the aggregate timer enabled with a scheduled next elapse.
- The inversion marker present; the boot directory still in scope; the database materially smaller than the pre-inversion size.
- All three acceptance lists present and readable.
- A full run through the unit. **A findings result is a pass** when the findings are known and deliberately visible; only a tool failure is a verify failure. A verify that treats `1` as failure would push an operator toward accepting real drift to make the check go green.
- The log written, non-empty, and carrying a transaction identifier in its name.
- Serialisation demonstrated by issuing a second start against the running unit and observing that it waits.

### Idempotence and rollback

Re-applying is a no-op on every stage: marker-guarded configuration edits skip, unit installation rewrites identical content, timer enablement is already satisfied. The acceptance step is the one stage that always does work, by design.

No boot path is touched and no reboot is involved. The units are timer-driven and post-boot, so the failure mode of a broken apply is a check that does not run — not a host that does not boot.

Rollback restores the previous AIDE configuration, the previous database, the previous banner and the previous timer from the backup directory the apply step creates before making any change.

## Related patterns

- [RPM-versus-filesystem path aliasing](../../explanation/rpm-vs-filesystem-path-aliasing.md) — why the unowned sweep must normalise both path-aliasing classes before comparing, and what it reports if it does not.
- [F44 sbin/bin merge fcontext](../../explanation/f44-sbin-bin-merge.md) — the same merge seen from the SELinux side.
- [UMASK and daemon readability](../../explanation/umask-and-daemon-readability.md) — why the blanket `0644` reflex is wrong for the AIDE configuration.
