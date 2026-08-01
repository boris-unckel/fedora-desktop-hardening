<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Full run, 2026-08 — findings

Run of the complete cloud-testable suite against the feature branch
`feat/smartd-exec-label-and-kernel-rotation` (base commit `d2096b3`), covering every change
made since the last full run of 2026-06-05. Infrastructure rebuilt from an empty provider
project; base snapshot image `415031334`.

Scope: the 23 component scenarios plus the system tier. The four session-only topics
(`flatpak_portal_cache`, `keepassxc`, `mozilla_firefox`, `mozilla_thunderbird`) stay out of
cloud scope; they ship no component scenario.

## Outcome

**Green through the system tier, with the full cloud-testable set for the first time.**

- **Component tier: 23 / 23 green.** Every role that ships a component scenario passes the
  full sequence from the baked base snapshot: create, foundation prepare, converge,
  idempotence with zero changed tasks, verify in both SELinux contexts (`staff_t` and
  `sysadm_t`), destroy. Previously 19.
- **System tier: green over 22 topics.** Cumulative converge in bootstrap order, a second
  converge with zero changed tasks, a real reboot with boot-survival
  (`is-system-running=running`), and post-reboot per-topic persistence clean **in both
  SELinux contexts for all 22**. Previously 19 applied and 19 verified — see D7 for why those
  two numbers stopped agreeing.
- **Both documented deferrals resolved**, neither as a tolerance: `cups` was a real policy
  gap and is fixed; `integrity_monitoring` was never a runtime problem at all.
- **Eight defects found and fixed**, plus five documentation corrections. Two of the eight
  (D1, D2) would have reported a green run while proving nothing; two more (D7, D8) were
  defects in the verification apparatus rather than in the hardening.

The four session-only topics (`flatpak_portal_cache`, `keepassxc`, `mozilla_firefox`,
`mozilla_thunderbird`) remain outside cloud scope and ship no component scenario. The session
tier is still not run.

## What the run was asked to settle

Six commits had never been exercised by the suite. Two topics carried documented deferrals.
Both deferrals turned out to be something other than their documentation claimed, which is
the single most useful result of this run:

| Deferral as documented | What it actually was |
|---|---|
| `cups` — "clean except an `avc_clean` count still being classified" | A real gap in the topic's own CIL module. Fixed, not tolerated. |
| `integrity_monitoring` — "its verify runs the full four-check pass and a second serialisation start, which is too long-running to carry inside a cumulative converge" | Not a runtime problem at all. The measured pass takes **6 s**. The role had never completed a component converge, because its scenario was missing three lines of scaffolding. |

A third topic, `staff_wayland_memfd`, was listed in the test matrix as cloud-testable while
its preflight gated the whole role off for a missing package. Its scenario passed while
exercising nothing.

The pattern is worth stating plainly: **three of the five topics in the first batch failed
in a way that prevented the role from running at all**, rather than by behaving wrongly. A
suite that reads exit codes alone cannot distinguish "this role is correct" from "this role
never executed".

## Environment characteristics confirmed

- **Node boot time is ~10 minutes to SSH** in `ash` for this image, consistently — control
  node, builder, and every managed node. The wait loop in `bootstrap_infra.sh` allows
  40 × (10 s connect timeout + 10 s sleep), so this sits inside the budget but not far
  inside it. It dominates the wall-clock of a serial fan-out.
- **Only one managed node can exist at a time.** `ansible/molecule/shared/create.yml`
  attaches each node at `private_base + private_offset + idx`, and with one platform per
  scenario `idx` is always 0 — every scenario claims the same fixed address `10.10.1.10`.
  A node left behind makes every subsequent `create` fail with `ip_not_available`, and the
  `destroy` step of `molecule test` removes only its own scenario's node. This makes the
  serial design of `run_suite.sh` a hard requirement rather than a caution; a parallel
  fan-out would collide on the fixed address.
- **`PerSourcePenalties` (OpenSSH 10.x) punishes diagnostic probing.** Hand-probing port 22
  on a booting node — repeated `/dev/tcp` connects or bare `ssh` attempts — is exactly the
  burst of half-open connections the mechanism drops a source address for, and it locks the
  operator address out of the very node being diagnosed. This is why the harness multiplexes
  every command over one persistent `ControlMaster` connection. Diagnose from the log file,
  not by touching the node.
- One benign message during the base bake, in an otherwise clean log:
  `Failed to set unit properties on smartd.service: Unit smartd.service not found.` — a
  `smartmontools` scriptlet running `systemctl set-property` before the unit is registered.
  It does not affect the baked image; `topic_smartd` passes.

## Defects found and fixed

### D1 — `integrity-check` aborts mid-run on any unversioned path under `/boot`

Introduced by `d2096b3`. `boot_artifact_kver()` extracted the kernel version with
`grep -oE … | head -1`. "No version in this path" is the **normal** case for that function —
every unversioned path under the boot directory takes it, starting with
`/boot/loader/entries`, which changes on every kernel rotation. `grep` signals it with
exit 1, `set -o pipefail` promotes it to a pipeline failure, and `set -e` then killed the
entire run at the caller's `kv="$(boot_artifact_kver "$path")"` assignment: mid-check-3,
with a truncated log, check 4 never run, and a bare exit 1.

The exit code is what makes this severe. `1` is the documented "findings" status, and
`verify_run` in the role's own verify script treats status 1 as a **PASS** ("findings — a
PASS; review them, do not accept them to silence the check"). A hard abort was therefore
indistinguishable from a normal result, and would have been reported green by the very check
written to catch it.

Fixed by matching with the shell's own regex engine, which has no exit-status coupling —
the same idiom `is_kernel_bls_entry()` already used two functions above.

Two further instances of the same class were fixed alongside:

- `installed_kernel_versions()` had the identical `grep` pipeline, which made its caller's
  explicit `TOOL FAILURE: no installed kernels could be determined` branch unreachable dead
  code.
- The two `find`-based sweep walks in `check_unowned()` and `write_accept_lists()` swallowed
  a non-zero `find` status. An incomplete walk — an absent or unreadable scan root — would
  have been compared against the full package list and reported every unwalked path as
  "expected file gone": a plausible-looking answer to a broken precondition. Both now
  diagnose it as a tool failure, matching the discipline `check_boot_entries()` already
  states ("An unreadable directory MUST be a tool failure, not a finding").

Verified against real AIDE output rather than against assumption: AIDE 0.19.2 reports were
generated with the stock Fedora report settings (`report_level=changed_attributes`,
`report_grouped=yes`, `report_summarize_changes=yes`) and the parser run against them. The
section/line-shape parser itself is correct — the detail block is not double-counted, and an
adversarial fixture (planted kernel, planted unversioned file, tampered image of an installed
kernel) leaves all five entries in the remainder, so the classification does not weaken
detection.

### D2 — `topic_smartd` verify aborts under `staff_t` instead of reporting

Introduced by `d2096b3`. Same class as D1, in a different file. `file_type()` was
`stat -c '%C' "$1" 2>/dev/null | awk -F: '{print $3}'`. The topic relabels
`/usr/bin/smartd` to `fsdaemon_exec_t`, and `staff_t` holds no `getattr` on that type, so
`stat` fails from a confined staff shell — `pipefail` plus `set -e` then killed the script at
`actual=$(file_type …)`. The author's own `if [[ -z "${actual}" ]] … "context not readable"`
branch was unreachable.

The symptom was `staff_t rc=1` after nine lines with no FAIL line at all, against
`sysadm_t rc=0` with all fourteen checks — an abort, not drift.

The relabel is the property the commit introduces, so the role made its own verify
inoperable in exactly the context this test harness is built to check.

Fixed in three places:

1. `|| true` in `file_type()`, so the "context not readable" branch becomes reachable.
2. `verify_exec_label` and `verify_symlink_label` gated behind `is_sysadm_t` with
   `report_skip`. This is both the file's established idiom and the article's explicit
   promise ("checks that need `sysadm_t` are reported as `SKIP` rather than as drift when
   invoked from a non-privileged context"). Reporting it as drift would make a correctly
   hardened host fail its own verify.
3. The two label checks added to the expected-set table in
   `docs/reference/topics/smartd.md`. The commit's prose claimed "The verify stage asserts
   both", but the Verification section never listed them — script and oracle had drifted.

### D3 — `topic_integrity_monitoring` had never completed a component converge

Introduced by `e7a32ea`. Its `molecule/default/converge.yml` was the only one of the
twenty-three missing `become`, `become_flags`, and the `vars` block carrying
`foundation_sudo_roles_user`. The converge failed at the foundation preflight
(`foundation_sudo_roles_user is defined` → false) before reaching the role.

This is the defect behind the documented runtime deferral. Brought to the canonical form
every other scenario uses.

### D4 — `topic_cups`: a real NNP transition gap (resolves the `avc_clean` deferral)

The two denials, captured with `ausearch` on a node kept alive with `molecule converge`:

```
denied { nnp_transition }   cups-deviced  cupsd_t → cups_brf_t          (process2)
denied { execute_no_trans } /usr/lib/cups/backend/cups-brf  cupsd_t → cups_brf_exec_t
```

One event in two lines: `cups-deviced` enumerates the backends at daemon start-up, the
domain transition is refused under `NoNewPrivileges`, and the kernel's fallback to executing
in the calling domain is refused too.

**Classified against the `auditctl_t` precedent: not analogous.** In the auditd case the
subject is the verification tooling itself — `auditctl` reaching `auditctl_t` through the
role switch — which is measurement noise, and that verify deliberately excludes it. Here the
subject is `cupsd_t`, the hardened service, and the cause is its own drop-in's
`NoNewPrivileges`. That is precisely the class this topic's CIL module already repairs three
times over; `cups_brf_t` was simply omitted.

The extent of the class was measured rather than guessed, so the finding does not return in a
second round: only two transitions lead from `cupsd_t` into the CUPS family — `cups_pdf_t`
(already present) and `cups_brf_t` (missing); the remainder (`abrt_helper`, `apm`, `chkpwd`,
`exim`, `logrotate`, `sendmail`, `updpwd`) are not print backends. Of the seventeen backends
on disk, sixteen carry `bin_t` and execute in `cupsd_t` with no transition at all, which NNP
permits. `cups-brf` is the only one with a domain of its own. One rule closes the class.

Stock policy carries `type_transition cupsd_t cups_brf_exec_t:process cups_brf_t`, so the
transition is intended and the rule restores stock behaviour rather than extending it.

Applied to `nnp_cups.cil` (now five rules), `cil_rule_5` in `verify.sh`, and
`docs/reference/topics/cups.md` throughout — the rule count appeared in six places, plus the
listing and the Verification table. The shipped CIL and the documented listing are checked
against each other mechanically.

### D5 — acceptance lists carry the wrong SELinux user

Found once D3 let the role's verify run for the first time:

```
[FAIL] /etc/integrity-check/accepted-rpm-verify.txt is staff_u:object_r:etc_t:s0,
       file_contexts says system_u:object_r:etc_t:s0
[FAIL] /etc/integrity-check/accepted-unowned.txt   is staff_u:object_r:etc_t:s0,
       file_contexts says system_u:object_r:etc_t:s0
```

The type is right; only the **user field** is wrong. The affected files are exactly the two
that `integrity-check accept` writes itself — the role-shipped `accepted-context.txt` is
correct. A newly created file inherits the SELinux user of the creating process, and `accept`
is documented as a manual step run through `sudo -r sysadm_r -t sysadm_t`.

This is the drift class `7ab4063` built the full-context check for, and it is the first thing
that check caught: a type-only comparison — including this script's own check 4, which rests
on `restorecon -n` — reports nothing here.

Fixed with a `restorecon -F` pass after each list write. `-F` is load-bearing: plain
`restorecon` leaves the user field untouched. The fix belongs in the script rather than in the
deploying role: the role relabels *before* its own first `accept`, and the documented workflow
is an operator running `accept` by hand after reviewing findings, so an apply-time fix would
hold only until the first manual acceptance.

### D6 — `topic_staff_wayland_memfd` was gated off, not tested

The compositor packages had dropped out of the lean base image, so the role's preflight
package assertion gated the entire role off and the scenario passed having exercised nothing.

Fixed with a scenario-local install in the role's own `molecule/default/prepare.yml`, which
is where the base bake's own design says such packages belong. The probe-then-install idiom
of the shared prepare is followed deliberately: managed nodes have no public IPv4 and reach
the mirrors over IPv6 only, so an avoidable metadata refresh is an avoidable failure.

A repo-wide check confirmed this was the only role in that state.

## Documentation defects corrected

Three of these were found by reading the code against its own prose rather than by testing:

| Where | What it claimed | Reality |
|---|---|---|
| `bake_base_snapshot.sh` header | the base bakes `gnome-shell`, `mutter`, `keepassxc` | the package list excludes them, and the note below the list says so explicitly |
| `bake_base_snapshot.sh` header | "SELinux set to enforcing in the persistent config … managed nodes boot already-enforcing" | the base stays **permissive** on purpose; the inline comment at the `sed` call explains why (a clone re-runs cloud-init, cloud-init under enforcing stalls, and sshd is ordered after `cloud-init.target`). `foundation_prepare` owns the switch |
| `docs/reference/topics/smartd.md` | prose asserted both label checks | the Verification expected-set table listed neither |
| `docs/reference/topics/cups.md` | four rules / three helper subdomains | five / four after D4 |
| `livetest/topic-test-matrix.md` | — | carries no row at all for `topic_flatpak_kfd_device`; never added when the topic was created |

## Latent issue fixed without a live trigger

`matchpathcon -m link` is not a documented mode value (valid: `file`, `dir`, `pipe`,
`chr_file`, `blk_file`, `lnk_file`, `sock_file`). libselinux happens to return the same answer
as `lnk_file` for it, while a genuinely unknown value returns `default_t` — so the behaviour is
undocumented rather than correct. Changed to `lnk_file` across the sixteen verify scripts that
carried it. The branch is unreachable for drop-in directories, so this could not have changed
any run outcome.

### D7 — the system tier verified 19 of the 22 topics it deployed

`ansible/molecule/system/converge.yml` and `ansible/molecule/system/verify.yml` each carried
their own copy of `system_tier_topics`. Adding the three newly-cleared topics to the converge
without touching the verify made the two diverge, and the run reported
`post-reboot persistence OK: all 19 topics clean in both contexts` while having deployed 22.

The duplication is the defect, not the missing entries. A divergence here is invisible in
exactly the direction that matters: the verify side is the one that shrinks, so the run stays
green and simply checks less. The three unverified topics were the three most interesting
ones — the newly added `cups`, `integrity_monitoring`, and `flatpak_kfd_device`.

Fixed by extracting the list into `ansible/molecule/system/vars/system-tier-topics.yml`,
loaded by both playbooks through `vars_files`, so the class cannot recur. `cups.service` was
added to `scored_units` at the same time, since cups is now a hardened unit inside the tier
(14 scored units, previously 13).

### D8 — `topic_integrity_monitoring` verify reports privileged-only checks as drift

Surfaced by the D7 fix on its very first run: with the post-reboot gate extended from 19 to
22 topics, it failed immediately with
`staff_t failures: ['topic_integrity_monitoring']; sysadm_t failures: []`.

The script carried **no `sysadm_t` gate at all** — the only cloud-tested role in that state.
From a confined staff shell it cannot read `/etc/aide.conf` (0600 by deliberate design), the
baseline (`aide_db_t`), or the log directory (`aide_log_t`), and an unreadable file yields
exactly the same empty `grep` as a genuinely missing rule. So it reported:

```
[FAIL] no inverted rules found in /etc/aide.conf
[FAIL] /boot no longer in scope -- the early-boot image would be uncovered
[FAIL] baseline missing or empty
[FAIL] no non-empty run log found
```

None of which is drift. All four describe the reading domain, not the state. The unit-start
checks additionally stalled on an interactive polkit password prompt.

This is the same class as D2, and the same underlying confusion in both: **"I cannot read it"
reported as "it is not there."** In D2 the abort at least made itself visible as a truncated
run; here the script produced a confident, fully-formatted, entirely wrong drift report.

The reason it survived to the system tier is the second half of the defect: this role's
component scenario was **the only one of 23 that ran verify.sh in a single context**, and that
context was the privileged one. The gap was structurally invisible where it lived.

Fixed on both halves: `is_sysadm_t` plus a `skip()` helper gating the four privileged blocks
(`verify_scope`, `verify_run`, `verify_log`, `verify_serialisation`), and the component
scenario now runs both contexts and asserts both exit 0, like the other 22. Component
scenarios running both contexts: 23 / 23.

## Open observation — `integrity_monitoring` findings in the cumulative tier

In its component scenario the four-check pass reports `ExecMainStatus=0` ("clean"). In the
cumulative system tier the same pass reports `ExecMainStatus=1` ("findings") on both converge
runs, reproducibly.

`1` is a documented PASS — the verify states "findings — a PASS; review them, do not accept
them to silence the check" — and the acceptance lists show the baseline did capture the other
topics' files (533 unowned entries in the cumulative run against 484 in the component run).
The runtime figure is consistent across both (6 s component, 7–8 s cumulative).

**What the findings actually are is not established.** The detail lives in the run log on the
node, and the node is destroyed at the end of the scenario. This is recorded as an open
observation rather than explained: capturing it needs a deliberate run that keeps the node
alive, the same way the `cups` denials were captured for D4.

## Disposition matrix

All 27 topic roles.

| Topic | Component | System tier | Note |
|---|---|---|---|
| `topic_alsa_state` | PASS | yes | HW-gap on the effectiveness branch (no sound device) |
| `topic_auditd` | PASS | yes | smoke test for the pipeline |
| `topic_avahi_daemon` | PASS | yes | |
| `topic_chronyd` | PASS | yes | |
| `topic_cron` | PASS | yes | |
| `topic_cups` | PASS | yes | **deferral resolved** — D4 |
| `topic_dbus_broker` | PASS | yes | |
| `topic_flatpak_audio_sandbox` | PASS | yes | |
| `topic_flatpak_collection_id` | PASS | yes | |
| `topic_flatpak_kfd_device` | PASS | yes | first time in the system tier; functional branch is a real HW-gap (no AMD GPU) |
| `topic_flatpak_oci_pull_dbus` | PASS | yes | |
| `topic_integrity_monitoring` | PASS | yes | **deferral resolved** — D3, D5, D8; four-check pass measured at 6 s |
| `topic_kernel_hardening` | PASS | yes | |
| `topic_network_manager` | PASS | yes | |
| `topic_plymouth` | PASS | yes | HW-gap on the effectiveness branch (no graphical boot) |
| `topic_python_pip_user_tree` | PASS | yes | |
| `topic_rngd` | PASS | yes | |
| `topic_smartd` | PASS | yes | D2; HW-gap on the effectiveness branch (virtio exposes no SMART) |
| `topic_switcheroo_control` | PASS | yes | |
| `topic_thermald` | PASS | yes | HW-gap on the effectiveness branch (no DPTF) |
| `topic_tuned` | PASS | yes | |
| `topic_udisks2` | PASS | yes | |
| `topic_staff_wayland_memfd` | PASS | no | D6 — exercised for the first time; excluded from the system tier by design (Wayland session) |
| `topic_flatpak_portal_cache` | — | no | session-only, no component scenario |
| `topic_keepassxc` | — | no | session-only, no component scenario |
| `topic_mozilla_firefox` | — | no | session-only, no component scenario |
| `topic_mozilla_thunderbird` | — | no | session-only, no component scenario |

## Security scores

Captured on the final system-tier run, pre-hardening baseline against the post-reboot
hardened state.

| Metric | Pre | Post | Previous run (2026-06-05) |
|---|---|---|---|
| OpenSCAP (`ssg-fedora-ds`) pass count | 184 | **201** | 184 → 200 |
| Lynis hardening index | 67 | **75** | 67 → 74 |

`systemd-analyze security` unit exposure, lower is better:

| Unit | Pre | Post |
|---|---|---|
| `auditd.service` | 9.4 | 6.6 |
| `dbus-broker.service` | 8.7 | 7.2 |
| `NetworkManager.service` | 7.8 | 4.9 |
| `chronyd.service` | 3.5 | 3.2 |
| `crond.service` | 9.6 | 3.4 |
| `rngd.service` | 9.6 | 3.3 |
| `tuned.service` | 9.6 | 7.5 |
| `udisks2.service` | 9.6 | 4.7 |
| `avahi-daemon.service` | 9.6 | 2.7 |
| `smartd.service` | 9.6 | 3.0 |
| `thermald.service` | 9.6 | 2.6 |
| `alsa-state.service` | 9.6 | 2.6 |
| `plymouth-start.service` | 9.5 | 1.9 |
| `cups.service` | NA | 7.1 |

Two entries need stating rather than glossing:

- **`cups.service` has no pre-hardening figure.** It was added to the scored set in this run
  (D7), and the baseline capture reports `NA` for it — the delta is therefore unknown, not
  zero. Its post value of 7.1 is the second-highest of the scored units, which is consistent
  with the topic's documented scope: it deliberately does not set `User=`/`Group=` and leaves
  the upstream internal privilege model alone.
- **`tuned.service` at 7.5 and `dbus-broker.service` at 7.2** remain high relative to the
  rest. Both are known and in scope for their own topics, not regressions in this run.

The scores are recorded as trend values and are not a gate this run, matching the note in
`verify.yml`: a tool quirk must not be able to mask the boot-survival and persistence result.
