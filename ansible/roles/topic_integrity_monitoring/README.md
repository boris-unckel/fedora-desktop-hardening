<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# topic_integrity_monitoring

File-integrity monitoring for a Fedora 44 or later host. Replaces a whole-tree
AIDE run with four checks, only one of which carries a baseline.

Full reference: [integrity monitoring](../../../docs/reference/topics/integrity-monitoring.md).

## What it does

| Check | Covers | Baseline |
|---|---|---|
| `rpm -Va` | Content, mode, owner, group, capabilities of the package-owned set. | None — the package database is maintained by the transaction itself. |
| Unowned sweep | Files no package owns. | None — computed against the package database each run. |
| AIDE | Hash history of the remainder. | Yes, and only for the remainder. |
| `restorecon -nvR` | SELinux context drift, dry-run only. | None. |

On a package-managed host the first check covers the overwhelming majority of
the tree without any hand-maintained state. The role measures that share on the
target during preflight and reports it, so an operator on an unusual host can
see the number before applying rather than after.

## What it installs

```
/usr/local/sbin/integrity-check              wrapper, modes: check | accept
/etc/systemd/system/integrity-check.service  outer unit
/etc/systemd/system/integrity-check.timer    the single trigger
/etc/systemd/system/aide-check.service       inner unit (no timer)
/etc/systemd/system/aide-init.service        acceptance unit (no timer, no [Install])
/etc/profile.d/aide-alert.sh                 optional shell banner
/etc/integrity-check/accepted-*.txt          three acceptance lists
/usr/local/share/selinux/aide_extras.cil     one-rule policy module, priority 400
/etc/aide.conf                               marker-guarded inversion block appended
```

## Design points worth knowing before you change anything

**The scope is computed, never shipped.** `defaults/main.yml` names the rule
*prefixes* to comment out — never a resulting path set. The residue is
host-specific; a shipped list would be wrong on every other host. If you add a
tunable here, keep that property.

**One trigger, deliberately.** AIDE locks its report-file target, so two
concurrent runs make the second fail with exit 21. With a single unit as the
only entry point, systemd's job engine serialises starts and the collision
cannot happen. Do not add a second timer, and do not call the tools directly
from anywhere — start the unit.

**The AIDE check runs nested, for SELinux reasons.** The wrapper carries
`bin_t`, so PID 1 starts it as `unconfined_service_t`, and from that domain
there are no type-transitions to the confined tool domains. The wrapper
therefore runs `systemctl start --wait aide-check.service` so that PID 1 execs
the binary and the stock `init_t → aide_t` transition applies. Inlining the AIDE
call into the wrapper would silently drop that confinement.

**Read `ExecMainStatus`, never the caller's return code.**
`systemctl start --wait` does not propagate the inner unit's exit code — an
inner unit exiting 5 produces caller `rc=1`. Consuming the caller's code
collapses AIDE's bitmask onto "non-zero" and makes a tool failure
indistinguishable from a content delta.

**`ExecMainStatus` does not cover `ExecStartPost`.** The acceptance unit moves
the new database into place and relabels it as `ExecStartPost`. On failure
`ExecMainStatus` still reads 0 and the old database is still there and still
non-empty. Anything checking that unit must also require `Result=success` and
prove the intermediate file is gone.

**Acceptance is manual and never automated.** The role takes the *first*
baseline when none exists and refuses to refresh an existing one. An automated
refresh accepts every change before anyone has looked at it, which turns a
change detector into a self-confirming one. Its absence is the point.

**The acceptance-list hash rule lives outside the managed block.** A gate that
only fires in the "block is missing" branch would never deliver the rule to a
host that already carries the block.

## Idempotence notes

Every stage is idempotent on a correctly configured host:

- The configuration edits are marker-guarded and match-guarded; a second apply
  finds nothing to change.
- Unit and wrapper installation rewrite identical content.
- Timer enablement is already satisfied.
- `accepted-context.txt` is seeded with `force: false` and never overwritten —
  re-seeding would silently adopt whatever drift accumulated since.
- The first-baseline task is gated on the database being absent.

The one stage that always does work is the acceptance step, and only when an
operator invokes it directly.

## Verify

`files/verify.sh` returns non-zero on drift. One judgement call is encoded
there deliberately: **an aggregate status of 1 (findings) is a pass.** Known
findings that are deliberately left visible keep the aggregate at 1
indefinitely, and that is intended. A verify that treated 1 as failure would
push an operator toward accepting real drift just to make the check go green.
Only a tool failure (2) is a verify failure.

Run it after a `daemon-reload`, and on a node that booted enforcing — a
mid-run switch to enforcing produces denial noise that has nothing to do with
this role.

## Rollback

No boot path is touched and no reboot is involved; the units are timer-driven
and post-boot, so a broken apply yields a check that does not run rather than a
host that does not boot.

```console
# systemctl disable --now integrity-check.timer
# rm -f /etc/systemd/system/integrity-check.{service,timer} \
       /etc/systemd/system/aide-init.service \
       /usr/local/sbin/integrity-check \
       /etc/profile.d/aide-alert.sh
# cp -a /etc/aide.conf.bak-preinvert /etc/aide.conf
# systemctl daemon-reload
# semodule -X 400 -r aide_extras
```

Restoring the pre-inversion database from the operator's own backup returns the
host to whole-tree monitoring.
