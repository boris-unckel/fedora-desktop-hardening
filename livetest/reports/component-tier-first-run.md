<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Component-tier first run — findings

First end-to-end execution of the component tier against a real cloud node.
Provider: Hetzner Cloud (server type `cpx21`, image `fedora-44`, location `ash`).
Scope: the `topic_auditd` component scenario as the pipeline-proving vertical
slice. All cloud resources were destroyed on completion; the project holds zero
resources.

## Outcome

The harness pipeline — provision, substrate prepare, foundation tier, converge,
verify, destroy — runs end to end. The four-layer foundation tier reaches a clean
apply-and-verify state after seven defects were fixed in flight. The first topic
converge then exposed two further issues that need deliberate remediation rather
than a mechanical fix, so the slice did not reach green and the run was stopped
with the infrastructure torn down.

## Environment characteristics confirmed

- The provider image boots SELinux **permissive**, the default login maps to
  `unconfined_u`, and it is **root-only** — no unprivileged cloud account is
  materialized. The harness therefore creates the connection account through
  cloud-init, installs the SELinux tooling, switches to enforcing, and maps the
  account to `staff_u` before any role runs.
- OpenSSH 10.x ships `PerSourcePenalties` enabled by default; a burst of
  connection attempts against a still-starting `sshd` gets the source address
  dropped. The harness disables it on provisioned nodes and drives everything
  over one persistent control connection.
- Shared-vCPU server types are offered only in the US datacenters (`ash`, `hil`);
  the EU locations returned none, so the run used `ash`.

## Foundation-tier defects found and fixed

The foundation roles were evidently validated only with the controller and target
on the same host. Under a real control-node-to-managed-node push they failed in
seven distinct ways, each fixed in flight:

1. **`foundation_umask`** — the `lineinfile` `regexp` used the POSIX class
   `[[:space:]]` in an Ansible (Python `re`) context, where it does not match a
   tab. The stock `UMASK` line was never replaced; a duplicate was appended.
   Changed to `\s`.
2. **`foundation_sudo_roles`** — the same POSIX-class-in-Python-`re` bug in the
   sudoers `secure_path` `lineinfile`. Changed to `\s`.
3. **`foundation_sudo_roles` preflight** — a `stat` of `{{ role_path }}/files/...`
   ran on the managed node, where the controller-side path does not exist. Added
   `delegate_to: localhost`.
4. **`foundation_sudo_roles`** — the CIL publish directory was written before it
   existed (it is created by a later layer), and `copy` does not create parents.
   Added a directory-create step.
5. **`foundation_sudo_roles` verify** — `semodule -lfull` piped into an `awk` that
   exits on first match sent SIGPIPE to `semodule` under `set -o pipefail`,
   aborting the script with code 141. Removed the early `exit`.
6. **`foundation_umask` verify** — the live-umask check reads the umask of its own
   process; under Ansible `become` that reflects the sudo context, not a login
   shell. Addressed in the harness substrate by giving `sudo` a restrictive
   umask. The configuration checks (login.defs and `pam_umask`) were already
   correct.
7. **`foundation_audit_logging_baseline` verify** — read journald `Storage` via
   `systemctl show --property=Storage`, which is not a unit property and is always
   empty. Changed to read the merged journald configuration, defaulting to `auto`.

After these fixes the full foundation tier applies and self-verifies cleanly on a
fresh node. The seven fixes were reviewed and accepted by the operator (2026-06-04)
and are committed.

## Topic-tier issues (left for operator-reviewed remediation)

The `topic_auditd` converge exposed two issues that are not single-line fixes and
that touch security-control behavior:

- **Verify runs before daemon-reload.** The role notifies a `daemon-reload`
  handler, which fires at play end, after the role's own verify task. The verify
  reads the unit before the drop-in is merged, so `NoNewPrivileges` and the
  `Protect*` directives read as unset. A daemon-reload must happen before the
  directive checks.
- **Mid-run enforcing flip produces audit noise.** The component substrate
  switches the node from permissive to enforcing during the run rather than
  booting under enforcing, so SELinux denials accumulate during the transition.
  The topic verify's audit-cleanliness check assumes a boot-enforcing host and
  reports those denials. Separating genuine denials from transition noise needs
  analysis, and a clean result needs a boot-enforcing substrate.

The same class of issue is likely to recur across the remaining topics.

## Disposition

- The harness (Molecule delegated driver against the provider, the shared
  create and destroy playbooks, the substrate-and-foundation prepare, and the
  component scenario) is built and proven through the foundation tier.
- The seven foundation fixes are applied in the role tree and are ready for
  review.
- The session tier, the system-tier reboot and scoring, and the remaining topics
  were not run.
- Every cloud resource was destroyed; the provider project is empty.

## Resolved decisions

The two design points the run raised are decided.

### D1 — verify ordering: fix the roles

Each daemon topic runs `meta: flush_handlers` immediately before its own verify task,
so the notified `daemon-reload` runs and the merged unit is in place before
`systemctl show` is read. A plain reload (not a restart) is sufficient and matches the
stage-config / effect-on-reboot intent. The harness verify step stays the authoritative
gate. This applies to every daemon topic that ships a drop-in plus a reload handler.
Rationale: the roles are run-anywhere artifacts, so a first-run self-verify failure is a
real defect fixed at the source rather than masked in the harness.

### D2 — enforcing substrate via a suite-scoped base snapshot

Nodes boot under enforcing instead of flipping mid-run, so audit-cleanliness and runtime
checks are trustworthy and the shipped verify scripts pass unmodified. An enforcing base
snapshot is baked once per suite run, and every component and system node provisions from
it (no per-scenario reboot). The base is suite-scoped, not persistent.

Snapshot housekeeping (serial runs, single OS, zero residue for cost):

- Labels distinguish kinds: the base carries `livetest=base`; pre-reboot rollback handles
  carry `livetest=transient` plus a run identifier.
- Preflight sweep: at suite start, delete any leftover `livetest` servers and snapshots
  from an aborted prior suite. This is the self-healing backstop against the snapshot cap.
- In-run: the system tier creates a pre-reboot transient and deletes it as soon as
  boot-survival passes.
- Full teardown, on success and on abort (an exit trap in the suite driver): destroy all
  servers, delete all snapshots (base and transient), then the network, firewalls, and SSH
  key, leaving the project empty and verified at zero resources.
- The cap is otherwise a non-issue: serial runs keep live snapshots at roughly one to
  three. Only a light assertion remains — abort if the project still holds snapshots after
  the preflight sweep.

Phase-2-remaining artifacts for these decisions: `bake_base_snapshot.yml`,
`snapshot_housekeeping.yml`, the suite driver's teardown trap, and `meta: flush_handlers`
in the daemon topic roles. The boot-enforcing base substrate should be folded into
`test-environment.md` when the harness is completed.

## Recommended next steps

- Review and accept the seven foundation fixes.
- Implement the resolved decisions above (D1 and D2).
- Re-run the component slice to green, then proceed to the remaining topics and
  the system tier under the same provision-snapshot-test-destroy discipline.

## Component fan-out run (2026-06-04)

D1 and D2 were implemented and proven: `topic_auditd` passes the full component
scenario end to end from the enforcing base snapshot (create, foundation prepare,
converge with the daemon-reload flushed before verify, idempotence with zero changed
tasks, verify in both contexts, destroy). One further fix was needed: the role's
`avc_clean` over-counted (it counted matching lines, including the benign admin-tool
denial `auditctl_t -> auditd_log_t:dir { read }` raised when `auditctl` runs through the
`sysadm_r` transition). It now counts distinct denial records and excludes that
admin-tool self-denial, and prints any real denial.

A full fan-out then ran all 23 cloud-testable topics serially from the base snapshot.
`topic_auditd` passed; the other 22 failed in three root-caused classes:

| Class | Topics | Root cause | Status |
|---|---|---|---|
| Invalid server name | 12 (every topic whose name contains an underscore: dbus_broker, kernel_hardening, network_manager, avahi_daemon, flatpak_collection_id, python_pip_user_tree, switcheroo_control, flatpak_audio_sandbox, flatpak_oci_pull_dbus, gnupg_pinentry_dbus, staff_wayland_memfd, alsa_state) | The provisioned server name `managed-<topic>` carried the role-name underscore; the provider rejects names that are not valid hostnames. Confirmed (dbus_broker, kernel_hardening). | Fixed: hyphenate the generated platform names. |
| Verify drift | cups confirmed; chronyd, cron, rngd, tuned, udisks2, smartd, aide ran and failed verify, cause not yet captured | cups failed a stat of its daemon's vendor unit because the package is absent from the minimal base image (auditd passed because `audit` is baked in). The other seven are unconfirmed (per-node logs were torn down with the control node). | Pending: bake the common daemon packages into the base (a desktop-like target) or have prepare install the topic package; then re-confirm the rest. |
| Node unreachable | plymouth, thermald | SSH never came up within 300 s. Cause not isolated. | Pending: investigate (cloud-init/boot vs transient). |

The 22 generated component scenarios and `flush_handlers` across 22 roles are committed to
the tree. All cloud resources were torn down after the run; the project holds zero
resources. The remaining work — base-package strategy, the unreachable pair, per-topic
verify drift, and the system tier — is a distinct next pass; this matrix is its roadmap.

## Harness rebuild and second fan-out (2026-06-04)

The ad-hoc provisioning bash was reconstructed as committed, shellcheck-clean drivers under
`harness/` (`lib.sh`, `bootstrap_infra.sh`, `bake_base_snapshot.sh`, `run_suite.sh`,
`teardown.sh`, `README.md`). The cost policy changed: the control node, base snapshot,
network, key, and firewalls are reusable infrastructure and are kept between runs; only the
transient managed nodes are recycled per scenario, and full teardown is a manual,
operator-initiated step.

### Golden-image boot failures found and fixed

Booting managed nodes from a baked snapshot exposed a chain of clone-boot failures that the
first run (which booted the catalogue image directly) never hit. Each is now fixed in the
harness:

- **PerSourcePenalties on the control node.** Only managed nodes had it disabled; the
  control node, built from the catalogue image, penalised the operator's address during the
  provisioning burst. Fixed by disabling it on every node and routing all remote commands
  over a single persistent SSH `ControlMaster` connection (no reconnect bursts).
- **Emptied machine-id.** Truncating `/etc/machine-id` to generalise the image set
  `ConditionFirstBoot`, so `systemd-firstboot` blocked the headless boot waiting for console
  input and sshd never started. Fixed by not touching machine-id; a clone re-runs cloud-init
  anyway via its fresh provider instance-id.
- **Enforcing at boot.** A clone re-runs cloud-init under enforcing on its first boot and
  stalls, and sshd is ordered after `cloud-init.target`, so sshd never comes up. The base is
  now baked **permissive**; `foundation_prepare` sets enforcing and reboots once into a clean
  enforcing boot (cloud-init already done), which also removes the mid-run permissive→enforcing
  transition noise the suite-scoped snapshot was meant to avoid. This refines D2: the base is
  permissive, the enforcing boot is per node.
- **Baked staff_u mapping.** Mapping the connection user to staff_u in the base made the
  prepare session start confined, so plain sudo (staff_sudo_t) could not write `/etc/selinux`
  and the enforcing-config task failed. Fixed by leaving the base unconfined-default and
  letting `foundation_prepare` establish the mapping from the initial unconfined session.
- **Recycled provider IPs with tracked host keys.** A reused address with a new host key was
  refused. Fixed with no host-key tracking for these ephemeral nodes (matches the scenario's
  `host_key_checking: false`).
- **Heavy desktop stack.** `gnome-shell`/`mutter` pull `gdm` and the graphical target, which
  is unnecessary for the component tier; dropped from the base.
- `run_suite` recorded a failing topic instead of aborting (a guarded return code), and the
  wait timeouts were raised to 600 s for the reboot-bearing prepare.

Diagnostic note: the operator workstation's sandbox blocks raw `/dev/tcp` probes, which
produced false "port closed" readings during boot-debugging; the node's own journal and the
control-node Molecule run are the reliable signals.

### Second fan-out result

All 23 cloud-testable topics ran serially from the rebuilt base: **7 pass** (auditd,
network_manager, tuned, flatpak_collection_id, flatpak_audio_sandbox, flatpak_oci_pull_dbus,
python_pip_user_tree), 16 fail. The failures are categorised; most are verify-script drift
the live test correctly surfaced, not hardening defects:

| Category | Topics | Cause | Disposition |
|---|---|---|---|
| Invalid bash in verify | rngd, thermald, alsa_state, switcheroo_control, cron | `readonly -i` is not valid bash (only `declare` takes `-i`); the script aborts before any check | Fixed: `declare -ri`. |
| Cap/RAF compare not normalised | plymouth (case), udisks2 (cap + RAF order), smartd (cap order) | `systemctl show` renders caps lower-case in kernel-bit order and RAF alphabetically; exact-string compares fail though the set is correct | Fixed plymouth (lower-case set) and udisks2 (order/case-insensitive set compare); smartd still HW-gapped. |
| F44 fcontext drift in preflight | kernel_hardening (`sysctl_conf_t`→`system_conf_t`, `systemd_unit_file_t`→`systemd_conf_t`), cron (drop-in dir), aide (`aide_conf_t`→`etc_t`) | the expected SELinux types predate the F44 labelling; preflight gates the role before apply | Pending: update expected types to the F44 values. |
| Environment / tooling gap | cups (`lpstat` non-zero: no printers), dbus_broker (`dbus-send` absent), aide (database not initialised) | the check assumes a desktop with state a fresh VM lacks | Pending: make the check tolerant of the headless baseline or seed the state. |
| HW-gap (expected non-green) | smartd (no SMART device → inactive), thermald, switcheroo_control, alsa_state | virtio exposes no SMART/DPTF/GPU-mux/sound hardware | Expected; verify directive application, not daemon liveness. |
| Applicability-gated (expected) | gnupg_pinentry_dbus | no `pinentry-gnome3` backend selected on the node, so the topic gates itself out | Expected; needs a prepare that selects the backend to exercise. |
| Deferred package | staff_wayland_memfd | asserts a desktop package dropped from the lean base | Pending: a GUI-enabled variant or scenario-local install. |
| Open finding | cups | `avc_clean` reports 2 denials (records not yet captured) | Pending: capture the records; classify real vs benign as with the auditd `auditctl_t` case. |

### Verify-fixed subset re-run

The fixed subset (rngd, plymouth, udisks2, thermald, switcheroo_control, alsa_state) was
re-run. **udisks2 now passes** (the set-compare cleared its cap and RAF order drift), taking
the green count to 8/23. The others, with `readonly -i` fixed, now run their real checks and
expose the next layer:

- **RestrictAddressFamilies order is systemic.** rngd, thermald, and alsa_state all fail the
  same exact-string RAF compare (`AF_UNIX AF_NETLINK` vs `AF_NETLINK AF_UNIX`) that udisks2's
  `verify_set_property` fixed. The order/case-insensitive set compare should be applied to
  every topic that asserts CapabilityBoundingSet or RestrictAddressFamilies by string.
- **SystemCallFilter class-token method.** plymouth's cap-case fix worked, but it (like avahi)
  then fails because the verify looks for `~@class` / `@class` tokens in the value returned by
  `systemctl show -p SystemCallFilter --value`, which is the **expanded syscall list** with no
  class tokens. The check must read the raw directive (`systemctl cat` / the drop-in), not the
  resolved value — the same shape udisks2's `verify_systemcallfilter` already uses (length +
  anchor presence).
- **HW-gap and applicability confirmed.** thermald and alsa_state are `inactive` with no
  PID (no DPTF / no sound card), alsa_state additionally is a oneshot state-restore (the
  liveness/active check does not fit a oneshot) and wants `/var/lib/alsa/asound.state` and
  `alsactl_exec_t` (F44 gives a different fcontext). switcheroo_control hits its single-GPU
  applicability gate. rngd reports no `hwrng`/"dropped to" journal lines (entropy-source
  logging differs on a VM). These are expected non-green on virtio.

### Systematic next-pass fixes (precise, mechanical)

1. Apply the order/case-insensitive set compare (the `verify_set_property` pattern) to every
   CapabilityBoundingSet / RestrictAddressFamilies assertion across topics.
2. Read SystemCallFilter class tokens from the raw unit, not the resolved value (plymouth,
   avahi, and any topic asserting `@class` tokens).
3. Update preflight expected SELinux types to the F44 labels (kernel_hardening
   `system_conf_t` + `systemd_conf_t`, cron drop-in dir, aide `etc_t`, alsa `alsactl` path).
4. Make liveness/active tolerant of oneshot services and classify HW-gap topics
   (smartd/thermald/alsa/switcheroo) as directive-applied rather than daemon-live; treat
   applicability-gated topics (gnupg_pinentry_dbus, switcheroo_control) as expected skips.
5. Make environment-dependent checks tolerant of the headless baseline (cups `lpstat` with no
   printers, dbus-broker `dbus-send` absent, aide uninitialised database, rngd entropy source)
   or seed the state in prepare.
6. Capture the cups `avc_clean` denial records and classify real vs benign.

The reusable infrastructure (control node, base snapshot, network, key, firewalls) is kept
per the cost policy; only managed nodes were recycled. The system tier (cumulative P1 apply →
reboot → boot-survival → OpenSCAP/Lynis/systemd-analyze scoring) remains the final step.

## Verify-drift mop-up and system-tier build (2026-06-05)

The six next-pass items above were worked to completion against the warm base snapshot,
re-confirming each topic on a real node rather than reasoning from the prior log. The pass
took the confirmed-green component count to **19 of the cloud-testable topics**, fixed two
systemic harness bugs and two genuine hardening/role defects, and built the system tier.

### Harness bugs found (would have blocked every topic)

- **`foundation_prepare` forced a network refresh.** It ran `dnf install` of the SELinux
  tooling the base already bakes; once the baked dnf metadata cache went stale the install
  tried to refresh over the managed node's IPv6-only egress and failed with a DNS error,
  aborting prepare for every topic. It now probes with `rpm -q` first and installs only
  genuinely-missing packages, so the normal path needs no network.
- **`journalctl --since boot` is invalid.** `boot` is not a parseable `--since` timestamp
  (`Failed to parse timestamp: boot`), so the journal-since-boot checks silently matched
  nothing and always failed. Replaced with `-b` across rngd/thermald verify and three
  `probe.sh` baselines (and the thermald role recon).

### Genuine hardening / role defects the live test surfaced

- **chronyd dropped only one of four caps.** The drop-in wrote
  `CapabilityBoundingSet=~CAP_NET_ADMIN ~CAP_NET_BIND_SERVICE ~CAP_NET_BROADCAST ~CAP_NET_RAW`,
  but the leading `~` governs the whole line; the per-token `~` on tokens 2–4 made them
  malformed, so only `CAP_NET_ADMIN` was removed. Correcting the syntax then revealed chronyd
  fails to start without the other three (it binds the NTP socket and uses them during
  startup even in client mode). End state: drop `CAP_NET_ADMIN` only, with the verify aligned.
- **kernel_hardening apply was unreachable, then non-idempotent.** With preflight fixed
  (F44 labels), apply ran for the first time and exposed: (a) the first `flush_handlers`
  fired the `restorecon`-of-all-four-paths handler before three drop-ins existed — now the
  handler relabels only existing paths; (b) `/etc/systemd/coredump.conf.d` does not exist on
  stock F44 and `copy` does not create parents — now created first; (c) the grubby apply
  keyed `changed_when` on `/proc/cmdline` (never carries the args pre-reboot) so it reported
  changed on every converge — now keyed on the BLS args grubby actually manages.

### Verify-script drift fixed (the live test was right, the scripts were wrong)

- **cap/RAF set normalisation** across rngd, thermald, alsa_state, cron (RAF order) and
  smartd (cap kernel-bit order) and avahi (cap case) — order/case-insensitive set compare.
- **SCF `@class` from the raw unit** for cron and avahi; plymouth's expected subtractive
  tokens corrected to the bare `@resources …` spelling the drop-in actually ships (one `~`
  governs the line).
- **F44 SELinux labels** in defaults/preflight/verify and the reference docs: `/etc/sysctl.d`
  `system_conf_t`, coredump `systemd_conf_t`, cron drop-in `crond_unit_file_t`,
  `/etc/aide.conf` `etc_t`, `alsactl` `alsa_exec_t`.
- **HW-gap / headless tolerances:** thermald & smartd accept the `ConditionVirtualization=no`
  inactive state; alsa_state accepts the no-sound-card inactive state (and tolerates the
  `setpriority` seccomp hit on a no-card host — a Phase-B SCF interaction to settle on real
  sound hardware); switcheroo_control tolerates absent `lspci`; cups accepts socket-activated
  service state and `lpstat` "No destinations"; dbus_broker skips the redundant `dbus-send`
  round-trip when the tool is absent (busctl covers it); kernel_hardening skips
  unprivileged-unreadable sysctls and the PAM-mediated ulimit check in the staff_t pass and
  treats the running-cmdline as pending-reboot (grubby staging is the gate).

### Component matrix after the pass

| Disposition | Count | Topics |
|---|---|---|
| Green (confirmed this pass) | 11 | rngd, thermald, cron, smartd, avahi_daemon, dbus_broker, plymouth, switcheroo_control, alsa_state, chronyd, kernel_hardening |
| Green (carried, unchanged) | 8 | auditd, network_manager, tuned, udisks2, flatpak_collection_id, flatpak_audio_sandbox, flatpak_oci_pull_dbus, python_pip_user_tree |
| Deferred — open AVC finding | 2 | aide (`avc_clean` 12 hits, from the prepare full-FS `aide --init`), cups (`avc_clean` 2 hits) — records to be captured and classified |
| Expected skip — applicability | 1 | gnupg_pinentry_dbus (preflight cannot read the operator's `gpg-agent.conf`, `gpg_secret_t`; belongs to the session tier) |
| Out of scope — session / Wayland | 5 | keepassxc, mozilla_firefox, mozilla_thunderbird, flatpak_portal_cache, staff_wayland_memfd |

The base snapshot, control node, network, key, and firewalls are kept per the cost policy;
managed nodes were recycled per scenario.

### System tier — first cumulative run (2026-06-05)

The system tier was built (`ansible/molecule/system/` + the committed driver
`harness/run_system.sh`) and run against the base: foundation prepare with a pre-hardening
score baseline, cumulative apply of the 19 green-eligible topics in P1→P3 order, idempotence,
a real reboot (`side_effect`), then post-reboot per-topic persistence and OpenSCAP / Lynis /
systemd-analyze scoring (`verify`).

Step outcomes, in order:

| Step | Result |
|---|---|
| create | ✓ |
| prepare (foundation + baseline scores) | ✓ |
| converge (19 topics cumulative) | ✓ — no cross-topic apply conflict |
| idempotence (second converge, zero changed) | ✓ — all 19 idempotent cumulatively |
| side_effect (real reboot + boot-survival) | ✓ — host returned, reachable, `is-system-running=degraded` |
| verify (post-reboot persistence + scoring) | ✗ — 2 of 19 topics failed post-reboot |

**Boot-survival of the host passed.** The cumulative hardened host (foundation + 19 topics,
including the kernel-cmdline change now active) survived a real reboot and came back reachable.

**The tier caught a genuine boot-failure-class defect.** `plymouth-start.service` entered
`failed` at boot — the one degraded unit — so its post-reboot verify failed. The component
tier cannot catch this: plymouth-start runs at the foundation reboot, which happens *before*
the plymouth drop-in is applied, so the component scenario only ever inspects an
already-exited clean-boot unit. The system reboot is the first boot where plymouth-start
starts *with* its hardening drop-in, and it fails. The strong hypothesis is the documented
`ReadWritePaths` runtime-race (`226/NAMESPACE`): the drop-in's
`ReadWritePaths=/run/plymouth /var/lib/plymouth /var/spool/plymouth` are not all present at
early boot, which a post-apply restart (component tier) tolerates but a real boot does not.
This is precisely the P1 boot-failure class the tier exists to surface; it degrades the boot
(splash service) rather than preventing it.

**udisks2 also failed post-reboot persistence.** Almost certainly the same shape as cups —
`udisks2.service` is D-Bus-activated and idle (inactive) after a reboot with nothing calling
it — but the per-topic stdout was not logged this run, so the exact failing check is not yet
captured.

The persistence assert fired before the scoring task, so the post-hardening OpenSCAP / Lynis /
systemd-analyze numbers were not captured this run.

#### System-tier next pass (precise)

1. **plymouth boot-failure:** confirm the failure mode on a kept node
   (`systemctl status plymouth-start`, `journalctl -b`); if `226/NAMESPACE`, apply the
   `-`-prefix `ReadWritePaths` (or `RuntimeDirectory=`/`StateDirectory=`) fix per the
   runtime-race pattern.
2. **udisks2 post-reboot:** apply the cups-style activation tolerance (accept an
   inactive-but-`Result=success` D-Bus-activated unit; SKIP liveness when idle), after
   confirming the failing check.
3. **scoring capture:** move the scoring task before the persistence assert (and log each
   topic's full verify stdout) so the three scores and the per-topic failure detail are
   recorded even when persistence fails.
4. re-run the system tier for a fully-green result with the three security scores against the
   baseline.

Two cross-topic / post-reboot bugs the tier already fixed this pass: NetworkManager's
connectivity verdict briefly dropping after dbus_broker's restart (settle-poll), and the
system reboot/scoring plays needing the `sysadm_r/sysadm_t` role switch (the staff_t
DAC-caps trap — plain `become` in the now-staff_u context cannot read the umask-0027
AnsiballZ module file).

## System tier — fully green, boot-defect root-caused (2026-06-05)

The plymouth boot-failure was confirmed, root-caused, fixed, and the system tier re-run to a
fully-green result with the three security scores captured.

### Plymouth boot-failure: the hypothesis was wrong

The prior pass's strong hypothesis — `ReadWritePaths` runtime-race (`226/NAMESPACE`) — was
**refuted** by direct observation on a kept node. The confirm-first step was decisive.

A `managed-plymouth` node was provisioned (foundation + the plymouth role) and rebooted via a
throwaway side-effect that captured the boot-time state. Findings:

- All three `ReadWritePaths` targets **exist** at boot (`/run/plymouth`, `/var/lib/plymouth`,
  `/var/spool/plymouth` → `True`/`True`/`True`). Not a missing-path / namespace fault.
- The actual failure: `Main PID … (code=dumped, signal=SYS)`, `status=31/SYS`,
  `Result: core-dump`. plymouthd is **seccomp-SIGSYS-killed**, not `226/NAMESPACE`.
- The coredump stack trace names the syscall: `#0 klogctl` ← `ply_show_new_kernel_messages` ←
  `show_splash_screen` ← `main`. plymouthd calls `klogctl` (the `syslog(2)` syscall) on every
  splash show, to render kernel boot messages.
- `systemd-analyze syscall-filter` confirms `syslog` is **not** in `@system-service` and
  **not** in any of the eleven subtracted classes. The default-deny allowlist therefore
  excludes it silently, and the unprivileged `SystemCallErrorNumber` default (kill) turns the
  first `klogctl` into a SIGSYS.

This is a Phase-B SCF over-restriction, not a runtime-race. The component tier could not catch
it because plymouth-start runs once at the *foundation* reboot (before the drop-in exists); the
system reboot is the first boot of plymouth-start *with* the drop-in.

### Fix and live validation

`SystemCallFilter=syslog` is added to `99-process-restrict.conf` as a positive re-add. Because
`syslog` is absent from every subtracted class, the add carries no precedence conflict — the
merged effective filter simply gains the one syscall. `ProtectKernelLogs=yes` is **retained**:
it gates the actual ring-buffer read to `EPERM`, which plymouth tolerates; the SCF line only
prevents the kill. Iteration B (`ProtectKernelLogs=no`) was tested on the same node and gave
no behavioural benefit (plymouthd still lingers `active (running)`), so the stronger
`ProtectKernelLogs=yes` was kept.

Validated on the kept node (deploy + reboot + `molecule verify`, both SELinux contexts):
plymouth-start → `active`, `Result=success`, no core-dump, clean boot journal,
`scf_syslog_allow → syslog permitted`, `verify.sh clean in staff_t and sysadm_t`. The node was
then destroyed.

### Sub-state discovery (headless lingering)

With the drop-in applied, plymouth-start settles into `active (running)` on a headless node —
plymouthd lingers after both `plymouth-quit` and `plymouth-quit-wait` complete (most plausibly
the `--retain-splash` path with no display manager to take the splash over). The component tier
saw `active (exited)` only because it inspected the pre-drop-in foundation boot. The verify is
now tolerant: `SubState` is asserted as a set (`exited` or `running`) with `Result=success`, and
a dedicated `scf_syslog_allow` check enforces the syslog re-add so the SIGSYS regression cannot
silently return.

### udisks2 D-Bus-activation tolerance

`udisks2.service` is D-Bus-activated and idles back out, so it is `inactive` after a reboot with
nothing calling it — the same shape as cups. `verify.sh` now accepts an inactive unit when the
system D-Bus service file (`org.freedesktop.UDisks2.service`) is present and SKIPs the liveness
probe when there is no MainPID; the security properties read from the loaded unit config
regardless of run state.

### Harness / verify improvements

- `system/verify.yml`: the security-score capture now runs **before** the persistence gate, and
  every topic's full `verify.sh` stdout is logged in both contexts. A drifted topic can no
  longer cost the run its score record, and the failing check is visible without a re-run.
- `system/side_effect.yml`: now captures `systemctl status` + `journalctl -b` for every failed
  unit, so a boot-survival failure self-documents the exit code (e.g. a future `nnn/NAMESPACE`
  or SIGSYS) in the run log instead of a bare unit name.

### System-tier re-run result (fully green)

| Step | Result |
|---|---|
| converge (foundation + 19 topics) | ok=548, changed=102, failed=0 |
| idempotence (second converge) | **changed=0**, failed=0 |
| side_effect (real reboot) | **boot-survival OK: is-system-running=running** |
| verify — persistence | **all 19 topics clean in both contexts (staff_t + sysadm_t)** |

No failed units, no SIGSYS, no core-dump anywhere in the run.

**Security scores (pre → post hardening), captured this run:**

`systemd-analyze security` unit exposure (lower is better):

| Unit | pre | post |
|---|---|---|
| plymouth-start | 9.5 | **1.9** |
| alsa-state | 9.6 | 2.6 |
| thermald | 9.6 | 2.6 |
| avahi-daemon | 9.6 | 2.7 |
| smartd | 9.6 | 3.0 |
| chronyd | 3.5 | 3.2 |
| rngd | 9.6 | 3.3 |
| crond | 9.6 | 3.4 |
| udisks2 | 9.6 | 4.7 |
| NetworkManager | 7.8 | 4.9 |
| auditd | 9.4 | 6.6 |
| dbus-broker | 8.7 | 7.2 |
| tuned | 9.6 | 7.5 |

- **OpenSCAP** (`ssg-fedora-ds`): pass 184 → **200**, fail 218 → 202.
- **Lynis** hardening index: 67 → **74**.

### Component matrix update

plymouth and udisks2 move from the system-tier deferred column to **green**: the full
cloud-testable set (19 topics) now passes the cumulative converge, the real reboot, post-reboot
persistence in both SELinux contexts, and contributes to the measured score deltas. Reusable
infrastructure (control node, base snapshot, network, key, firewalls) was kept; every managed
node (investigation + system) was recycled per the cost policy.
