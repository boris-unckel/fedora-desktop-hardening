<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Flatpak audio sandbox bind-mount surface

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 that affects the bwrap sandbox-construction step of every Flatpak application holding the `pulseaudio` socket permission, on hosts where the operator login is mapped to the confined SELinux user `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t` (stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`). The deliverable is a single topic-owned CIL module loaded at priority 400 carrying exactly one `(allow ...)` rule that keeps the audio-bind-mount step of bwrap sandbox construction operational under `staff_t`-confined launches. The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** new SELinux type, **no** new SELinux attribute binding, **no** file-context mapping, and **no** `restorecon` invocation; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

This topic does **not** cover the Flatpak configuration model (`/etc/flatpak/`, `~/.local/share/flatpak/`, the per-app `~/.var/app/<appid>/` sandbox tree, the Flatpak manifest format, the `flatpak override` permission model, the `flatpak-portal` interaction surface), the bwrap sandbox-construction sequence beyond the single audio-bind-mount step on which the functional rule fires (other `mounton` targets, the `filesystem remount` family, the `var_lib_t:file execute` family for runtime-binary execution, the `sysctl_t:file write` for bwrap-internal `oom_score_adj` updates), the per-application Flatpak-permission posture (which applications hold `pulseaudio`, which hold `--device=all`, which hold neither — that surface is owned by the application-specific Topic articles), the PulseAudio or PipeWire user-side audio stack (per-user audio daemon, socket layout under `/run/user/${uid}/`, user-systemd unit), the `staff_u`-mapping deployment decision (the prerequisite Foundation layer owns this), the absence of a stock `staff_t → bwrap_t` type-transition on Fedora 44 as a hardening goal in itself (the absence is treated as the platform precondition that makes the gap reachable, and a future custom domain-transition is explicitly out of scope here), Flatpak-side workarounds (for example, `flatpak override --nosocket=pulseaudio` to dodge the gap by removing the permission — the deliberate posture is that the application's audio permission is intentional and the SELinux side is the correct surface to fix), the `domain_can_mmap_files` SELinux boolean (orthogonal — no relation to the allow rule in this topic), and the `systemd-analyze security` numeric score model (this topic ships no systemd service unit and the score model does not apply).

## End-state configuration

The end-state ships exactly one operator-installed file: a CIL source under `/root/`. The source is loaded into the system's targeted-policy module store at priority 400 via `semodule -X 400 -i`. The single allow rule in the source patches one pre-existing stock-policy gap; both the source type (`staff_t`) and the target type (`device_t`) are stock-policy types shipped by the targeted policy on Fedora 44 and are not declared by this module.

### Topic identity

The pipeline under hardening is the chain a desktop operator triggers when running, for example, `flatpak run <appid>` from the operator's interactive shell against any Flatpak application whose manifest declares `--socket=pulseaudio` (or, less commonly, `--device=all` which subsumes audio-device access). The shell runs under `staff_t` (the operator login is mapped to `staff_u`); the Flatpak launcher invokes `bwrap` to construct the application's sandbox; bwrap (running under `staff_t`, because stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`) executes a series of bind-mounts that assemble the sandbox root, and one of those bind-mounts maps the host's `/dev/snd` directory (SELinux type `device_t`) to `/newroot/dev/snd` inside the sandbox so the application can open ALSA devices through the per-user PulseAudio or PipeWire daemon. The single allow rule in this topic is the minimal allow surface required to keep the audio-bind-mount step of the bwrap sandbox-construction sequence functional under `staff_t`-confined launches.

The end-state depends on two stock packages on Fedora 44: `flatpak` (provides `/usr/bin/flatpak` and the per-application launch path) and `bubblewrap` (provides `/usr/bin/bwrap`, the sandbox-construction binary that performs the `mount(2) MS_BIND` call on which the functional rule fires). The SELinux types `flatpak_t` and `bwrap_t` are bound by stock-policy file_contexts on Fedora 44 but are **not** referenced by this topic — the source domain in the functional rule is `staff_t`, the operator's desktop role-stack, because stock targeted policy does not ship a `staff_t → bwrap_t` type-transition for `/usr/bin/bwrap` and bwrap therefore inherits the launching shell's `staff_t` domain. The topic does not require an additional package install; the role's preflight asserts both packages are present and aborts fail-fast on a missing entry. The topic is out of scope on hosts whose desktop role-stack is `unconfined_u:unconfined_r:unconfined_t` (stock policy already grants the equivalent device-directory mount surface to `unconfined_t`), on hosts where a future stock-policy update has shipped a `staff_t → bwrap_t` type-transition and bwrap consequently no longer runs in `staff_t`, and on hosts whose Flatpak inventory contains no application declaring the `pulseaudio` permission (the gap is unreachable; the role's preflight emits an informational note but does not abort, on the rationale that pre-applying the policy patch protects future application installs).

### Topic shape — single-rule stock-policy gap-patch

This topic occupies a structurally different shape than the system-services topics in this tree. The end-state is **not** "a daemon runs in a hardened domain". The end-state is a single CIL module loaded at priority 400 that contains exactly one `(allow ...)` rule and patches one pre-existing stock-policy gap without declaring any new SELinux types, without binding any new attributes, without shipping a systemd unit or drop-in, without altering file labels, and without restarting any service. Every downstream subsection is framed by this structural fact: the modify stage is one `semodule -X 400 -i` call, the verify discipline asserts the single allow surface is present in the loaded policy, and the rollback action is one `semodule -X 400 -r` call.

### Functional rule

The single allow rule patches the gap that breaks the audio-bind-mount step of bwrap sandbox construction under `staff_t`-launched Flatpak applications. Stock targeted policy on Fedora 44 ships **no** allow on `staff_t × device_t : dir mounton` for the desktop role-stack `staff_u:staff_r:staff_t`. The bwrap `mount(2)` call with `MS_BIND` for the source path `/oldroot/dev/snd` onto the destination `/newroot/dev/snd` returns `EACCES`; bwrap surfaces the failure to its standard error stream as `bwrap: Can't bind mount /oldroot/dev/snd on /newroot/dev/snd: Permission denied` (verbatim — the wording is upstream-fixed in the bubblewrap source and is not locale-translated) and exits non-zero before the application's main binary is executed. The Flatpak launcher reports a generic "failed to start" condition to the desktop user; the application's main window never opens. The functional symptom is a clean abort at sandbox-construction time, not a partial start: no application code runs, no application files are written, and the next launch attempt re-runs the same code path.

### Permission-set discrimination

The gap is reachable only on Flatpak applications whose manifest declares the `pulseaudio` socket permission (typical entry: `--socket=pulseaudio`) or, less commonly, the broad `devices=all` permission that subsumes audio-device access. Applications that do not declare an audio permission do not trigger the bwrap audio-bind-mount step and consequently do not reach the gap; they launch successfully on stock policy without this topic. The practical implication for an operator: a Flatpak application family that mixes audio-using and audio-silent members may exhibit a partial-failure surface where some applications launch and others abort at bwrap; the discriminating factor is the per-application `pulseaudio`-permission declaration, not a host-level setting. The role's preflight inspects each installed Flatpak application and counts entries whose permissions column contains the substring `pulseaudio`; the no-audio-Flatpak case is informational, not a deploy blocker — a future Flatpak install of an audio-using application still benefits from a pre-applied policy patch.

### Custom CIL module

Path: `/root/flatpak_audio_sandbox.cil`. Loaded at priority 400 via `semodule -X 400 -i /root/flatpak_audio_sandbox.cil`.

```cil
;; flatpak_audio_sandbox.cil — patches one stock-policy gap on Fedora 44
;; that affects the bwrap sandbox-construction step of Flatpak applications
;; holding the pulseaudio socket permission, on hosts where the desktop
;; login is mapped to the confined SELinux user staff_u and bwrap runs in
;; the source domain staff_t (no stock type-transition to bwrap_t).
;;
;; Functional rule: bwrap performs an MS_BIND mount of the host /dev/snd
;; directory (type device_t) into the sandbox root at /newroot/dev/snd.
;; Stock policy lacks the mounton allow on device_t directories for
;; staff_t, so the sandbox construction aborts and the application never
;; starts. Audio-silent applications are unaffected (the audio-bind step
;; is gated by the pulseaudio permission declared in the Flatpak manifest).
(allow staff_t device_t (dir (mounton)))
```

The module body declares no `(type ...)`, no `(typeattributeset ...)`, no `(roletype ...)`, no `(typetransition ...)`, and no `(typepermissive ...)`. Both the source type (`staff_t`) and the target type (`device_t`) are stock-policy types shipped by the targeted policy on Fedora 44. The single `mounton` permission on class `dir` is the only access surface this module grants; secondary surfaces (`device_t:chr_file {read write open}` on individual ALSA character-device nodes such as `/dev/snd/controlC0` or `/dev/snd/pcmC0D0p`, and `device_t:filesystem remount` on the audio-mount target after the bind step) are deliberately not pre-granted. An operator who observes a secondary AVC after the deploy on a different host (for example, an application that bypasses the per-user PulseAudio or PipeWire daemon and opens ALSA character devices directly) extends the same module additively rather than authoring a parallel one — but the canonical end-state on Fedora 44 with the typical PulseAudio- or PipeWire-mediated audio path is the single-rule form, and no secondary AVC fires on the canonical hardware/software pairing in this tree.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that the allow surface is absent in the currently loaded policy: `sesearch -A -s staff_t -t device_t -c dir -p mounton` returns empty. The role aborts as a no-op (return code reported to the operator, not as a failure) when the allow surface is already present in the loaded policy, on the assumption that a future stock-policy update has shipped the equivalent grant and the workaround is no longer required.
2. If the module `flatpak_audio_sandbox` is already installed at priority 400, copy the previously installed CIL source from `/var/lib/selinux/targeted/active/modules/400/flatpak_audio_sandbox/cil` to `/root/flatpak_audio_sandbox.cil.pre-reinstall` as a re-install audit anchor.
3. Write the CIL source at `/root/flatpak_audio_sandbox.cil` with explicit `0644 root:root`.
4. `semodule -X 400 -i /root/flatpak_audio_sandbox.cil`.
5. Post-load re-probe: the `sesearch` call of step 1 must now return a non-empty result (one allow line).

The role does **not** call `restorecon` (no file labels are altered), does **not** call `semanage fcontext` (no file-context mappings are added), does **not** restart any system service, does **not** restart the per-user PulseAudio or PipeWire daemon, does **not** restart any system or user `dbus-broker`, and does **not** invoke `flatpak run` of its own. SELinux access checks evaluate the loaded policy on each system call, so a subsequent `flatpak run` from the operator's shell picks up the new allow rule without restart and the operator does not need to restart the per-user audio daemon or any system service after the deploy. No host reboot is required.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain (`semodule`, `sesearch`, `ausearch`) transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### File modes

This topic ships exactly one operator-installed file:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/flatpak_audio_sandbox.cil` | `0644` | `root:root` | (host-default for `/root/`, typically `admin_home_t`) |

The explicit `0644` is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both run from a `staff_t`-confined shell for the staff-side checks; checks that need the policy store (`semodule`, `sesearch`, `ausearch`) are gated behind a `sysadm_t` domain check and reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_flatpak_audio_sandbox/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rpm -q flatpak bubblewrap`), the operator-installed Flatpak inventory (`flatpak list --columns=application,permissions`), counts entries whose permissions column contains the substring `pulseaudio` (the per-application discrimination signal), reports the operator's runtime SELinux context via `id -Z` (the canonical applicability anchor — `staff_u:staff_r:staff_t` is the matching mapping), the priority-400 module slot via `semodule -lfull | grep -wE '^[ ]*400.*flatpak_audio_sandbox'`, the functional-rule allow surface via `sesearch -A -s staff_t -t device_t -c dir -p mounton`, and the AVC stream since boot via `ausearch -m AVC,USER_AVC -ts boot` filtered for `staff_t.*device_t.*dir` and `path="/newroot/dev/snd"`. The `semodule`, `sesearch`, and `ausearch` queries are gated behind a `sysadm_t` domain check and reported as `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_flatpak_audio_sandbox/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `flatpak_audio_sandbox` module installed at priority 400 | `yes` |
| Functional allow `staff_t × device_t : dir mounton` present | `yes` |
| Functional-class AVC denials since boot | `0` |

Liveness probes are not part of the canonical Soll/Ist comparison; the policy-store reads are sufficient. Where any liveness inspection is needed, the verify uses the `[[ -d /proc/${pid} ]]` form rather than `kill -0`, because cross-user `kill -0` from a `staff_t` shell against a foreign-uid PID returns `EPERM` rather than `ESRCH` and would misreport a live process as dead. The verify does not invoke a `flatpak run` of its own. Asserting the AVC-clean state requires a host that has already launched at least one audio-permission-holding Flatpak application since boot; the verify reports the AVC-clean count as zero on a host that has not yet exercised the path, which is also the expected end-state value (the verify does not distinguish "zero because soaked" from "zero because untriggered" — the probe's audio-Flatpak-inventory output is the applicability signal).

### AVC posture

The AVC posture has two parts. On a soaked, `staff_u`-mapped host whose desktop user has launched at least one Flatpak application declaring the `pulseaudio` permission since boot **without** the workaround applied, the audit stream carries one or more `denied  { mounton }` records of class `staff_t × device_t : dir`, each with `path="/newroot/dev/snd"`, `comm="bwrap"`, `scontext` resolving to `staff_u:staff_r:staff_t`, and `tcontext` resolving to `system_u:object_r:device_t`. The records typically appear once per launch attempt because bwrap aborts on the first denied bind-mount and never reaches subsequent sandbox-construction steps. These are the records the functional rule closes. On the same workload with the workaround applied, the same filter returns an empty result. Secondary-class records (for example, `device_t:chr_file {read write open}` on individual ALSA character-device nodes, or `device_t:filesystem remount` on the audio-mount target) are not observed on the canonical Fedora-44 software stack documented in this tree — the single `mounton` allow on `device_t:dir` is sufficient for the PulseAudio- or PipeWire-mediated audio path that Flatpak applications use end-to-end. An operator who observes a secondary class on a different host extends the same module additively rather than authoring a parallel module.

Drift signals on an applied host: any fresh `denied  { mounton }` record of class `staff_t × device_t : dir` with `path="/newroot/dev/snd"` indicates the functional rule has been rolled back or a stock-policy update has shipped a `neverallow` that pre-empts the priority-400 grant; either case is operator-investigation. A surge of `denied` records of any other class involving `staff_t` or `device_t` is **not** drift caused by this topic and is investigated independently — most commonly a Flatpak application that adopts a non-PulseAudio audio path (direct ALSA character-device access) and exposes the secondary `device_t:chr_file` surface noted above.

The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. The CIL source is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `semodule -X 400 -i` install task is wrapped in a `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_audio_sandbox/cil` guard, so a re-run on a host already carrying the module reports `changed=false`. The role runs no `restorecon`, no `semanage fcontext`, no `systemctl restart`, and no handler. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery is a single-stage rollback. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r flatpak_audio_sandbox
```

Post-rollback, `sesearch -A -s staff_t -t device_t -c dir -p mounton` returns empty. The module slot at `/var/lib/selinux/targeted/active/modules/400/flatpak_audio_sandbox/` is removed. The CIL source at `/root/flatpak_audio_sandbox.cil` is **not** removed by `semodule -r` (it is the operator's source artefact, not part of the module slot); operators who want to also remove the source file do so explicitly with `rm -f /root/flatpak_audio_sandbox.cil`. Boot-failure risk for this topic is structurally zero — the single allow rule grants access on a user-process-side bind-mount step performed by bwrap from a desktop role that is not active during the boot sequence; the rule is not reachable from `init_t`, does not introduce an `nnp_transition` constraint, and does not introduce a system-service namespace effect. The worst-case post-rollback symptom is that audio-permission-holding Flatpak applications stop launching again.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The single allow rule patches a narrowly-scoped gap on a user-process-side SELinux type pair (`staff_t`, `device_t`) reached only from the operator's desktop shell during a Flatpak application launch whose manifest declares the `pulseaudio` permission. The rule does not exercise the kernel NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting hardening pattern documented in this tree. The deploy ships no systemd unit, no drop-in, no file-label change, and introduces no new SELinux type — the priority-400 module mechanism described in the Foundation layer carries the entire deploy.
