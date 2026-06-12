<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Flatpak compute-device bind surface (/dev/kfd)

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 that affects the bwrap sandbox-construction step of every Flatpak application holding the `dri` device permission, on hosts running Flatpak 1.18 or later whose kernel exposes the AMD compute device node `/dev/kfd`, where the operator login is mapped to the confined SELinux user `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t` (stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`). The deliverable is a single topic-owned CIL module loaded at priority 400 carrying exactly one `(allow ...)` rule that keeps the compute-device bind step of bwrap sandbox construction operational under `staff_t`-confined launches. The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** new SELinux type, **no** new SELinux attribute binding, **no** file-context mapping, and **no** `restorecon` invocation; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

This topic does **not** cover the Flatpak configuration model (`/etc/flatpak/`, the per-app `~/.var/app/<appid>/` sandbox tree, the manifest format, the `flatpak override` permission model), the bwrap sandbox-construction sequence beyond the single device-bind step on which the functional rule fires, the per-application Flatpak-permission posture (which applications hold `dri` — that surface is owned by the application-specific Topic articles), the ROCm compute stack and its userland (the `/dev/kfd` node's first-class consumers; no compute access is granted by this topic), the GPU render-node surface under `/dev/dri/` (stock policy already covers it for `staff_t`; the gap is specific to the `hsa_device_t`-typed compute node), the `staff_u`-mapping deployment decision (the prerequisite Foundation layer owns this), the absence of a stock `staff_t → bwrap_t` type-transition as a hardening goal in itself (the absence is treated as the platform precondition that makes the gap reachable), Flatpak-side workarounds (the `dri` device permission carries the hardware-rendering surface the application legitimately uses; the SELinux side is the correct surface to fix), and the `systemd-analyze security` numeric score model (this topic ships no systemd service unit and the score model does not apply).

## End-state configuration

The end-state ships exactly one operator-installed file: a CIL source under `/root/`. The source is loaded into the system's targeted-policy module store at priority 400 via `semodule -X 400 -i`. The single allow rule in the source patches one pre-existing stock-policy gap; both the source type (`staff_t`) and the target type (`hsa_device_t`) are stock-policy types shipped by the targeted policy on Fedora 44 and are not declared by this module.

### Topic identity

The pipeline under hardening is the chain a desktop operator triggers when running `flatpak run <appid>` from the operator's interactive shell against any Flatpak application whose manifest declares the granular `dri` device permission (typical entry: `--device=dri`). Applications holding the broad `all` device permission are **not** affected: `devices=all` binds the host `/dev` directory wholesale in a single directory bind and never reaches the per-node `stat` on `/dev/kfd`; only the granular `dri` permission derives a per-node device-bind set. The shell runs under `staff_t`; the Flatpak launcher invokes `bwrap` to construct the application's sandbox; bwrap (running under `staff_t`) assembles the sandbox root from a series of bind mounts. Flatpak 1.18 or later derives the device-bind set for the `dri` permission from the host's device inventory and includes the AMD compute device node `/dev/kfd` (kernel fusion driver, character device, SELinux type `hsa_device_t`, host-default mode `0666 root:render`) alongside the render nodes under `/dev/dri/` whenever the node exists. bwrap `stat(2)`s every bind source before mounting it; the `stat` on `/dev/kfd` is the access on which the functional rule fires. Earlier Flatpak releases did not include `/dev/kfd` in the `dri` bind set, which is why the gap surfaces as a launch regression on the first cold start after a Flatpak upgrade across the 1.18 boundary rather than as a long-standing failure.

The end-state depends on two stock packages on Fedora 44: `flatpak` (provides the per-application launch path; the version boundary 1.18 is the trigger discriminator) and `bubblewrap` (provides `/usr/bin/bwrap`, the sandbox-construction binary that performs the `stat(2)` call on which the functional rule fires). The topic is out of scope on hosts whose desktop role-stack is `unconfined_u:unconfined_r:unconfined_t` (stock policy grants the equivalent device surface to `unconfined_t`), and on hosts where a future stock-policy update has shipped a `staff_t → bwrap_t` type-transition. On hosts whose kernel does not expose `/dev/kfd` (no AMD GPU, or the `amdgpu` driver not loaded — including typical headless cloud nodes), the gap is unreachable: Flatpak only binds existing nodes. The role's preflight emits an informational note on a node-less host but does not abort, on the rationale that pre-applying the policy patch protects a future hardware change; the rule is inert while the target type has no instance.

### Topic shape — single-rule stock-policy gap-patch

This topic occupies the same structural shape as the [Flatpak audio sandbox](flatpak-audio-sandbox.md) sibling topic: the end-state is a single CIL module loaded at priority 400 that contains exactly one `(allow ...)` rule and patches one pre-existing stock-policy gap without declaring any new SELinux types, without binding any new attributes, without shipping a systemd unit or drop-in, without altering file labels, and without restarting any service. The modify stage is one `semodule -X 400 -i` call, the verify discipline asserts the single allow surface is present in the loaded policy, and the rollback action is one `semodule -X 400 -r` call. The load-bearing difference from the sibling: the denial this topic patches is suppressed by a stock `dontaudit` rule, so the audit stream is empty in both the broken and the healthy state, and the verify discipline substitutes a functional `stat` probe for the AVC-clean assertion (see §"AVC posture").

### Functional rule

Stock targeted policy on Fedora 44 ships **zero** allow rules on `staff_t × hsa_device_t : chr_file` — `sesearch -A -s staff_t -t hsa_device_t -c chr_file` returns empty on an unpatched host. The bwrap `stat(2)` call on the bind source `/dev/kfd` returns `EACCES`; bwrap surfaces the failure on its standard error stream as `bwrap: Can't get type of source /dev/kfd: Permission denied` (verbatim — the wording is upstream-fixed in the bubblewrap source and is not locale-translated) and exits non-zero before the application's main binary is executed. The functional symptom is a clean abort at sandbox-construction time, not a partial start: no application code runs, and the next launch attempt re-runs the same code path. DAC is not the gate: the node's host-default mode is world-readable-writable (`0666`), so the SELinux check is the only refusing layer.

The single allow rule grants `getattr` only. bwrap needs the `stat(2)` metadata read to proceed; the bind mount itself and the in-sandbox use by an application that does not run ROCm compute workloads require no `read`, `write`, `open`, or `ioctl` on the node from `staff_t`. The minimal grant keeps compute-device access from the desktop domain closed; the deliberately-narrow first permission and the re-exercise discipline after loading it follow the [SELinux denial sequence-masking](../../explanation/selinux-denial-sequence-masking.md) pattern — the kernel reports a multi-permission access vector one missing permission at a time, so the canonical end-state is established by granting the observed minimum and re-running the launch path to confirm no subsequent permission surfaces.

### Audit-silence property

The `getattr` denial on the device node is suppressed by a stock `dontaudit` rule: `ausearch -m avc -ts recent` returns no record for the failing launch, and the operator's audit channel stays empty while every `dri`-holding application fails to start. The detection chain on an affected host runs without the audit stream: `stat /dev/kfd` (or `ls -lZ /dev/kfd`) from the `staff_t` shell fails with `EACCES`; the role-switched read `sudo -r sysadm_r -t sysadm_t ls -lZ /dev/kfd` shows the `hsa_device_t` label; `sesearch -A -s staff_t -t hsa_device_t -c chr_file` (role-switched) returns empty and explains the refusal. The trap shape — a kernel refusal whose policy has chosen not to advertise it, diagnosed by re-running the read from a broader domain — is documented in [The unlabeled_t silent EACCES trap](../../explanation/unlabeled-t-silent-eacces.md); the trap fires here on a known stock type rather than on the unknown-type sentinel, but the symptom contradiction (shell-level `EACCES`, empty audit channel) and the role-transition diagnostic are the same.

### Custom CIL module

Path: `/root/flatpak_kfd_device.cil`. Loaded at priority 400 via `semodule -X 400 -i /root/flatpak_kfd_device.cil`.

```cil
;; flatpak_kfd_device.cil — patches one stock-policy gap on Fedora 44
;; that affects the bwrap sandbox-construction step of Flatpak
;; applications holding the dri device permission, on hosts running
;; Flatpak 1.18 or later whose kernel exposes the AMD compute device
;; node /dev/kfd, where the desktop login is mapped to the confined
;; SELinux user staff_u and bwrap runs in the source domain staff_t
;; (no stock type-transition to bwrap_t).
;;
;; Functional rule: Flatpak 1.18+ includes /dev/kfd (type hsa_device_t)
;; in the device-bind set derived from the dri permission; bwrap
;; stat(2)s the bind source before mounting it. Stock policy carries
;; zero allow rules on staff_t × hsa_device_t : chr_file, so the stat
;; fails with EACCES (dontaudit-suppressed, no AVC record) and the
;; sandbox construction aborts before the application starts. The
;; getattr-only grant keeps compute access from staff_t closed.
(allow staff_t hsa_device_t (chr_file (getattr)))
```

The module body declares no `(type ...)`, no `(typeattributeset ...)`, no `(roletype ...)`, no `(typetransition ...)`, and no `(typepermissive ...)`. Both the source type (`staff_t`) and the target type (`hsa_device_t`) are stock-policy types shipped by the targeted policy on Fedora 44. The single `getattr` permission on class `chr_file` is the only access surface this module grants; secondary surfaces (`read write open ioctl` on the node — the ROCm compute path) are deliberately not pre-granted. An operator who observes a secondary refusal after the deploy (an application that legitimately runs GPU compute from a `dri`-only manifest) extends the same module additively rather than authoring a parallel one — but the canonical end-state for desktop applications that use the `dri` permission for hardware-accelerated rendering is the single-rule `getattr` form, and no subsequent permission surfaces on the canonical launch path.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that the allow surface is absent in the currently loaded policy: `sesearch -A -s staff_t -t hsa_device_t -c chr_file -p getattr` returns empty. The role skips the push as a clean no-op when the allow surface is already present in the loaded policy, on the assumption that a future stock-policy update has shipped the equivalent grant and the workaround is no longer required.
2. If the module `flatpak_kfd_device` is already installed at priority 400, copy the previously installed CIL source from `/var/lib/selinux/targeted/active/modules/400/flatpak_kfd_device/cil` to `/root/flatpak_kfd_device.cil.pre-reinstall` as a re-install audit anchor.
3. Write the CIL source at `/root/flatpak_kfd_device.cil` with explicit `0644 root:root`.
4. `semodule -X 400 -i /root/flatpak_kfd_device.cil`.
5. Post-load re-probe: the `sesearch` call of step 1 must now return a non-empty result (one allow line).

The role does **not** call `restorecon` (no file labels are altered), does **not** call `semanage fcontext`, does **not** restart any service, and does **not** invoke `flatpak run` of its own. SELinux access checks evaluate the loaded policy on each system call, so a subsequent `flatpak run` from the operator's shell picks up the new allow rule without restart. No host reboot is required.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain (`semodule`, `sesearch`) transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### File modes

This topic ships exactly one operator-installed file:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/flatpak_kfd_device.cil` | `0644` | `root:root` | (host-default for `/root/`, typically `admin_home_t`) |

The explicit `0644` is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Checks that need the policy store (`semodule`, `sesearch`) are gated behind a `sysadm_t` domain check and reported as `SKIP` rather than as drift when invoked from a non-privileged context; the functional `stat` check is gated the opposite way — it proves the end-state only from a `staff_t` shell (a `sysadm_t` read succeeds regardless of the topic-owned rule) and is reported as `SKIP` from any other domain or on a host without the device node. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_flatpak_kfd_device/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence and the installed Flatpak version (`rpm -q flatpak bubblewrap`, `flatpak --version` — the 1.18 boundary is the trigger discriminator), the operator-installed Flatpak inventory with a count of entries whose permissions column carries the `dri` substring (the per-application discrimination signal), the device-node state (`/dev/kfd` existence, plus the label read attempt from the current domain — a failing `ls -lZ` from `staff_t` on an existing node is the live symptom signal), the operator's runtime SELinux context via `id -Z`, the priority-400 module slot via `semodule -lfull`, and the functional-rule allow surface via `sesearch -A -s staff_t -t hsa_device_t -c chr_file`. The probe prints an explicit note that the AVC stream carries no record for this class in either state (the denial is `dontaudit`-suppressed) and therefore deliberately runs no `ausearch` stage. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_flatpak_kfd_device/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for domain-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `flatpak_kfd_device` module installed at priority 400 | `yes` |
| Functional allow `staff_t × hsa_device_t : chr_file getattr` present | `yes` |
| `stat /dev/kfd` from the `staff_t` shell | succeeds (functional Ist-check; `SKIP` when the node is absent or the shell is not `staff_t`) |

There is no AVC-clean row: the denial this topic patches is `dontaudit`-suppressed and produces no audit record in either the broken or the healthy state, so an `ausearch`-based assertion would be vacuously green on an unpatched host. The functional `stat` row is the substitute — it exercises exactly the access bwrap performs at sandbox-construction time, from exactly the domain bwrap runs in. Where any liveness inspection is needed, the verify uses the `[[ -d /proc/${pid} ]]` form rather than `kill -0`, because cross-user `kill -0` from a `staff_t` shell against a foreign-uid PID returns `EPERM` rather than `ESRCH` and would misreport a live process as dead. The verify does not invoke a `flatpak run` of its own.

### AVC posture

The AVC posture of this topic is the inverse of its siblings: the audit stream is **not** a signal surface for this class. On an unpatched host whose desktop user launches a `dri`-holding Flatpak application, the launch aborts at bwrap with the stderr line quoted in §"Functional rule" — and the audit stream stays empty, because the `getattr` denial is covered by a stock `dontaudit` rule. On a patched host the same filter is equally empty. An operator who pattern-matches "no AVC means no SELinux problem" misses this class entirely; the operational drift signal is the bwrap stderr line on application launch plus the failing `stat` from the `staff_t` shell, both of which the verify's functional row covers. The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md) still applies to every other class on the host; for suppressed classes, `sesearch --dontaudit` from the role-switched context is the tool that explains the empty channel.

Drift signals on an applied host: a recurrence of the bwrap stderr line `Can't get type of source /dev/kfd` indicates the functional rule has been rolled back or pre-empted; the verify's `rule_present` and `kfd_stat_from_staff_t` rows catch both. A launch failure naming a **different** bind source is not this topic's drift and is investigated independently.

The role's modify stage is idempotent. The CIL source is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `semodule -X 400 -i` install task is wrapped in a `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_kfd_device/cil` guard, so a re-run on a host already carrying the module reports `changed=false`. The role runs no `restorecon`, no `semanage fcontext`, no `systemctl restart`, and no handler. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery is a single-stage rollback. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r flatpak_kfd_device
```

Post-rollback, `sesearch -A -s staff_t -t hsa_device_t -c chr_file` returns empty and the module slot at `/var/lib/selinux/targeted/active/modules/400/flatpak_kfd_device/` is removed. The CIL source at `/root/flatpak_kfd_device.cil` is **not** removed by `semodule -r`; operators who want to also remove the source file do so explicitly. Boot-failure risk for this topic is structurally zero — the single allow rule grants a metadata read on a user-process-side launch step performed by bwrap from a desktop role that is not active during the boot sequence; the rule is not reachable from `init_t` and introduces no namespace or transition effect. The worst-case post-rollback symptom is that `dri`-holding Flatpak applications stop launching again on hosts that expose `/dev/kfd`.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [The unlabeled_t silent EACCES trap](../../explanation/unlabeled-t-silent-eacces.md) — the same audit-silence trap shape fires here on a known stock type: a `dontaudit`-suppressed denial produces a shell-level `EACCES` with an empty audit channel, and the canonical diagnostic is re-running the read from a role-transitioned domain.
- [SELinux denial sequence-masking](../../explanation/selinux-denial-sequence-masking.md) — the rationale for granting the observed minimum (`getattr` only) and re-exercising the launch path after the load instead of pre-granting a speculative permission set.
