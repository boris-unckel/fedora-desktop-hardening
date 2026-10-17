<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Flatpak audio sandbox bind-mount surface

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic covers one allow surface in the SELinux targeted policy on Fedora 44 that the bwrap sandbox-construction step of every Flatpak application holding the `pulseaudio` socket permission depends on, on hosts where the operator login is mapped to the confined SELinux user `staff_u` and bwrap inherits the desktop role-stack `staff_u:staff_r:staff_t` (stock targeted policy on Fedora 44 ships no type-transition `staff_t → bwrap_t` for `/usr/bin/bwrap`). The stock policy supplies the surface. The deliverable of this topic is the assertion that it is present, plus the removal of a priority-400 module that would duplicate it. The end-state ships **no** SELinux module, **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** file-context mapping, and **no** `restorecon` invocation.

This topic does **not** cover the Flatpak configuration model (`/etc/flatpak/`, `~/.local/share/flatpak/`, the per-app `~/.var/app/<appid>/` sandbox tree, the Flatpak manifest format, the `flatpak override` permission model, the `flatpak-portal` interaction surface), the bwrap sandbox-construction sequence beyond the single audio-bind-mount step (other `mounton` targets, the `filesystem remount` family, the `var_lib_t:file execute` family for runtime-binary execution, the `sysctl_t:file write` for bwrap-internal `oom_score_adj` updates), the per-application Flatpak-permission posture (owned by the application-specific Topic articles), the PulseAudio or PipeWire user-side audio stack, the `staff_u`-mapping deployment decision (the prerequisite Foundation layer owns this), the absence of a stock `staff_t → bwrap_t` type-transition as a hardening goal in itself, Flatpak-side workarounds such as `flatpak override --nosocket=pulseaudio` (the application's audio permission is intentional), and the `systemd-analyze security` score model (this topic ships no service unit).

## End-state configuration

### Topic identity

The pipeline is the chain a desktop operator triggers when running, for example, `flatpak run <appid>` from the operator's interactive shell against a Flatpak application whose manifest declares `--socket=pulseaudio` (or `--device=all`, which subsumes audio-device access). The shell runs under `staff_t`; the Flatpak launcher invokes `bwrap` to construct the application's sandbox; bwrap, still in `staff_t`, executes a series of bind-mounts that assemble the sandbox root, and one of them maps the host's `/dev/snd` directory (SELinux type `device_t`) to `/newroot/dev/snd` inside the sandbox so the application can reach ALSA devices through the per-user PulseAudio or PipeWire daemon.

The end-state depends on two stock packages on Fedora 44: `flatpak` (provides `/usr/bin/flatpak`) and `bubblewrap` (provides `/usr/bin/bwrap`, which performs the `mount(2) MS_BIND` call). The SELinux types `flatpak_t` and `bwrap_t` are bound by stock file_contexts but are **not** referenced by this topic — the source domain is `staff_t`, because bwrap inherits the launching shell's domain. The role's preflight asserts both packages are present and aborts fail-fast on a missing entry. The topic is out of scope on hosts whose desktop role-stack is `unconfined_u:unconfined_r:unconfined_t`, and on hosts where a stock `staff_t → bwrap_t` type-transition makes bwrap leave `staff_t`.

### Functional rule

The bind-mount needs the allow `staff_t × device_t : dir mounton`. Without it, the bwrap `mount(2)` call with `MS_BIND` from `/oldroot/dev/snd` onto `/newroot/dev/snd` returns `EACCES`; bwrap reports `bwrap: Can't bind mount /oldroot/dev/snd on /newroot/dev/snd: Permission denied` (verbatim, not locale-translated) and exits before the application's main binary runs. The desktop user sees a generic "failed to start"; no application code runs and nothing is written.

The stock targeted policy grants the rule through the interface call `dev_mounton(staff_t)` in `policy/modules/roles/staff.te`, which expands to `allow staff_t device_t:dir mounton;`. On Fedora 44 the call ships with `selinux-policy` 44.2 and later. The grant is part of the loaded policy as soon as that package is installed; no module, no reload, and no restart is involved.

### Permission-set discrimination

Only Flatpak applications that declare the `pulseaudio` socket permission (or `--device=all`) perform the audio bind-mount and depend on the rule. Audio-silent applications never reach the step. On a host whose policy lacks the rule, an application family that mixes audio-using and audio-silent members shows a partial-failure surface: some launch, others abort at bwrap, and the discriminating factor is the per-application permission declaration. The role's preflight counts installed applications whose permissions column contains `pulseaudio`; zero is reported as an informational note, and the rule is asserted regardless.

### Modify stage

The role ships no policy. Its modify stage runs in this order:

1. If a module named `flatpak_audio_sandbox` is installed at priority 400 (module slot `/var/lib/selinux/targeted/active/modules/400/flatpak_audio_sandbox/`), remove it with `semodule -X 400 -r flatpak_audio_sandbox`. Such a module carries only the rule the stock policy already grants.
2. Remove the CIL source files `/root/flatpak_audio_sandbox.cil` and `/root/flatpak_audio_sandbox.cil.pre-reinstall` where present.
3. Assert `sesearch -A -s staff_t -t device_t -c dir -p mounton` returns the allow line. A missing line fails the role with a pointer to the policy-package requirement.

The role does not call `restorecon`, `semanage fcontext`, or `systemctl`, and does not run `flatpak` itself. The `staff_u → sysadm_r → sysadm_t` role-switch surface the SELinux toolchain transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md); the priority-400 module store the removal step reads is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Checks that need the policy store (`semodule`, `sesearch`, `ausearch`) are gated behind a `sysadm_t` domain check and reported as `SKIP` from a `staff_t` shell.

### Probe

```bash
bash ansible/roles/topic_flatpak_audio_sandbox/files/probe.sh
```

The probe reports package presence (`rpm -q flatpak bubblewrap`), the Flatpak inventory (`flatpak list --columns=application,permissions`) with the count of entries whose permissions contain `pulseaudio`, the operator's runtime SELinux context (`id -Z`; `staff_u:staff_r:staff_t` is the matching mapping), the priority-400 module slot (`semodule -lfull | grep -wE '^[ ]*400.*flatpak_audio_sandbox'`), the allow surface (`sesearch -A -s staff_t -t device_t -c dir -p mounton`), and the AVC stream since boot filtered for `staff_t.*device_t.*dir` and `path="/newroot/dev/snd"`. It exits `0` regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_flatpak_audio_sandbox/files/verify.sh
```

The verify exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `flatpak_audio_sandbox` module installed at priority 400 | `no` |
| Allow `staff_t × device_t : dir mounton` present in the loaded policy | `yes` |
| Functional-class AVC denials since boot | `0` |

`rule_present` is the load-bearing check. It does not care where the rule comes from; it fails when a policy update loses the grant, which is the event this topic exists to detect. The AVC count is zero both on a host that has launched an audio-permission-holding application since boot and on one that has not; the probe's inventory output is the applicability signal. The verify runs no liveness probe and no `flatpak run`.

### AVC posture

On a `staff_u`-mapped host whose loaded policy lacks the rule, every launch of a Flatpak application declaring the `pulseaudio` permission produces one `denied  { mounton }` record of class `staff_t × device_t : dir`, with `path="/newroot/dev/snd"`, `comm="bwrap"`, `scontext` resolving to `staff_u:staff_r:staff_t`, and `tcontext` resolving to `system_u:object_r:device_t`; bwrap aborts on the first denied bind-mount, so one record appears per launch attempt. On the end-state the same filter returns empty. Secondary classes (`device_t:chr_file {read write open}` on individual ALSA nodes, `device_t:filesystem remount`) are not observed on the PulseAudio- or PipeWire-mediated audio path that Flatpak applications use.

A fresh `denied  { mounton }` record of the functional class on an applied host means the loaded policy no longer carries the grant. Records of other classes involving `staff_t` or `device_t` are not caused by this topic and are investigated independently. The diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

### Recovery

When `rule_present` fails:

1. Check the policy package: `rpm -q selinux-policy-targeted`. Below 44.2 on Fedora 44, update it; the grant arrives with the package.
2. When the current package lacks the grant, the stock policy has lost it. Restore the surface with a priority-400 module carrying the single rule, under a name other than `flatpak_audio_sandbox` (the role removes a module of that name), and report the regression to the policy maintainers:

   ```cil
   ;; staff_device_mounton.cil
   (allow staff_t device_t (dir (mounton)))
   ```

   ```bash
   sudo -r sysadm_r -t sysadm_t semodule -X 400 -i staff_device_mounton.cil
   ```

   `rule_present` turns green again with the module loaded. Remove the module with `semodule -X 400 -r staff_device_mounton` once a policy update restores the stock grant.

Boot-failure risk for this topic is structurally zero: the rule concerns a user-process-side bind-mount step performed by bwrap from a desktop role that is not active during boot, is not reachable from `init_t`, introduces no `nnp_transition` constraint, and has no system-service namespace effect. The worst-case symptom of a missing rule is that audio-permission-holding Flatpak applications do not start.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The rule concerns a user-process-side SELinux type pair (`staff_t`, `device_t`) reached only from the operator's desktop shell during a Flatpak application launch whose manifest declares the `pulseaudio` permission. It does not exercise the NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting pattern documented in this tree.
