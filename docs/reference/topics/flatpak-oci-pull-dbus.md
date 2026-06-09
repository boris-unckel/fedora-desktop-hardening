<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Flatpak OCI-pull D-Bus session-bus surface

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 that affects the `flatpak install --system` admin pipeline when the operator login is mapped to the confined SELinux user `staff_u`, the install command is issued from a role-switched `sysadm_t` context, and the targeted Flatpak remote is OCI-typed (URL prefixed `oci+`, the canonical example being the stock `fedora` remote at `oci+https://registry.fedoraproject.org`). The deliverable is a single topic-owned CIL module loaded at priority 400 carrying exactly one `(allow ...)` rule that keeps the OCI pre-pull access-token request operational. The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/flatpak/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** new SELinux type, **no** new SELinux attribute binding, **no** file-context mapping, and **no** `restorecon` invocation; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

This topic does **not** cover the Flatpak configuration model (`/etc/flatpak/`, `~/.local/share/flatpak/`, the per-app `~/.var/app/<appid>/` sandbox tree, the OCI manifest format, the ostree commit/delta format, the `flatpak override` permission model, the `flatpak-portal` interaction surface), the `flatpak-oci-authenticator` D-Bus service interface (its method set, signal set, OCI access-token semantics), the choice between OCI-typed and ostree-typed remotes as a deployment-policy decision, the `flatpak install --user` path (the user-bus install path runs in `staff_t` against the operator's own `/run/user/${uid}/bus` and is governed by a different stock-policy surface), the `staff_u`-mapping deployment decision (the prerequisite Foundation layer owns this), the per-Flatpak-app sandbox-permission posture (filesystem, socket, device permissions in the application's `org.freedesktop.Flatpak` portal-permission table — that surface is owned by the application-specific Topic articles), Flatpak-side workarounds (for example, switching the remote from OCI to ostree to dodge the gap, or installing from `unconfined_u` to dodge the `sysadm_t` source-domain mismatch), the `domain_can_mmap_files` SELinux boolean (orthogonal — no relation to the allow rule in this topic), and the `systemd-analyze security` numeric score model (this topic ships no systemd service unit and the score model does not apply).

## End-state configuration

The end-state ships exactly one operator-installed file: a CIL source under `/root/`. The source is loaded into the system's targeted-policy module store at priority 400 via `semodule -X 400 -i`. The single allow rule in the source patches one pre-existing stock-policy gap; both the source type (`sysadm_t`) and the target type (`unconfined_dbusd_t`) are stock-policy types shipped by the targeted policy on Fedora 44 and are not declared by this module.

### Topic identity

The pipeline under hardening is the chain a desktop operator triggers when running, for example, `sudo -r sysadm_r -t sysadm_t flatpak install -y --system fedora <appid>`. The operator's interactive shell (`staff_t` under the `staff_u` user-mapping) runs `sudo -r sysadm_r -t sysadm_t flatpak …`, which lands in the role-switched `sysadm_t` admin context. The `flatpak` CLI (running under `sysadm_t`) consults the configured remote, identifies the remote as OCI-typed, and lazy-spawns a pre-pull token request via the `flatpak-oci-authenticator` D-Bus service. The token-request path opens the per-user D-Bus session bus of `uid=0` at `/run/user/0/bus` (SELinux type `unconfined_dbusd_t`) by calling `connectto` on the bus socket. The single allow rule in this topic is the minimal allow surface required to keep the OCI-typed `flatpak install --system` admin pipeline functional.

The end-state depends on one stock package on Fedora 44: `flatpak` (provides `/usr/bin/flatpak` and the `flatpak-oci-authenticator` D-Bus service definition under `/usr/share/dbus-1/services/`; the SELinux type `flatpak_t` for the binary is bound by stock-policy file_contexts but is **not** referenced by this topic — the source domain in the functional rule is `sysadm_t`, the operator's role-switched admin context, because the AVC fires on the `flatpak` invocation made from the operator's shell, not on a confined transition into `flatpak_t`). The topic does not require an additional package install; the role's preflight asserts the package is present and aborts fail-fast on a missing entry. The topic is out of scope on hosts whose admin role is `unconfined_u:unconfined_r:unconfined_t` (stock policy already grants the equivalent admin-bus connect surface to `unconfined_t`), on hosts whose admin operator runs `flatpak install --user` (the user-bus path runs in `staff_t` and uses the operator's own `/run/user/${uid}/bus`, which is governed by a different stock-policy surface), and on hosts whose Flatpak remote inventory contains no OCI-typed entries (the gap is unreachable; the role's preflight emits an informational note but does not abort, on the rationale that pre-applying the policy patch protects future remote additions).

### Topic shape — single-rule stock-policy gap-patch

This topic occupies a structurally different shape than the system-services topics in this tree. The end-state is **not** "a daemon runs in a hardened domain". The end-state is a single CIL module loaded at priority 400 that contains exactly one `(allow ...)` rule and patches one pre-existing stock-policy gap without declaring any new SELinux types, without binding any new attributes, without shipping a systemd unit or drop-in, without altering file labels, and without restarting any service. Every downstream subsection is framed by this structural fact: the modify stage is one `semodule -X 400 -i` call, the verify discipline asserts the single allow surface is present in the loaded policy, and the rollback action is one `semodule -X 400 -r` call.

### Functional rule

The single allow rule patches the gap that breaks the OCI-typed `flatpak install --system` admin pipeline under `sysadm_t`-issued installs. Stock targeted policy on Fedora 44 ships **no** allow on `sysadm_t × unconfined_dbusd_t : unix_stream_socket connectto` for the role-switched `staff_u → sysadm_r → sysadm_t` admin path. The token-request `connectto` call returns `EACCES`; the `flatpak` CLI surfaces the error to the operator as a generic permission-denied message (the exact wording is locale-dependent and is not reproduced here) and aborts before the OCI manifest fetch is even attempted — no bytes of the application payload are pulled. The functional symptom is a clean abort, not a partial install: the local Flatpak repository remains untouched and the next install attempt re-runs the same code path.

### Remote-type discrimination

The gap is reachable only on Flatpak remotes of **type OCI**. Flatpak supports two remote-payload formats: the historical **ostree** format (the canonical example being the public Flathub remote at `https://dl.flathub.org/repo/`, where applications are stored as ostree commits and deltas) and the newer **OCI** format (the canonical example being the Fedora-shipped `fedora` remote at `oci+https://registry.fedoraproject.org`, where applications are stored as OCI container images with a per-application authenticator hand-off). The token-request D-Bus call is issued only on the OCI code path, by design — ostree-format remotes do not negotiate per-application access tokens and therefore never open the `uid=0` session bus. The practical implication for an operator: an admin install of a Flathub-hosted application from `sysadm_t` succeeds against stock policy without this topic; an admin install of a Fedora-OCI-hosted application from `sysadm_t` fails. The role's preflight inspects each configured remote and reports whether at least one OCI-typed remote is present; the no-OCI-remote case is informational, not a deploy blocker — a future remote addition still benefits from a pre-applied policy patch.

### Custom CIL module

Path: `/root/flatpak_oci_pull_dbus.cil`. Loaded at priority 400 via `semodule -X 400 -i /root/flatpak_oci_pull_dbus.cil`.

```cil
;; flatpak_oci_pull_dbus.cil — patches one stock-policy gap on Fedora 44
;; that affects `flatpak install --system` from OCI-typed remotes when the
;; install is issued from sysadm_t (the role-switched admin context for
;; staff_u-mapped operators).
;;
;; Functional rule: OCI-typed remotes negotiate a pre-pull access token
;; via the flatpak-oci-authenticator D-Bus service, which connects to the
;; uid=0 D-Bus session bus at /run/user/0/bus (type unconfined_dbusd_t).
;; Stock policy lacks the connectto allow on the bus socket for sysadm_t,
;; so the install aborts before the OCI manifest fetch is attempted.
;; ostree-typed remotes are unaffected (no token-request path).
(allow sysadm_t unconfined_dbusd_t (unix_stream_socket (connectto)))
```

The module body declares no `(type ...)`, no `(typeattributeset ...)`, no `(roletype ...)`, no `(typetransition ...)`, and no `(typepermissive ...)`. Both the source type (`sysadm_t`) and the target type (`unconfined_dbusd_t`) are stock-policy types shipped by the targeted policy on Fedora 44. The single `connectto` permission is the only access surface this module grants; secondary surfaces (`unix_stream_socket {read write}`, `dbus send_msg`) are deliberately not pre-granted. An operator who observes a secondary AVC after the deploy on a different host extends the same module additively rather than authoring a parallel one — but the canonical end-state on Fedora 44 with the current `flatpak`/`fedora`-remote pairing is the single-rule form, and no secondary AVC fires on the canonical hardware/software pairing in this tree.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that the allow surface is absent in the currently loaded policy: `sesearch -A -s sysadm_t -t unconfined_dbusd_t -c unix_stream_socket -p connectto` returns empty. The role aborts as a no-op (return code reported to the operator, not as a failure) when the allow surface is already present in the loaded policy, on the assumption that a future stock-policy update has shipped the equivalent grant and the workaround is no longer required.
2. If the module `flatpak_oci_pull_dbus` is already installed at priority 400, copy the previously installed CIL source from `/var/lib/selinux/targeted/active/modules/400/flatpak_oci_pull_dbus/cil` to `/root/flatpak_oci_pull_dbus.cil.pre-reinstall` as a re-install audit anchor.
3. Write the CIL source at `/root/flatpak_oci_pull_dbus.cil` with explicit `0644 root:root`.
4. `semodule -X 400 -i /root/flatpak_oci_pull_dbus.cil`.
5. Post-load re-probe: the `sesearch` call of step 1 must now return a non-empty result (one allow line).

The role does **not** call `restorecon` (no file labels are altered), does **not** call `semanage fcontext` (no file-context mappings are added), does **not** restart any system service, does **not** restart `dbus-broker` or any per-user D-Bus session bus, and does **not** kick off a `flatpak install` of its own. SELinux access checks evaluate the loaded policy on each system call, so a subsequent `flatpak install --system` from the operator's shell picks up the new allow rule without restart and the operator does not need to restart the per-user session bus or any system service after the deploy. No host reboot is required.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain and the `flatpak install --system` admin command transit through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### File modes

This topic ships exactly one operator-installed file:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/flatpak_oci_pull_dbus.cil` | `0644` | `root:root` | (host-default for `/root/`, typically `admin_home_t`) |

The explicit `0644` is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both run from a `staff_t`-confined shell for the staff-side checks; checks that need `sysadm_t` are reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_flatpak_oci_pull_dbus/files/probe.sh
```

The probe reports state without judging it. It enumerates package presence (`rpm -q flatpak`), the operator-configured Flatpak remote inventory (`flatpak remotes --columns=name,url,collection` with per-remote OCI-vs-ostree discrimination based on the URL prefix `oci+`), the operator's runtime SELinux context via `id -Z` (the canonical applicability anchor — `staff_u:staff_r:staff_t` is the matching mapping), the priority-400 module slot via `semodule -lfull | grep -wE '^[ ]*400.*flatpak_oci_pull_dbus'`, the functional-rule allow surface via `sesearch -A -s sysadm_t -t unconfined_dbusd_t -c unix_stream_socket -p connectto`, and the AVC stream since boot via `ausearch -m AVC,USER_AVC -ts boot` filtered for `sysadm_t.*unconfined_dbusd_t.*unix_stream_socket` and `path="/run/user/0/bus"`. The `semodule`, `sesearch`, and `ausearch` queries are gated behind a `sysadm_t` domain check and reported as `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_flatpak_oci_pull_dbus/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `flatpak_oci_pull_dbus` module installed at priority 400 | `yes` |
| Functional allow `sysadm_t × unconfined_dbusd_t : unix_stream_socket connectto` present | `yes` |
| Functional-class AVC denials since boot | `0` |

Liveness probes are not part of the canonical Soll/Ist comparison; the policy-store reads are sufficient. Where any liveness inspection is needed, the verify uses the `[[ -d /proc/${pid} ]]` form rather than `kill -0`, because `kill -0` against a foreign-uid PID from a `staff_t` shell returns `EPERM` rather than `ESRCH` and would misreport a live process as dead. The verify does not invoke a `flatpak install` of its own. Asserting the AVC-clean state requires a host that has already issued at least one `flatpak install --system` from an OCI remote since boot; the verify reports the AVC-clean count as zero on a host that has not yet exercised the path, which is also the expected end-state value (the verify does not distinguish "zero because soaked" from "zero because untriggered" — the probe's remote-inventory output is the applicability signal).

### AVC posture

The AVC posture has two parts. On a soaked, `staff_u`-mapped host whose admin operator has issued at least one `sudo -r sysadm_r -t sysadm_t flatpak install -y --system <oci-remote> <appid>` since boot **without** the workaround applied, the audit stream carries one or more `denied  { connectto }` records of class `sysadm_t × unconfined_dbusd_t : unix_stream_socket`, each with `path="/run/user/0/bus"`, `scontext` resolving to `staff_u:sysadm_r:sysadm_t`, and `tcontext` resolving to `unconfined_u:unconfined_r:unconfined_dbusd_t`. The records typically appear as a small cluster of two per install attempt: one for the `flatpak` parent process with `comm="flatpak"`, and one for the dconf-worker child process with the hex-encoded `comm` value `64636F6E6620776F726B6572` (the audit subsystem hex-encodes `comm` values containing spaces; the decoded English string is `dconf worker`). These are the records the functional rule closes. On the same workload with the workaround applied, the same filter returns an empty result. Secondary-class records (for example, `unix_stream_socket {read write}` on the same bus or `dbus send_msg` at the D-Bus method-call layer) are not observed on the canonical Fedora-44 software stack documented in this tree — the single `connectto` allow is sufficient end-to-end. An operator who observes a secondary class on a different host extends the same module additively rather than authoring a parallel module.

Drift signals on an applied host: any fresh `denied  { connectto }` record of class `sysadm_t × unconfined_dbusd_t : unix_stream_socket` with `path="/run/user/0/bus"` indicates the functional rule has been rolled back or a stock-policy update has shipped a `neverallow` that pre-empts the priority-400 grant; either case is operator-investigation. A surge of `denied` records of any other class involving `sysadm_t` or `unconfined_dbusd_t` is **not** drift caused by this topic and is investigated independently — most commonly a `flatpak` upstream version bump that introduces a new D-Bus interaction not covered by the single rule.

The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. The CIL source is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `semodule -X 400 -i` install task is wrapped in a `creates: /var/lib/selinux/targeted/active/modules/400/flatpak_oci_pull_dbus/cil` guard, so a re-run on a host already carrying the module reports `changed=false`. The role runs no `restorecon`, no `semanage fcontext`, no `systemctl restart`, and no handler. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery is a single-stage rollback. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r flatpak_oci_pull_dbus
```

Post-rollback, `sesearch -A -s sysadm_t -t unconfined_dbusd_t -c unix_stream_socket -p connectto` returns empty. The module slot at `/var/lib/selinux/targeted/active/modules/400/flatpak_oci_pull_dbus/` is removed. The CIL source at `/root/flatpak_oci_pull_dbus.cil` is **not** removed by `semodule -r` (it is the operator's source artefact, not part of the module slot); operators who want to also remove the source file do so explicitly with `rm -f /root/flatpak_oci_pull_dbus.cil`. Boot-failure risk for this topic is structurally zero — the single allow rule grants access on a user-process-side D-Bus stream-socket connect from an admin role that is not active during the boot sequence; the rule is not reachable from `init_t`, does not introduce an `nnp_transition` constraint, and does not introduce a `mount_t` namespace effect.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

This topic does not cross-link any pattern article. The single allow rule patches a narrowly-scoped gap on a user-process-side SELinux type pair (`sysadm_t`, `unconfined_dbusd_t`) reached only from the operator's role-switched admin shell during an OCI-typed `flatpak install --system` invocation. The rule does not exercise the kernel NoNewPrivileges-transition constraint, the systemd `SystemCallFilter` privilege-drop sequence, the systemd `PrivateMounts` implicit-enable, the systemd `ReadWritePaths` runtime race, the cross-user liveness-probe trap, or any other cross-cutting hardening pattern documented in this tree. The deploy ships no systemd unit, no drop-in, no file-label change, and introduces no new SELinux type — the priority-400 module mechanism described in the Foundation layer carries the entire deploy.
