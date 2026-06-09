<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Wayland compositor shared-memory buffer surface

> **Prerequisite.** This topic assumes the Foundation layer has been applied. See [Bootstrap](../../tutorials/bootstrap-hardened-host.md).

## Scope

This topic documents one narrowly-scoped gap in the stock SELinux targeted policy on Fedora 44 that affects the desktop Wayland compositor on hosts where the operator login is mapped to the confined SELinux user `staff_u` and the compositor consequently runs in the `staff_t` domain (stock targeted policy on Fedora 44 ships no domain transition that would move the operator's session compositor out of `staff_t`). The gap is reached when the compositor maps a Wayland client's shared-memory (`wl_shm`) buffer — an anonymous `memfd` labelled `tmpfs_t` — into its own address space with read-write protection. The deliverable is a single topic-owned CIL module loaded at priority 400 carrying exactly one `(allow ...)` rule with two permissions that keeps client buffer composition operational under a `staff_t`-confined compositor. The end-state ships **no** systemd unit, **no** systemd drop-in, **no** `/etc/profile.d/` script, **no** configuration file under `/etc/`, **no** polkit rule, **no** sudoers fragment, **no** desktop-entry override, **no** new SELinux type, **no** new SELinux attribute binding, **no** file-context mapping, **no** SELinux boolean toggle, and **no** `restorecon` invocation; the artefact-shape negatives are stated here once because they are load-bearing for the role's idempotence claim and for the rollback posture.

This topic does **not** cover the Wayland protocol itself (the `wl_shm`, `wl_buffer`, or `wl_surface` interface specifications, the buffer-pool lifecycle, the damage-tracking model), the desktop compositor's configuration (`mutter` settings, GNOME session management, the compositor's own GPU-render or hardware-cursor-plane paths beyond the shared-memory buffer surface on which the functional rule fires), the per-application client toolkit (the choice between a Qt-Wayland, a GTK-Wayland, or an SDL-Wayland client — all `wl_shm`-using clients exercise the same compositor-side path), the X11 fallback session (`Xwayland`-mediated clients do not use the `wl_shm` `memfd` path and do not reach the gap), the `staff_u`-mapping deployment decision (the prerequisite Foundation layer owns this), the GPU direct-rendering buffer path (`dma-buf`-backed `wl_buffer` objects are labelled differently and are out of scope — this topic covers the software shared-memory path only), the `domain_can_mmap_files` SELinux boolean as a system-wide setting (the deliberate posture is that a targeted custom allow is scope-correct and the boolean stays off — see the permission-set composition section), and the `systemd-analyze security` numeric score model (this topic ships no systemd service unit and the score model does not apply).

## End-state configuration

The end-state ships exactly one operator-installed file: a CIL source under `/root/`. The source is loaded into the system's targeted-policy module store at priority 400 via `semodule -X 400 -i`. The single allow rule in the source patches one pre-existing stock-policy gap; both the source type (`staff_t`) and the target type (`tmpfs_t`) are stock-policy types shipped by the targeted policy on Fedora 44 and are not declared by this module.

### Topic identity

The pipeline under hardening is the buffer-attach path a Wayland client triggers every time it presents a frame through the software shared-memory route. A Wayland client running in the operator's session creates an anonymous `memfd` (SELinux type `tmpfs_t`), maps it as a `wl_shm` buffer pool, draws its frame into the pool, and passes the file descriptor to the compositor over the Wayland socket. The compositor — the GNOME compositor embedded in `gnome-shell`/`mutter`, running in `staff_t` because the operator login is mapped to `staff_u` — receives the descriptor and maps the pool into its own address space with `PROT_READ|PROT_WRITE` to composite the client's surface. The single allow rule in this topic is the minimal allow surface required to keep that compositor-side `mmap(2)` functional under a `staff_t`-confined compositor.

The end-state depends on the GNOME desktop stack on Fedora 44: `gnome-shell` and `mutter` provide the compositor process that performs the `mmap(2)` on which the functional rule fires. The SELinux domain of the compositor is `staff_t` — the operator's desktop role-stack — because the operator login is mapped to `staff_u` and stock targeted policy ships no domain transition that would move the session compositor into a dedicated domain. The topic does not require an additional package install; the role's preflight asserts the compositor packages are present and aborts fail-fast on a missing entry. The topic is out of scope on hosts whose desktop role-stack is `unconfined_u:unconfined_r:unconfined_t` (stock policy already grants the equivalent `tmpfs_t` file surface to `unconfined_t`), on hosts running an X11 session (the `Xwayland`-mediated clients do not use the `wl_shm` `memfd` path), and on hosts where a future stock-policy update has shipped the equivalent grant to `staff_t`. The functional class is not specific to one client toolkit: any `wl_shm`-using Wayland client under the `staff_u` mapping (Qt, GTK, or other) exercises the same compositor-side path, so the gap presents as a session-wide condition rather than a single-application one.

### Topic shape — single-rule stock-policy gap-patch

This topic occupies a structurally different shape than the system-services topics in this tree. The end-state is **not** "a daemon runs in a hardened domain". The end-state is a single CIL module loaded at priority 400 that contains exactly one `(allow ...)` rule — carrying two permissions on one access vector — and patches one pre-existing stock-policy gap without declaring any new SELinux types, without binding any new attributes, without toggling any SELinux boolean, without shipping a systemd unit or drop-in, without altering file labels, and without restarting any service. Every downstream subsection is framed by this structural fact: the modify stage is one `semodule -X 400 -i` call, the verify discipline asserts both permissions of the single allow surface are present in the loaded policy, and the rollback action is one `semodule -X 400 -r` call.

### Functional rule

The single allow rule patches the gap that breaks the compositor-side shared-memory buffer attach under a `staff_t`-confined compositor. When the compositor maps the client's `wl_shm` pool with `mmap(fd, ..., PROT_READ|PROT_WRITE, MAP_SHARED, ...)`, the kernel SELinux hook evaluates the access against the `staff_t × tmpfs_t : file` vector. Stock targeted policy on Fedora 44 grants `staff_t` the permissions `{ getattr ioctl lock open read }` on `tmpfs_t` files — enough to receive and read the descriptor, but not enough to complete the read-write mapping. The `mmap(2)` returns `EACCES`. The compositor reports the failure back to the client as a fatal protocol error; the client-visible symptom is the Wayland connection aborting with an invalid-argument error, and the client window never finishes presenting. The symptom is session-wide because the compositor serves every client over the same shared-memory path: a single missing permission on the compositor's domain blocks the buffer attach for whichever client next presents a software frame.

### Permission-set composition

The single allow vector requires two permissions, and both are stated explicitly in the rule because a read-write `mmap(2)` on a file decomposes into two distinct SELinux checks:

| Permission | Why it is required | Stock state for `staff_t × tmpfs_t : file` |
|---|---|---|
| `read` | The `PROT_READ` flag of the mapping. | Already granted by stock policy — **not** re-stated in this module. |
| `write` | The `PROT_WRITE` flag of the mapping translates into a `file:write` check. | Absent — granted by this module. |
| `map` | The `mmap(2)` call itself requires the `file:map` permission, independent of the protection flags. | Granted by stock policy only through the `domain` attribute under the `domain_can_mmap_files` boolean, which is **off** by default — so the stock allow does not apply, and this module grants `map` directly. |

The `map` permission warrants attention because it is the one a naive read of stock policy would assume is already covered: `sesearch -A -s staff_t -t tmpfs_t -c file -p map` does return a stock allow line, but the line is boolean-conditional on `domain_can_mmap_files`, and with the boolean off the conditional rule does not grant the access at runtime. The scope-correct fix is the targeted custom allow shown below, not a system-wide `setsebool domain_can_mmap_files on` — toggling the boolean grants `map` on every file type to every domain carrying the `domain` attribute, which is far broader than the cause. The custom allow restricts the grant to the exact `staff_t × tmpfs_t : file` vector.

### Module separation

The rule ships in its own module rather than folded into a broader `staff_u`-extension module. The deliberate posture is one cause, one module: a module whose sole subject is the compositor's shared-memory buffer surface is independently installable, independently verifiable, and independently removable, and its single-vector scope is auditable at a glance. A future related `staff_t × wayland-*` gap that an operator confirms empirically extends this module additively rather than spawning a parallel one; an unrelated `staff_u` policy extension belongs in its own module.

### Custom CIL module

Path: `/root/staff_wayland_memfd.cil`. Loaded at priority 400 via `semodule -X 400 -i /root/staff_wayland_memfd.cil`.

```cil
;; staff_wayland_memfd.cil — patches one stock-policy gap on Fedora 44
;; that affects the desktop Wayland compositor running in the staff_t
;; domain under the confined SELinux user staff_u.
;;
;; Functional rule: the compositor maps a Wayland client's shared-memory
;; (wl_shm) buffer — an anonymous memfd labelled tmpfs_t — with the
;; protection flags PROT_READ|PROT_WRITE. SELinux translates the
;; PROT_WRITE flag into a file:write check and the mmap call itself into
;; a file:map check; file:read is already granted to staff_t on tmpfs_t
;; files by stock policy. Stock policy grants neither write nor map to
;; staff_t on tmpfs_t files: write is absent entirely, and the stock map
;; allow (carried on the domain attribute) is gated by the
;; domain_can_mmap_files boolean, which is off by default. Without both
;; permissions the compositor's buffer-attach mmap fails and the client's
;; Wayland connection aborts with a fatal protocol error.
(allow staff_t tmpfs_t (file (write map)))
```

The module body declares no `(type ...)`, no `(typeattributeset ...)`, no `(roletype ...)`, no `(typetransition ...)`, no `(typepermissive ...)`, and no `(booleanif ...)`. Both the source type (`staff_t`) and the target type (`tmpfs_t`) are stock-policy types shipped by the targeted policy on Fedora 44. The merged display from `sesearch -A -s staff_t -t tmpfs_t -c file` after the module loads shows the stock permissions and the two module-contributed permissions together; the `map` line additionally appears as a boolean-unconditional allow contributed by this module, distinct from the stock boolean-conditional `map` line carried on the `domain` attribute.

### Custom CIL deploy

The modify-stage action sequence runs in this order:

1. Pre-test that the allow surface is absent in the currently loaded policy: `sesearch -A -s staff_t -t tmpfs_t -c file -p write` returns empty, and `sesearch -A -s staff_t -t tmpfs_t -c file -p map` returns only the stock boolean-conditional line (no unconditional `staff_t`-specific allow). The role aborts as a no-op (return code reported to the operator, not as a failure) when both permissions are already present as unconditional grants in the loaded policy, on the assumption that a future stock-policy update has shipped the equivalent grant and the workaround is no longer required.
2. If the module `staff_wayland_memfd` is already installed at priority 400, copy the previously installed CIL source from `/var/lib/selinux/targeted/active/modules/400/staff_wayland_memfd/cil` to `/root/staff_wayland_memfd.cil.pre-reinstall` as a re-install audit anchor.
3. Write the CIL source at `/root/staff_wayland_memfd.cil` with explicit `0644 root:root`.
4. `semodule -X 400 -i /root/staff_wayland_memfd.cil`.
5. Post-load re-probe: `sesearch -A -s staff_t -t tmpfs_t -c file -p write` and `sesearch -A -s staff_t -t tmpfs_t -c file -p map` must each now return a non-empty result.

The role does **not** call `restorecon` (no file labels are altered), does **not** call `semanage fcontext` (no file-context mappings are added), does **not** call `setsebool` (no boolean is toggled), does **not** restart the compositor, and does **not** restart any system service. SELinux access checks evaluate the loaded policy on each system call, so a running compositor picks up the new allow rule without restart and the operator does not need to log out or restart the session after the deploy — the next client buffer attach observes the new policy automatically. No host reboot is required.

The `staff_u → sysadm_r → sysadm_t` role-switch surface that the SELinux toolchain (`semodule`, `sesearch`, `ausearch`) transits through is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md). The priority-400 publish path the CIL module rides on is documented in [SELinux custom CIL bootstrap](../foundation/selinux-cil-bootstrap.md).

### File modes

This topic ships exactly one operator-installed file:

| Path | Mode | Owner:Group | SELinux type |
|---|---|---|---|
| `/root/staff_wayland_memfd.cil` | `0644` | `root:root` | (host-default for `/root/`, typically `admin_home_t`) |

The explicit `0644` is required because the operator UMASK 0027 would otherwise produce `0640`, and a re-run of the role from a `staff_sudo_t` context (plain `sudo` from a `staff_u`-mapped login that forgot the role-switch) would fail to read the source. The reflex is documented in [UMASK 0027](../foundation/umask.md).

## Verification

The role's `files/` directory ships two scripts: a read-only probe and a Soll/Ist verify. Both run from a `staff_t`-confined shell for the staff-side checks; checks that need the policy store (`semodule`, `sesearch`, `ausearch`) are gated behind a `sysadm_t` domain check and reported as `SKIP` rather than as drift when invoked from a non-privileged context. The role-switch surface is documented in [staff_u and sudo role transitions](../foundation/sudo-roles.md).

### Probe

```bash
bash ansible/roles/topic_staff_wayland_memfd/files/probe.sh
```

The probe reports state without judging it. It enumerates compositor-package presence (`rpm -q gnome-shell mutter`), the operator session type best-effort (`XDG_SESSION_TYPE`, the applicability hint — `wayland` is the matching session), the operator's runtime SELinux context via `id -Z` (the canonical applicability anchor — `staff_u:staff_r:staff_t` is the matching mapping), the priority-400 module slot via `semodule -lfull | grep -wE '^[ ]*400.*staff_wayland_memfd'`, the two functional-rule permissions via `sesearch -A -s staff_t -t tmpfs_t -c file -p write` and `... -p map`, and the AVC stream since boot via `ausearch -m AVC,USER_AVC -ts boot` filtered for `staff_t.*tmpfs_t.*file`. The `semodule`, `sesearch`, and `ausearch` queries are gated behind a `sysadm_t` domain check and reported as `SKIP needs sysadm_t` from a `staff_t` shell. The probe exits `0` on completion regardless of observed state and `2` only on missing tooling.

### Verify

```bash
bash ansible/roles/topic_staff_wayland_memfd/files/verify.sh
```

The verify script compares observed state against a hardcoded expected set and exits `0` on a clean match (with `SKIP` accepted for `sysadm_t`-gated checks), `1` on drift, and `2` on invocation error. The expected set:

| Property | Expected value |
|---|---|
| `staff_wayland_memfd` module installed at priority 400 | `yes` |
| Functional allow `staff_t × tmpfs_t : file write` present | `yes` |
| Functional allow `staff_t × tmpfs_t : file map` present | `yes` |
| Functional-class AVC denials since boot | `0` |

Both permissions are asserted independently because the access vector requires both and a partial grant is itself a drift signal: a module carrying `write` but not `map` (or the reverse) leaves the buffer attach broken on the missing half, and the verify must distinguish that state from a clean apply. Liveness probes are not part of the canonical Soll/Ist comparison; the policy-store reads are sufficient. Where any liveness inspection is needed, the verify uses the `[[ -d /proc/${pid} ]]` form rather than `kill -0`, because cross-user `kill -0` from a `staff_t` shell against a foreign-uid PID returns `EPERM` rather than `ESRCH` and would misreport a live process as dead.

### AVC posture

The AVC posture has two parts. On a `staff_u`-mapped host whose desktop has presented at least one software (`wl_shm`) frame since boot **without** the workaround applied, the audit stream carries one or more `denied  { write }` records of class `staff_t × tmpfs_t : file`, each with `comm="gnome-shell"`, a `path` of the form `/memfd:wayland-shm (deleted)` or `/memfd:wayland-cursor (deleted)`, `scontext` resolving to `staff_u:staff_r:staff_t`, and `tcontext` resolving to `staff_u:object_r:tmpfs_t`. Once the `write` permission is granted, the next presented frame advances the access path to the `mmap(2)` call and the same filter then carries `denied  { map }` records on the same class — the two permissions surface in sequence, not together, because the kernel short-circuits the access vector at the first missing permission. This ordering is the reason both permissions ship in the single end-state rule; the general class is documented in [SELinux denial sequence-masking](../../explanation/selinux-denial-sequence-masking.md). On the same workload with the workaround applied, the filter returns an empty result.

Drift signals on an applied host: any fresh `denied  { write }` or `denied  { map }` record of class `staff_t × tmpfs_t : file` with a `memfd:wayland-*` path indicates the functional rule has been rolled back or a stock-policy update has shipped a `neverallow` that pre-empts the priority-400 grant; either case is operator-investigation. A surge of `denied` records of any other class involving `staff_t` or `tmpfs_t` is **not** drift caused by this topic and is investigated independently.

The four-tool diagnosis loop (`ausearch`, `audit2why`, `audit2allow`, `sealert`) for the AVC stream is documented in [Audit and logging baseline](../foundation/audit-logging-baseline.md).

The role's modify stage is idempotent. The CIL source is pushed via `ansible.builtin.copy` from the role's `files/` directory and converges on byte-for-byte content match. The `semodule -X 400 -i` install task is wrapped in a `creates: /var/lib/selinux/targeted/active/modules/400/staff_wayland_memfd/cil` guard, so a re-run on a host already carrying the module reports `changed=false`. The role runs no `restorecon`, no `semanage fcontext`, no `setsebool`, no `systemctl restart`, and no handler. On a correctly applied host, `--check` reports zero changes. Stated as a claim, not a guarantee.

Recovery is a single-stage rollback. The byte-exact form:

```bash
sudo -r sysadm_r -t sysadm_t semodule -X 400 -r staff_wayland_memfd
```

Post-rollback, `sesearch -A -s staff_t -t tmpfs_t -c file -p write` returns empty and `sesearch -A -s staff_t -t tmpfs_t -c file -p map` returns only the stock boolean-conditional line. The module slot at `/var/lib/selinux/targeted/active/modules/400/staff_wayland_memfd/` is removed. The CIL source at `/root/staff_wayland_memfd.cil` is **not** removed by `semodule -r` (it is the operator's source artefact, not part of the module slot); operators who want to also remove the source file do so explicitly with `rm -f /root/staff_wayland_memfd.cil`. Boot-failure risk for this topic is structurally zero — the single allow rule grants access on a user-session compositor domain that is not active during the boot sequence; the rule is not reachable from `init_t`, does not introduce an `nnp_transition` constraint, and does not introduce a system-service namespace effect. The worst-case post-rollback symptom is that software-frame Wayland clients stop presenting again under the `staff_u` mapping.

> **If a deployment of this topic prevents boot:** see [Recover from boot failure](../../how-to/recover-from-boot-failure.md). Topic Reference articles do not inline recovery steps.

## Related patterns

- [SELinux denial sequence-masking](../../explanation/selinux-denial-sequence-masking.md) — The two permissions of this topic's single rule (`write`, then `map`) surface in sequence rather than together when an unmodified host presents successive frames, because the kernel short-circuits the access vector at the first missing permission. The pattern article explains why a one-shot AVC probe under-reports a multi-permission access vector and how to derive the full permission set instead.
